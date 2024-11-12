// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

/*
For testing via the win2012 vagrant box:
vagrant winrm -s cmd -e -c "cd C:\\Gopath\src\\github.com\\elastic\\beats\\metricbeat\\module\\system\\cpu; go test -v -tags=integration -run TestFetch"  win2012
*/

package cpu

import (
	"fmt"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/helpers/windows/pdh"
	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
	"github.com/elastic/gosigar/sys/windows"
)

var counters []string = []string{
	"\\Processor(_Total)\\% Processor Time",
	"\\Processor(_Total)\\% Idle Time",
}

/*
The below code implements a "metrics tracker" that gives us the ability to
calculate CPU percentages, as we average usage across a time period.
*/

// Monitor is used to monitor the overall CPU usage of the system over time.
type Monitor struct {
	lastSample CPUMetrics
	Hostfs     resolve.Resolver
	query      pdh.Query
}

// New returns a new CPU metrics monitor
// Hostfs is only relevant on linux and freebsd.
func New(hostfs resolve.Resolver) (*Monitor, error) {
	q, err := initializeQuery()
	if err != nil {
		return nil, fmt.Errorf("call to initialize PDH quert failed: %w", err)
	}
	return &Monitor{Hostfs: hostfs, query: q}, nil
}

// Fetch collects a new sample of the CPU usage metrics.
// This will overwrite the currently stored samples.
func (m *Monitor) Fetch() (Metrics, error) {
	metric, err := Get(m.Hostfs, m.query)
	if err != nil {
		return Metrics{}, fmt.Errorf("error fetching CPU metrics: %w", err)
	}

	oldLastSample := m.lastSample
	m.lastSample = metric

	return Metrics{previousSample: oldLastSample.totals, currentSample: metric.totals, count: len(metric.list), isTotals: true}, nil
}

// FetchCores collects a new sample of CPU usage metrics per-core
// This will overwrite the currently stored samples.
func (m *Monitor) FetchCores() ([]Metrics, error) {

	metric, err := Get(m.Hostfs, m.query)
	if err != nil {
		return nil, fmt.Errorf("error fetching CPU metrics: %w", err)
	}

	coreMetrics := make([]Metrics, len(metric.list))
	for i := 0; i < len(metric.list); i++ {
		lastMetric := CPU{}
		// Count of CPUs can change
		if len(m.lastSample.list) > i {
			lastMetric = m.lastSample.list[i]
		}
		coreMetrics[i] = Metrics{
			currentSample:  metric.list[i],
			previousSample: lastMetric,
			isTotals:       false,
		}

		// Only add CPUInfo metric if it's available
		// Remove this if statement once CPUInfo is supported
		// by all systems
		if len(metric.CPUInfo) != 0 {
			coreMetrics[i].cpuInfo = metric.CPUInfo[i]
		}
	}
	m.lastSample = metric
	return coreMetrics, nil
}

// Get fetches Windows CPU system times
func Get(_ resolve.Resolver, q pdh.Query) (CPUMetrics, error) {
	if err := q.CollectData(); err != nil {
		return CPUMetrics{}, fmt.Errorf("call to collect counter data failed: %w", err)
	}
	counterValues, err := q.GetFormattedCounterValues()
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("call to get formated values: %w", err)
	}
	var total, idle float64
	for counterName, counterVaule := range counterValues {
		if strings.Contains(counterName, "\\Processor(_Total)\\% Processor Time") {
			total = counterVaule[0].Measurement.(float64)
		} else {
			idle = counterVaule[0].Measurement.(float64)
		}
	}
	globalMetrics := CPUMetrics{}
	//convert from duration to ticks
	idleMetric := uint64(time.Duration(idle) / 1000)
	sysMetric := uint64(time.Duration(total) / 1000)
	// userMetrics := uint64(user / time.Millisecond)
	globalMetrics.totals.Idle = opt.UintWith(idleMetric)
	globalMetrics.totals.Sys = opt.UintWith(sysMetric)
	// globalMetrics.totals.User = opt.UintWith(userMetrics)
	// get per-cpu data
	cpus, err := windows.NtQuerySystemProcessorPerformanceInformation()
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("catll to NtQuerySystemProcessorPerformanceInformation failed: %w", err)
	}
	globalMetrics.list = make([]CPU, 0, len(cpus))
	for _, cpu := range cpus {
		idleMetric := uint64(cpu.IdleTime / time.Millisecond)
		sysMetric := uint64(cpu.KernelTime / time.Millisecond)
		userMetrics := uint64(cpu.UserTime / time.Millisecond)
		globalMetrics.list = append(globalMetrics.list, CPU{
			Idle: opt.UintWith(idleMetric),
			Sys:  opt.UintWith(sysMetric),
			User: opt.UintWith(userMetrics),
		})
	}
	return globalMetrics, nil
}

func initializeQuery() (pdh.Query, error) {
	query := pdh.Query{}
	for _, c := range counters {
		if err := query.AddCounter(c, "", "double", false); err != nil {
			return pdh.Query{}, err
		}
	}
	_ = query.CollectData()
	return query, nil
}
