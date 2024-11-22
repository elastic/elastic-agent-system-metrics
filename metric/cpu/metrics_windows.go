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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/helpers/windows/pdh"
	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
)

var (
	processorInformationCounter = "\\Processor Information(%s)\\%s"
	totalKernelTimeCounter      = fmt.Sprintf(processorInformationCounter, "_Total", "% Privileged Time")
	totalIdleTimeCounter        = fmt.Sprintf(processorInformationCounter, "_Total", "% Idle Time")
	totalUserTimeCounter        = fmt.Sprintf(processorInformationCounter, "_Total", "% User Time")
)

var (
	// a call to getAllCouterPaths is idempodent i.e. it returns same set of counters every time you call it.
	// we can save some cruicial cycles by converting it to a sync.Once
	getAllCouterPathsOnce = sync.OnceValues(getAllCouterPaths)
	getQueryOnce          = sync.OnceValues(getQuery)
)

// Get fetches Windows CPU system times
func Get(_ resolve.Resolver) (CPUMetrics, error) {
	globalMetrics := CPUMetrics{}
	q, err := getQueryOnce()
	if err != nil {
		return CPUMetrics{}, err
	}

	if err := q.CollectData(); err != nil {
		return CPUMetrics{}, fmt.Errorf("error collecting counter data: %w", err)
	}

	// get per-cpu data
	// try getting data via performance counters
	globalMetrics.list, err = populatePerCpuMetrics(q)
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("error calling populatePerCpuMetrics: %w", err)
	}

	kernel, user, idle, err := populateGlobalCPUMetrics(q, int64(len(globalMetrics.list)))
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("error calling populateGlobalCPUMetrics: %w", err)
	}

	globalMetrics.totals.Idle = opt.UintWith(uint64(idle / time.Millisecond))
	globalMetrics.totals.Sys = opt.UintWith(uint64(kernel / time.Millisecond))
	globalMetrics.totals.User = opt.UintWith(uint64(user / time.Millisecond))

	return globalMetrics, nil
}

func populateGlobalCPUMetrics(q *pdh.Query, numCpus int64) (time.Duration, time.Duration, time.Duration, error) {
	kernel, err := q.GetRawCounterValue(totalKernelTimeCounter)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error getting Privileged Time counter: %w", err)
	}
	idle, err := q.GetRawCounterValue(totalIdleTimeCounter)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error getting Idle Time counter: %w", err)
	}
	user, err := q.GetRawCounterValue(totalUserTimeCounter)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error getting Privileged User counter: %w", err)
	}
	// _Total values returned by PerfCounters are averaged by number of cpus i.e. average time for system as a whole
	// Previously, we used to return sum of times for all CPUs.
	// To be backward compatible with previous version, multiply the average time by number of CPUs.
	return time.Duration(kernel.FirstValue * 100 * numCpus), time.Duration(idle.FirstValue * 100 * numCpus), time.Duration(user.FirstValue * 100 * numCpus), nil
}

func populatePerCpuMetrics(q *pdh.Query) ([]CPU, error) {
	cpuMap := make(map[string]*CPU, runtime.NumCPU())
	counters, err := getAllCouterPathsOnce()
	if err != nil {
		return nil, fmt.Errorf("call to getAllCouterPaths failed: %w", err)
	}
	for _, counter := range counters {
		name := counter.name
		instance := counter.instance

		if strings.Contains(strings.ToLower(instance), "_total") {
			// we're only interested in per-cpu performance counters
			// counters containing "_TOTAL" are global counters i.e. average of all CPUs
			// hence, ignore such counters
			continue
		}

		if _, ok := cpuMap[instance]; !ok {
			cpuMap[counter.instance] = &CPU{}
		}
		val, err := q.GetRawCounterValue(name)
		if err != nil {
			return nil, fmt.Errorf("call to GetRawCounterValue failed for %s: %w", counter, err)
		}
		// the counter value returned by GetRawCounterValue is in 100-ns intervals
		// convert it to nanoseconds
		valUint := uint64(time.Duration(val.FirstValue*100) / time.Millisecond)

		if strings.Contains(strings.ToLower(name), "% idle time") {
			cpuMap[instance].Idle = opt.UintWith(valUint)
		} else if strings.Contains(strings.ToLower(name), "% privileged time") {
			cpuMap[instance].Sys = opt.UintWith(valUint)
		} else if strings.Contains(strings.ToLower(name), "% user time") {
			cpuMap[instance].User = opt.UintWith(valUint)
		}
	}

	list := make([]CPU, 0, len(cpuMap))
	for _, cpu := range cpuMap {
		list = append(list, *cpu)
	}
	return list, nil
}

type counter struct {
	name     string
	instance string
}

func getAllCouterPaths() ([]*counter, error) {
	// getAllCouterPaths returns needed counter paths to fetch per CPU data
	// For eg.
	//		In a system with 64 cores, getAllCounterPaths() will return:
	//			 \\Processor Information(0,0)\\% Privileged Time,
	//			 \\Processor Information(0,1)\\% Privileged Time,
	//			 \\Processor Information(0,2)\\% Privileged Time,
	//			 ...
	//			 \\Processor Information(0,63)\\% Privileged Time
	//			 \\Processor Information(0,0)\\% Idle Time,
	//			 \\Processor Information(0,1)\\% Idle Time,
	//			 \\Processor Information(0,2)\\% Idle Time,
	//			 ...
	//			 \\Processor Information(0,63)\\% Idle Time
	//			 \\Processor Information(0,0)\\% Idle Time,
	//			 \\Processor Information(0,1)\\% Idle Time,
	//			 \\Processor Information(0,2)\\% Idle Time,
	//			 ...
	//			 \\Processor Information(0,63)\\% Idle Time
	//			 \\Processor Information(0,0)\\% Privileged Time,
	//			 \\Processor Information(0,1)\\% Privileged Time,
	//			 \\Processor Information(0,2)\\% Privileged Time,
	//			 ...
	//			 \\Processor Information(0,63)\\% Privileged Time
	var q pdh.Query
	if err := q.Open(); err != nil {
		return nil, fmt.Errorf("Failed to open query: %w", err)
	}
	allKnownCounters, err := q.GetCounterPaths(fmt.Sprintf(processorInformationCounter, "*", "*"))
	if err != nil {
		return nil, fmt.Errorf("call to fetch all kernel counters failed: %w", err)
	}
	allKnownCounters = append(allKnownCounters, totalKernelTimeCounter, totalIdleTimeCounter, totalUserTimeCounter)

	allCounters := make([]*counter, 0)
	for _, counterName := range allKnownCounters {
		instance, err := pdh.MatchInstanceName(counterName)
		if err != nil {
			// invalid counter name - ignore the error
			// shouldn't really happen, but just in case
			continue
		}
		if !(strings.Contains(counterName, "Privileged Time") ||
			strings.Contains(counterName, "User Time") ||
			strings.Contains(counterName, "Idle Time")) {
			continue
		}
		allCounters = append(allCounters, &counter{
			instance: instance,
			name:     counterName,
		})
	}
	return allCounters, nil

}

func getQuery() (*pdh.Query, error) {
	var q pdh.Query
	if err := q.Open(); err != nil {
		return nil, fmt.Errorf("failed to open query: %w", err)
	}
	counters, err := getAllCouterPathsOnce()
	if err != nil {
		return nil, fmt.Errorf("call to getAllCouterPaths failed: %w", err)
	}
	// add all counters to our query.
	// all of the counter data will be collected once we call CollectData() in Get()
	for _, counter := range counters {
		if err := q.AddCounter(counter.name, "", "", false); err != nil {
			return nil, fmt.Errorf("call to AddCounter failed: %w", err)
		}
	}
	return &q, nil
}
