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
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/helpers/windows/pdh"
	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
	"github.com/elastic/gosigar/sys/windows"
)

var (
	kernelTimeCounter = "\\Processor Information(%s)\\% Privileged Time"
	userTimeCounter   = "\\Processor Information(%s)\\% User Time"
	idleTimeCounter   = "\\Processor Information(%s)\\% Idle Time"
)

// Get fetches Windows CPU system times
func Get(_ resolve.Resolver) (CPUMetrics, error) {
	var q pdh.Query
	var kernel, user, idle time.Duration
	var combinedErr, err error
	globalMetrics := CPUMetrics{}

	if err := q.Open(); err != nil {
		combinedErr = errors.Join(combinedErr, err)
		goto fallback
		// return CPUMetrics{}, fmt.Errorf("call to PdhOpenQuery failed: %w", err)
	}

	// get per-cpu data
	// try getting data via performance counters
	globalMetrics.list, err = populatePerCpuMetrics(&q)
	if err != nil {
		combinedErr = errors.Join(combinedErr, err)
		goto fallback
	}

	kernel, user, idle, err = populateGlobalCpuMetrics(&q)
	if err != nil {
		combinedErr = errors.Join(combinedErr, err)
		goto fallback
	}

	// _Total values returned by PerfCounters are averaged by number of cpus i.e. average time for system as a whole
	// Previously, we used to return sum of times for all CPUs.
	// To be backward compatible with previous version, multiply the average time by number of CPUs.
	globalMetrics.totals.Idle = opt.UintWith(uint64(idle/time.Millisecond) * uint64(len(globalMetrics.list)))
	globalMetrics.totals.Sys = opt.UintWith(uint64(kernel/time.Millisecond) * uint64(len(globalMetrics.list)))
	globalMetrics.totals.User = opt.UintWith(uint64(user/time.Millisecond) * uint64(len(globalMetrics.list)))

	return globalMetrics, nil

fallback:
	// fallback to GetSystemTimes()
	// GetSystemTimes() return global data for current processor group i.e. upto 64 cores
	kernel, user, idle, err = populateGlobalCpuMetricsFallback()
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("error getting counter values: %w", err)
	}

	// convert from duration to ticks
	// ticks are measured in 1-ms intervals
	globalMetrics.totals.Idle = opt.UintWith(uint64(idle / time.Millisecond))
	globalMetrics.totals.Sys = opt.UintWith(uint64(kernel / time.Millisecond))
	globalMetrics.totals.User = opt.UintWith(uint64(user / time.Millisecond))

	// fallback to _NtQuerySystemInformation
	// _NtQuerySystemInformation return per-cpu data for current processor group i.e. upto 64 cores
	globalMetrics.list, err = populatePerCpuMetricsFallback()
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("error getting per-cpu metrics: %w", err)
	}
	return globalMetrics, &PerfError{err: combinedErr}
}

func populateGlobalCpuMetrics(q *pdh.Query) (time.Duration, time.Duration, time.Duration, error) {
	kernel, err := q.GetRawCounterValue(fmt.Sprintf(kernelTimeCounter, "_Total"))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error getting Privileged Time counter: %w", err)
	}
	idle, err := q.GetRawCounterValue(fmt.Sprintf(idleTimeCounter, "_Total"))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error getting Idle Time counter: %w", err)
	}
	user, err := q.GetRawCounterValue(fmt.Sprintf(userTimeCounter, "_Total"))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error getting Privileged User counter: %w", err)
	}
	return time.Duration(kernel.FirstValue * 100), time.Duration(idle.FirstValue * 100), time.Duration(user.FirstValue * 100), nil
}

func populatePerCpuMetrics(q *pdh.Query) ([]CPU, error) {
	cpuMap := make(map[string]*CPU, runtime.NumCPU())
	counters, err := getAllCouterPaths(q)
	if err != nil {
		return nil, fmt.Errorf("call to getAllCouterPaths failed: %w", err)
	}
	for _, counter := range counters {
		instance, err := pdh.MatchInstanceName(counter)
		if err != nil {
			// invalid counter name - ignore the error
			// shouldn't really happen, but just in case
			continue
		}
		if strings.Contains(strings.ToLower(instance), "_total") {
			// we're only interested in per-cpu performance counters
			// counters containing "_TOTAL" are global counters i.e. average of all CPUs
			// hence, ignore such counteres
			continue
		}
		if _, ok := cpuMap[instance]; !ok {
			cpuMap[instance] = &CPU{}
		}
		val, err := q.GetRawCounterValue(counter)
		if err != nil {
			return nil, fmt.Errorf("call to GetRawCounterValue failed for %s: %w", counter, err)
		}
		// the counter value returned by GetRawCounterValue is in 100-ns intervals
		// convert it to nanoseconds
		valUint := uint64(time.Duration(val.FirstValue*100) / time.Millisecond)

		if strings.Contains(strings.ToLower(counter), "% idle time") {
			cpuMap[instance].Idle = opt.UintWith(valUint)
		} else if strings.Contains(strings.ToLower(counter), "% privileged time") {
			cpuMap[instance].Sys = opt.UintWith(valUint)
		} else if strings.Contains(strings.ToLower(counter), "% user time") {
			cpuMap[instance].User = opt.UintWith(valUint)
		}
	}

	list := make([]CPU, 0, len(cpuMap))
	for _, cpu := range cpuMap {
		list = append(list, *cpu)
	}
	return list, nil
}

func populatePerCpuMetricsFallback() ([]CPU, error) {
	cpus, err := windows.NtQuerySystemProcessorPerformanceInformation()
	if err != nil {
		return nil, fmt.Errorf("catll to NtQuerySystemProcessorPerformanceInformation failed: %w", err)
	}
	list := make([]CPU, 0, len(cpus))
	for _, cpu := range cpus {
		idleMetric := uint64(cpu.IdleTime / time.Millisecond)
		sysMetric := uint64(cpu.KernelTime / time.Millisecond)
		userMetrics := uint64(cpu.UserTime / time.Millisecond)
		list = append(list, CPU{
			Idle: opt.UintWith(idleMetric),
			Sys:  opt.UintWith(sysMetric),
			User: opt.UintWith(userMetrics),
		})
	}
	return list, nil
}

func populateGlobalCpuMetricsFallback() (idle, kernel, user time.Duration, err error) {
	idle, kernel, user, err = windows.GetSystemTimes()
	if err != nil {
		return
	}
	return
}

func getAllCouterPaths(q *pdh.Query) ([]string, error) {
	allKernelCounters, err := q.GetCounterPaths(fmt.Sprintf(kernelTimeCounter, "*"))
	if err != nil {
		return nil, fmt.Errorf("call to fetch all kernel counters failed: %w", err)
	}
	allUserCounters, err := q.GetCounterPaths(fmt.Sprintf(userTimeCounter, "*"))
	if err != nil {
		return nil, fmt.Errorf("call to fetch all user counters failed: %w", err)
	}
	allIdleCounters, err := q.GetCounterPaths(fmt.Sprintf(idleTimeCounter, "*"))
	if err != nil {
		return nil, fmt.Errorf("call to fetch all user counters failed: %w", err)
	}
	return append(allKernelCounters, append(allUserCounters, allIdleCounters...)...), nil

}
