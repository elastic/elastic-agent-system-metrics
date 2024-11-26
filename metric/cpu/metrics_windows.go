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
	"time"

	"github.com/elastic/elastic-agent-libs/helpers/windows/pdh"
	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
)

var (
	processorInformationCounter = "\\Processor Information(%s)\\%s"
	totalKernelTimeCounter      = fmt.Sprintf(processorInformationCounter, "*", "% Privileged Time")
	totalIdleTimeCounter        = fmt.Sprintf(processorInformationCounter, "*", "% Idle Time")
	totalUserTimeCounter        = fmt.Sprintf(processorInformationCounter, "*", "% User Time")
)

var query, qError = buildQuery()

// Get fetches Windows CPU system times
func Get(_ resolve.Resolver) (CPUMetrics, error) {
	globalMetrics := CPUMetrics{}
	if qError != nil {
		return globalMetrics, qError
	}

	if err := query.CollectData(); err != nil {
		return globalMetrics, err
	}

	kernelRawData, err := query.GetRawCounterArray(totalKernelTimeCounter, true)
	if err != nil {
		return globalMetrics, fmt.Errorf("error calling GetRawCounterArray for kernel counter: %w", err)
	}
	idleRawData, err := query.GetRawCounterArray(totalIdleTimeCounter, true)
	if err != nil {
		return globalMetrics, fmt.Errorf("error calling GetRawCounterArray for idle counter: %w", err)
	}
	userRawData, err := query.GetRawCounterArray(totalUserTimeCounter, true)
	if err != nil {
		return globalMetrics, fmt.Errorf("error calling GetRawCounterArray for user counter: %w", err)
	}
	var idle, kernel, user time.Duration
	globalMetrics.list = make([]CPU, len(userRawData))
	for i := 0; i < len(globalMetrics.list); i++ {
		// The values returned by GetRawCounterArray are of equal length and are sorted by instance names.
		// For CPU core {i}, idleRawData[i], kernelRawData[i], and userRawData[i] correspond to the idle time, kernel time, and user time, respectively.

		// values returned by counter are in 100-ns intervals. Hence, convert it to millisecond.
		idleTime := time.Duration(idleRawData[i].RawValue.FirstValue*100) / time.Millisecond
		kernelTime := time.Duration(kernelRawData[i].RawValue.FirstValue*100) / time.Millisecond
		userTime := time.Duration(userRawData[i].RawValue.FirstValue*100) / time.Millisecond

		globalMetrics.list[i].Idle = opt.UintWith(uint64(idleTime))
		globalMetrics.list[i].Sys = opt.UintWith(uint64(kernelTime))
		globalMetrics.list[i].User = opt.UintWith(uint64(userTime))

		// add the per-cpu time to track the total time spent by system
		idle += idleTime
		kernel += kernelTime
		user += userTime
	}

	globalMetrics.totals.Idle = opt.UintWith(uint64(idle))
	globalMetrics.totals.Sys = opt.UintWith(uint64(kernel))
	globalMetrics.totals.User = opt.UintWith(uint64(user))

	return globalMetrics, nil
}

func buildQuery() (pdh.Query, error) {
	var q pdh.Query
	if err := q.Open(); err != nil {
		return q, fmt.Errorf("failed to open query: %w", err)
	}
	if err := q.AddCounter(totalKernelTimeCounter, "", "", true, true); err != nil {
		return q, fmt.Errorf("error calling AddCounter for kernel counter: %w", err)
	}
	if err := q.AddCounter(totalUserTimeCounter, "", "", true, true); err != nil {
		return q, fmt.Errorf("error calling AddCounter for user counter: %w", err)
	}
	if err := q.AddCounter(totalIdleTimeCounter, "", "", true, true); err != nil {
		return q, fmt.Errorf("error calling AddCounter for idle counter: %w", err)
	}
	return q, nil
}
