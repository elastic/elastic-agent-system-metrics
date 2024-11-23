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

	if err := query.CollectData(); err != nil {
		return globalMetrics, err
	}

	kernelRawData, err := query.GetRawCounterArray(totalKernelTimeCounter, true)
	if err != nil {
		return globalMetrics, err
	}
	idleRawData, err := query.GetRawCounterArray(totalIdleTimeCounter, true)
	if err != nil {
		return globalMetrics, err
	}
	userRawData, err := query.GetRawCounterArray(totalUserTimeCounter, true)
	if err != nil {
		return globalMetrics, err
	}
	var idle, kernel, user time.Duration
	globalMetrics.list = make([]CPU, len(userRawData))
	for i := 0; i < len(globalMetrics.list); i++ {
		idleTimeNs := time.Duration(idleRawData[i].RawValue.FirstValue * 100)
		kernelTimeNs := time.Duration(kernelRawData[i].RawValue.FirstValue * 100)
		userTimeNs := time.Duration(userRawData[i].RawValue.FirstValue * 100)

		globalMetrics.list[i].Idle = opt.UintWith(uint64(idleTimeNs / time.Millisecond))
		globalMetrics.list[i].Sys = opt.UintWith(uint64(kernelTimeNs / time.Millisecond))
		globalMetrics.list[i].User = opt.UintWith(uint64(userTimeNs / time.Millisecond))

		// add the per-cpu time to track the total time spent by system
		idle += idleTimeNs
		kernel += kernelTimeNs
		user += userTimeNs
	}

	globalMetrics.totals.Idle = opt.UintWith(uint64(idle / time.Millisecond))
	globalMetrics.totals.Sys = opt.UintWith(uint64(kernel / time.Millisecond))
	globalMetrics.totals.User = opt.UintWith(uint64(user / time.Millisecond))

	return globalMetrics, nil
}

func buildQuery() (pdh.Query, error) {
	var q pdh.Query
	if err := q.Open(); err != nil {
		return q, err
	}
	if err := q.AddCounter(totalKernelTimeCounter, "", "", true); err != nil {
		return q, err
	}
	if err := q.AddCounter(totalUserTimeCounter, "", "", true); err != nil {
		return q, err
	}
	if err := q.AddCounter(totalIdleTimeCounter, "", "", true); err != nil {
		return q, err
	}
	return q, nil
}
