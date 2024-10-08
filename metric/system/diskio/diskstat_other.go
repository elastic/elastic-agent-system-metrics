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

//go:build (darwin && cgo) || freebsd
// +build darwin,cgo freebsd

package diskio

import (
	"errors"

	"github.com/shirou/gopsutil/v4/disk"
)

// NewDiskIOStat :init DiskIOStat object.
func NewDiskIOStat() *IOStat {
	return &IOStat{
		lastDiskIOCounters: map[string]disk.IOCountersStat{},
	}
}

// OpenSampling stub for linux implementation.
func (stat *IOStat) OpenSampling() error {
	return nil
}

// CalcIOStatistics stub for linux implementation.
func (stat *IOStat) CalcIOStatistics(rcounter disk.IOCountersStat) (IOMetric, error) {
	return IOMetric{}, errors.New("not implemented out of linux")
}

// CloseSampling stub for linux implementation.
func (stat *IOStat) CloseSampling() {}

// IOCounters should map functionality to disk package for linux os.
func IOCounters(names ...string) (map[string]disk.IOCountersStat, error) {
	return disk.IOCounters(names...)
}
