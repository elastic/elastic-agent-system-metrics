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

//go:build linux

package cgv2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/cgroup/cgcommon"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/cgroup/testhelpers"
)

const v2Path = "../testdata/docker/sys/fs/cgroup/system.slice/docker-1c8fa019edd4b9d4b2856f4932c55929c5c118c808ed5faee9a135ca6e84b039.scope"
const ubuntu = "../testdata/io_statfiles/ubuntu"
const ubuntu2 = "../testdata/io_statfiles/ubuntu2"

var testFileList = []string{
	"../testdata/docker.zip",
}

func TestMain(m *testing.M) {
	os.Exit(testhelpers.MainTestWrapper(m, testFileList))
}

func TestGetIO(t *testing.T) {
	ioTest := IOSubsystem{}
	err := ioTest.Get(v2Path, false)
	assert.NoError(t, err, "error in Get")

	goodStat := map[string]IOStat{
		"253:0": {
			Read:      IOMetric{Bytes: 1024, IOs: 1},
			Write:     IOMetric{Bytes: 4096, IOs: 1},
			Discarded: IOMetric{Bytes: 6, IOs: 8},
		},
		"8:0": {
			Read:      IOMetric{Bytes: 512, IOs: 100},
			Write:     IOMetric{Bytes: 4096, IOs: 1},
			Discarded: IOMetric{Bytes: 5, IOs: 23},
		},
	}

	assert.Equal(t, goodStat, ioTest.Stats)
}

func TestIostatFilesDuplicatedDeviceMetrics(t *testing.T) {
	ioTest := IOSubsystem{}
	err := ioTest.Get(ubuntu, false)
	assert.NoError(t, err, "error in Get")

	goodStat := map[string]IOStat{
		"7:7": {
			Read: IOMetric{
				Bytes: 556032,
				IOs:   78,
			},
			Write: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
			Discarded: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
		},
		"7:6": {
			Read: IOMetric{
				Bytes: 556032,
				IOs:   78,
			},
			Write: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
			Discarded: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
		},
		"7:5": {
			Read: IOMetric{
				Bytes: 556032,
				IOs:   78,
			},
			Write: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
			Discarded: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
		},
		"7:4": {
			Read: IOMetric{
				Bytes: 556032,
				IOs:   78,
			},
			Write: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
			Discarded: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
		},
		"7:3": {
			Read: IOMetric{
				Bytes: 21017600,
				IOs:   629,
			},
			Write: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
			Discarded: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
		},
	}

	assert.Equal(t, goodStat, ioTest.Stats)
}

func TestIOStatDeviceWithNoMetrics(t *testing.T) {
	ioTest := IOSubsystem{}
	err := ioTest.Get(ubuntu2, false)
	assert.NoError(t, err, "error in Get")

	goodStat := map[string]IOStat{
		"253:0": {
			Read: IOMetric{
				Bytes: 45931053056,
				IOs:   1078394,
			},
			Write: IOMetric{
				Bytes: 211814596608,
				IOs:   21426614,
			},
			Discarded: IOMetric{
				Bytes: 0,
				IOs:   0,
			},
		},
		"259:0": {
			Read: IOMetric{
				Bytes: 48963873792,
				IOs:   1315370,
			},
			Write: IOMetric{
				Bytes: 217588278272,
				IOs:   15358572,
			},
			Discarded: IOMetric{
				Bytes: 3222265856,
				IOs:   24,
			},
		},
	}
	assert.Equal(t, goodStat, ioTest.Stats)
}

func TestGetMem(t *testing.T) {
	mem := MemorySubsystem{}
	err := mem.Get(v2Path)
	assert.NoError(t, err, "error in GetV2")

	assert.Equal(t, uint64(3), mem.Mem.Events.High)
	assert.Equal(t, uint64(4), mem.Mem.Low.Bytes)
	assert.Equal(t, uint64(9125888), mem.Mem.Usage.Bytes)

	assert.Equal(t, uint64(17756400), mem.Stats.SlabReclaimable.Bytes)
	assert.Equal(t, uint64(12), mem.Stats.THPFaultAlloc)

	// Test memory pressure stall information
	expectedPressure := map[string]cgcommon.Pressure{
		"some": {
			Ten:          opt.Pct{Pct: 0.0},
			Sixty:        opt.Pct{Pct: 0.0},
			ThreeHundred: opt.Pct{Pct: 0.0},
			Total:        opt.UintWith(0),
		},
		"full": {
			Ten:          opt.Pct{Pct: 0.0},
			Sixty:        opt.Pct{Pct: 0.0},
			ThreeHundred: opt.Pct{Pct: 0.0},
			Total:        opt.UintWith(0),
		},
	}
	assert.Equal(t, expectedPressure, mem.Pressure)
}

func TestGetMemPressure(t *testing.T) {
	// Create a temp directory with memory.pressure file containing non-zero values
	tempDir := t.TempDir()

	// Create a memory.pressure file with meaningful values
	pressureContent := `some avg10=1.50 avg60=2.30 avg300=0.75 total=123456
full avg10=0.80 avg60=1.20 avg300=0.40 total=78901
`
	err := os.WriteFile(tempDir+"/memory.pressure", []byte(pressureContent), 0644)
	require.NoError(t, err)

	// Create minimal required memory files
	err = os.WriteFile(tempDir+"/memory.stat", []byte("anon 0\n"), 0644)
	require.NoError(t, err)

	mem := MemorySubsystem{}
	err = mem.Get(tempDir)
	assert.NoError(t, err, "error in Get")

	expectedPressure := map[string]cgcommon.Pressure{
		"some": {
			Ten:          opt.Pct{Pct: 1.50},
			Sixty:        opt.Pct{Pct: 2.30},
			ThreeHundred: opt.Pct{Pct: 0.75},
			Total:        opt.UintWith(123456),
		},
		"full": {
			Ten:          opt.Pct{Pct: 0.80},
			Sixty:        opt.Pct{Pct: 1.20},
			ThreeHundred: opt.Pct{Pct: 0.40},
			Total:        opt.UintWith(78901),
		},
	}
	assert.Equal(t, expectedPressure, mem.Pressure)
}

func TestGetMemNoPressure(t *testing.T) {
	// Test that memory subsystem works when memory.pressure doesn't exist
	tempDir := t.TempDir()

	// Create minimal required memory files but NOT memory.pressure
	err := os.WriteFile(tempDir+"/memory.stat", []byte("anon 0\n"), 0644)
	require.NoError(t, err)

	mem := MemorySubsystem{}
	err = mem.Get(tempDir)
	assert.NoError(t, err, "error in Get - should not fail if memory.pressure is missing")
	assert.Empty(t, mem.Pressure, "Pressure should be empty when memory.pressure file doesn't exist")
}

func TestGetCPU(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) string
		expected CPUSubsystem
	}{
		{
			name: "v2 path with pressure and CFS",
			setup: func(*testing.T) string {
				return v2Path
			},
			expected: CPUSubsystem{
				ID:   "",
				Path: "",
				Pressure: map[string]cgcommon.Pressure{
					"some": {
						Ten:          opt.Pct{Pct: 4.30},
						Sixty:        opt.Pct{Pct: 3.20},
						ThreeHundred: opt.Pct{Pct: 1.11},
						Total:        opt.UintWith(1676316),
					},
				},
				Stats: CPUStats{
					Usage: cgcommon.CPUUsage{
						NS: 26772130245,
					},
					User: cgcommon.CPUUsage{
						NS: 20979069928,
					},
					System: cgcommon.CPUUsage{
						NS: 5793060316,
					},
					Periods: opt.UintWith(1),
					Throttled: ThrottledField{
						Periods: opt.UintWith(4),
						Us:      opt.UintWith(10),
					},
				},
				CFS: CFS{
					// cpu.max: "max 100000" => unlimited quota (0)
					QuotaMicros:  opt.Us{Us: 0},
					PeriodMicros: opt.Us{Us: 100000},
					Weight:       100,
				},
			},
		},
		{
			name: "empty directory",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
			expected: CPUSubsystem{
				ID:       "",
				Path:     "",
				Pressure: map[string]cgcommon.Pressure{},
				Stats:    CPUStats{},
				CFS:      CFS{},
			},
		},
		{
			name: "cpu.stat only",
			setup: func(t *testing.T) string {
				b, err := os.ReadFile(filepath.Join(v2Path, "cpu.stat"))
				require.NoError(t, err)
				dir := t.TempDir()
				err = os.WriteFile(filepath.Join(dir, "cpu.stat"), b, 0644)
				require.NoError(t, err)
				return dir
			},
			expected: CPUSubsystem{
				ID:       "",
				Path:     "",
				Pressure: map[string]cgcommon.Pressure{},
				Stats: CPUStats{
					Usage: cgcommon.CPUUsage{
						NS: 26772130245,
					},
					User: cgcommon.CPUUsage{
						NS: 20979069928,
					},
					System: cgcommon.CPUUsage{
						NS: 5793060316,
					},
					Periods: opt.UintWith(1),
					Throttled: ThrottledField{
						Periods: opt.UintWith(4),
						Us:      opt.UintWith(10),
					},
				},
				CFS: CFS{},
			},
		},
		{
			name: "cpu.max with quota limit",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				// 50000/100000 => 50% CPU limit
				writeFile(t, filepath.Join(dir, "cpu.max"), "50000 100000")
				writeFile(t, filepath.Join(dir, "cpu.weight"), "200")
				return dir
			},
			expected: CPUSubsystem{
				ID:       "",
				Path:     "",
				Pressure: map[string]cgcommon.Pressure{},
				Stats:    CPUStats{},
				CFS: CFS{
					QuotaMicros:  opt.Us{Us: 50000},
					PeriodMicros: opt.Us{Us: 100000},
					Weight:       200,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cpu := CPUSubsystem{}
			err := cpu.Get(test.setup(t))
			require.NoError(t, err, "error in Get")
			assert.EqualValues(t, test.expected, cpu)
		})
	}
}

func TestParseCPUMax(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedQuota  uint64
		expectedPeriod uint64
		expectError    assert.ErrorAssertionFunc
	}{
		{
			name:           "unlimited quota",
			content:        "max 100000",
			expectedQuota:  0, // 0 represents unlimited
			expectedPeriod: 100000,
			expectError:    assert.NoError,
		},
		{
			name:           "limited quota",
			content:        "50000 100000",
			expectedQuota:  50000,
			expectedPeriod: 100000,
			expectError:    assert.NoError,
		},
		{
			name:           "small quota",
			content:        "1000 10000",
			expectedQuota:  1000,
			expectedPeriod: 10000,
			expectError:    assert.NoError,
		},
		{
			name:        "invalid format - single value",
			content:     "100000",
			expectError: assert.Error,
		},
		{
			name:        "invalid format - too many values",
			content:     "50000 100000 extra",
			expectError: assert.Error,
		},
		{
			name:        "invalid quota value",
			content:     "invalid 100000",
			expectError: assert.Error,
		},
		{
			name:        "invalid period value",
			content:     "50000 invalid",
			expectError: assert.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "cpu.max"), test.content)

			quota, period, err := parseCPUMax(dir)

			test.expectError(t, err)
			assert.Equal(t, test.expectedQuota, quota)
			assert.Equal(t, test.expectedPeriod, period)
		})
	}
}

func TestGetCFS(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string // filename -> content
		expected CFS
	}{
		{
			name: "both files present",
			files: map[string]string{
				"cpu.max":    "25000 100000",
				"cpu.weight": "150",
			},
			expected: CFS{
				QuotaMicros:  opt.Us{Us: 25000},
				PeriodMicros: opt.Us{Us: 100000},
				Weight:       150,
			},
		},
		{
			name: "only cpu.max present",
			files: map[string]string{
				"cpu.max": "max 100000",
			},
			expected: CFS{
				QuotaMicros:  opt.Us{Us: 0},
				PeriodMicros: opt.Us{Us: 100000},
				Weight:       0,
			},
		},
		{
			name: "only cpu.weight present",
			files: map[string]string{
				"cpu.weight": "500",
			},
			expected: CFS{
				QuotaMicros:  opt.Us{Us: 0},
				PeriodMicros: opt.Us{Us: 0},
				Weight:       500,
			},
		},
		{
			name:     "no files present",
			files:    nil,
			expected: CFS{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for filename, content := range test.files {
				writeFile(t, filepath.Join(dir, filename), content)
			}
			cfs, err := getCFS(dir)
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfs)
		})
	}
}

func writeFile(t testing.TB, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
}
