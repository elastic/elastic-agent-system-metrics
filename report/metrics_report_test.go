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

package report

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/monitoring"
)

func testSystemMetricsReport(t *testing.T) {
	systemMetrics := monitoring.NewRegistry()
	processMetrics := monitoring.NewRegistry()
	err := SetupMetricsOptions(MetricOptions{
		Name:           t.Name(),
		Version:        "test",
		EphemeralID:    "",
		SystemMetrics:  systemMetrics,
		ProcessMetrics: processMetrics,
		Logger:         logptest.NewTestingLogger(t, ""),
	})
	require.NoError(t, err)

	var gotCPU, gotMem, gotInfo atomic.Bool
	testFunc := func(key string, val any) {
		if key == "info.uptime.ms" {
			gotInfo.Store(true)
		}
		if key == "cpu.total.ticks" {
			gotCPU.Store(true)
		}
		if key == "memstats.rss" {
			gotMem.Store(true)
		}
	}

	//iterate over the processes a few times,
	// with the concurrency (hopefully) emulating what might
	// happen if this was an HTTP endpoint getting multiple GET requests
	iter := 100
	var wait sync.WaitGroup
	wait.Add(iter)
	ch := make(chan struct{})
	for range iter {
		go func() {
			<-ch
			processMetrics.Do(monitoring.Full, testFunc)
			wait.Done()
		}()
	}
	close(ch)

	wait.Wait()
	assert.True(t, gotCPU.Load(), "Didn't find cpu.total.ticks")
	assert.True(t, gotMem.Load(), "Didn't find memstats.rss")
	assert.True(t, gotInfo.Load(), "Didn't find info.uptime.ms")
}

func TestSystemMetricsReport(t *testing.T) {
	testSystemMetricsReport(t)
}

func TestSystemMetricsReportOnlyUseLocalProc(t *testing.T) {
	toRestore := map[string]string{}
	toUnset := []string{}
	for _, key := range []string{"HOST_PROC", "HOST_SYS", "HOST_ETC"} {

		if val, isSet := os.LookupEnv(key); isSet {
			toRestore[key] = val
		} else {
			toUnset = append(toUnset, key)
		}

		require.NoErrorf(
			t,
			os.Setenv(key, "/tmp/foo"),
			"cannot sent environment variable %q",
			key)
	}

	t.Cleanup(func() {
		for k, v := range toRestore {
			require.NoErrorf(t, os.Setenv(k, v), "cannot restore the value of %q", k)
		}

		for _, k := range toUnset {
			require.NoError(t, os.Unsetenv(k), "cannot unset env var %q", k)
		}
	})
	testSystemMetricsReport(t)
}
