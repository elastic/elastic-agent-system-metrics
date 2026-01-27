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

package memory

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-system-metrics/dev-tools/systemtests"
)

// Environment variables for controlling test expectations in CI:
// - EXPECT_ZSWAP: "exists" (zswap fields in /proc/meminfo), "missing", or empty (don't enforce)
// - EXPECT_ZSWAP_DEBUG: "exists" (debugfs accessible), "missing", or empty (don't enforce)

// TestMemoryFromContainer tests memory metric collection from inside a container
// monitoring the host via /hostfs mount
func TestMemoryFromContainer(t *testing.T) {
	logger := logptest.NewTestingLogger(t, "")
	hostfs := systemtests.DockerTestResolver(logger)

	mem, err := Get(hostfs)
	require.NoError(t, err)

	// Basic memory metrics should always be available
	assert.True(t, mem.Total.Exists(), "Total memory should exist")
	assert.True(t, mem.Free.Exists(), "Free memory should exist")
	assert.True(t, mem.Used.Bytes.Exists(), "Used memory should exist")
	assert.True(t, mem.Actual.Free.Exists(), "Actual free memory should exist")

	t.Logf("Total: %d, Free: %d, Used: %d", mem.Total.ValueOr(0), mem.Free.ValueOr(0), mem.Used.Bytes.ValueOr(0))

	// Test zswap metrics based on environment expectations
	expectZswap := os.Getenv("EXPECT_ZSWAP")
	expectDebug := os.Getenv("EXPECT_ZSWAP_DEBUG")

	zswapExists := mem.Zswap.Compressed.Exists()
	debugExists := !mem.Zswap.Debug.IsZero()

	t.Logf("Zswap exists: %v, Debug exists: %v (EXPECT_ZSWAP=%q, EXPECT_ZSWAP_DEBUG=%q)",
		zswapExists, debugExists, expectZswap, expectDebug)

	switch expectZswap {
	case "exists":
		assert.True(t, zswapExists, "EXPECT_ZSWAP=exists but zswap metrics not found in /proc/meminfo")
		if zswapExists {
			assert.True(t, mem.Zswap.Uncompressed.Exists(), "Zswapped should exist when Zswap exists")
			t.Logf("Zswap: Compressed=%d bytes, Uncompressed=%d bytes",
				mem.Zswap.Compressed.ValueOr(0), mem.Zswap.Uncompressed.ValueOr(0))
		}
	case "missing":
		assert.False(t, zswapExists, "EXPECT_ZSWAP=missing but zswap metrics found")
	default:
		// Empty or unset: don't enforce, just log
		if zswapExists {
			t.Logf("Zswap: Compressed=%d bytes, Uncompressed=%d bytes",
				mem.Zswap.Compressed.ValueOr(0), mem.Zswap.Uncompressed.ValueOr(0))
		} else {
			t.Log("Zswap is not available on this system")
		}
	}

	switch expectDebug {
	case "exists":
		assert.True(t, debugExists, "EXPECT_ZSWAP_DEBUG=exists but debug metrics not accessible")
		if debugExists {
			t.Logf("Zswap debug: StoredPages=%d, PoolTotalSize=%d",
				mem.Zswap.Debug.StoredPages.ValueOr(0), mem.Zswap.Debug.PoolTotalSize.ValueOr(0))
		}
	case "missing":
		assert.False(t, debugExists, "EXPECT_ZSWAP_DEBUG=missing but debug metrics found")
	default:
		// Empty or unset: don't enforce, just log
		if debugExists {
			t.Logf("Zswap debug: StoredPages=%d, PoolTotalSize=%d",
				mem.Zswap.Debug.StoredPages.ValueOr(0), mem.Zswap.Debug.PoolTotalSize.ValueOr(0))
		} else {
			t.Log("Zswap debug metrics not accessible (expected without elevated permissions)")
		}
	}
}
