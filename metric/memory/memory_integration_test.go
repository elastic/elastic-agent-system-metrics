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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-system-metrics/dev-tools/systemtests"
)

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

	// Zswap availability depends on kernel configuration (CONFIG_ZSWAP=y)
	// and whether zswap is enabled. We only verify parsing correctness,
	// not that zswap is available on the system.
	if mem.Zswap.Compressed.Exists() {
		t.Logf("Zswap is available: Compressed=%d bytes, Uncompressed=%d bytes",
			mem.Zswap.Compressed.ValueOr(0), mem.Zswap.Uncompressed.ValueOr(0))

		// If compressed exists, uncompressed should also exist
		assert.True(t, mem.Zswap.Uncompressed.Exists(), "Zswapped should exist when Zswap exists")
	} else {
		t.Skip("Zswap is not available on this system")
	}

	debug := mem.Zswap.Debug
	if debug.IsZero() {
		return
	}

	// If we got metrics, validate them
	t.Logf("Zswap debug metrics available:")
	if debug.StoredPages.Exists() {
		t.Logf("  StoredPages: %d", debug.StoredPages.ValueOr(0))
	}
	if debug.PoolTotalSize.Exists() {
		t.Logf("  PoolTotalSize: %d bytes", debug.PoolTotalSize.ValueOr(0))
	}
	if debug.WrittenBackPages.Exists() {
		t.Logf("  WrittenBackPages: %d", debug.WrittenBackPages.ValueOr(0))
	}
}
