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

package numcpu

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCPU(t *testing.T) {
	cpuCount, exists, err := getCPU()
	assert.NoError(t, err, "getCPU")
	if exists {
		assert.Greater(t, cpuCount, 0)
		t.Logf("Got actual CPU counts: %d", cpuCount)
	} else {
		t.Logf("No CPU counts implementaiton on platform, falling back.")
	}

}

func TestNumCPU(t *testing.T) {
	cpuCount := NumCPU()
	assert.NotEqual(t, -1, cpuCount)
	t.Logf("CPU Count: %d", cpuCount)
}
