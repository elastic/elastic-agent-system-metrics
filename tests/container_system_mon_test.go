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

package tests

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-system-metrics/dev-tools/systemtests"
)

// These tests are designed for the case of monitoring a host system from inside docker via a /hostfs

func TestKernelProc(t *testing.T) {
	t.Skip("This test will fail until https://github.com/elastic/elastic-agent-system-metrics/issues/135 is fixed")
	_ = logp.DevelopmentSetup()
	//manually fetch a kernel process
	// kernel processes will have a parent pid of 2
	dir, err := os.Open("/proc")
	require.NoError(t, err, "error opening /proc")

	const readAllDirnames = -1 // see os.File.Readdirnames doc

	names, err := dir.Readdirnames(readAllDirnames)
	require.NoError(t, err, "error reading directory names")
	var testPid int64
	for _, name := range names {
		if name[0] < '0' || name[0] > '9' {
			continue
		}
		statfile := filepath.Join("/proc/", name, "stat")
		statRaw, err := os.ReadFile(statfile)
		require.NoError(t, err)
		statPart := strings.Split(string(statRaw), " ")
		ppid := statPart[3]
		if ppid == "2" {
			testPid, err = strconv.ParseInt(ppid, 10, 64)
			require.NoError(t, err)
			break
		}
	}

	if testPid == 0 {
		t.Skip("could not find kernel process")
	}

	logp.DevelopmentSetup()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	runner := systemtests.DockerTestRunner{
		MonitorPID:       int(testPid),
		Basepath:         "./metric/system/process",
		Verbose:          true,
		Privileged:       true,
		Testname:         "TestSystemHostFromContainer",
		FatalLogMessages: []string{"Error fetching PID info for", "Non-fatal error fetching"},
	}
	err = runner.RunTestsOnDocker(ctx)
	require.NoError(t, err)
}

func TestPrivilegedAndRoot(t *testing.T) {
	// the "best possible" user config. This should yield no permissions errors
	_ = logp.DevelopmentSetup()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	runner := systemtests.DockerTestRunner{
		Basepath:          "./metric/system/process",
		Verbose:           true,
		Privileged:        true,
		Testname:          "TestSystemHostFromContainer",
		CreateHostProcess: exec.Command("sleep", "240"),
		FatalLogMessages:  []string{"Error fetching PID info for", "Non-fatal error fetching"},
	}
	err := runner.RunTestsOnDocker(ctx)
	require.NoError(t, err)
}

func TestPrivilegedAndRootHostNS(t *testing.T) {
	// Same as above test, but with the namespace set to host mode
	_ = logp.DevelopmentSetup()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	runner := systemtests.DockerTestRunner{
		CgroupNSMode:      container.CgroupnsModeHost,
		Basepath:          "./metric/system/process",
		Verbose:           true,
		Privileged:        true,
		Testname:          "TestSystemHostFromContainer",
		CreateHostProcess: exec.Command("sleep", "240"),
		FatalLogMessages:  []string{"Error fetching PID info for", "Non-fatal error fetching"},
	}
	err := runner.RunTestsOnDocker(ctx)
	require.NoError(t, err)
}

func TestNonRoot(t *testing.T) {
	// This tests running the container as a user other than root.
	_ = logp.DevelopmentSetup()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	runner := systemtests.DockerTestRunner{
		Basepath:          "./metric/system/process",
		Verbose:           true,
		Privileged:        true,
		Testname:          "TestSystemHostFromContainer",
		CreateHostProcess: exec.Command("sleep", "240"),
		// is it kinda cursed that we just use the system `mail` user? Yeah, but it works
		RunAsUser:        "mail",
		FatalLogMessages: []string{"Error fetching PID info for"},
	}
	err := runner.RunTestsOnDocker(ctx)
	require.NoError(t, err)
}

func TestRootNonPrivileged(t *testing.T) {
	// this is the "least optimal" setup. No root, no additional capabilities set
	_ = logp.DevelopmentSetup()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	runner := systemtests.DockerTestRunner{
		Basepath:          "./metric/system/process",
		Verbose:           true,
		Privileged:        false,
		Testname:          "TestSystemHostFromContainer",
		CreateHostProcess: exec.Command("sleep", "240"),
		RunAsUser:         "mail",
		FatalLogMessages:  []string{"Error fetching PID info for"},
	}
	err := runner.RunTestsOnDocker(ctx)
	require.NoError(t, err)
}
