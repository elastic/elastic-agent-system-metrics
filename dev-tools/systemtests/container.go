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

package systemtests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/elastic/elastic-agent-libs/logp"
)

// DockerTestRunner is a simple test framework for running a given go test inside a container.
// In order for this framework to work fully, tests running under this framework must use
// systemtests.DockerTestResolver() to fetch the hostfs, and also set debug-level logging via `logp`.
type DockerTestRunner struct {
	// Privileged is equivalent to the `--privileged` flag passed to `docker run`. Sets elevated permissions.
	Privileged bool
	// Sets the filepath passed to `go test`
	Basepath string
	// Testname will run a given test if set
	Testname string
	// Container name passed to `docker run`.
	Container string
	// RunAsUser will run the container as a non-root user if set to the given username
	// equivalent to `--user=USER`
	RunAsUser string
	// CgroupNSMode sets the cgroup namespace for the container. Newer versions of docker
	// will default to a private namespace. Unexpected namespace values have resulted in bugs.
	CgroupNSMode container.CgroupnsMode
	// Verbose enables debug-level logging
	Verbose bool
	// FatalLogMessages  will fail the test if a given string appears in the log output for the test.
	// Useful for turning non-fatal errors into fatal errors.
	// These are just passed to strings.Contains(). I.e. []string{"Non-fatal error"}
	FatalLogMessages []string
	// MonitorPID will tell tests to specifically check the correctness of process-level monitoring for this PID
	MonitorPID int
	// CreateHostProcess: this will start a process with the following args outside of the container,
	// and use the integration tests to monitor it.
	// Useful as "monitor random running processes" as a test heuristic tends to be flaky.
	CreateHostProcess *exec.Cmd
}

// RunResult returns the logs and return code from the container
type RunResult struct {
	ReturnCode int64
	Stderr     string
	Stdout     string
}

// RunTestsOnDocker runs a provided test, or all the package tests
// (as in `go test ./...`) inside a docker container with the host's root FS mounted as /hostfs.
// This framework relies on the tests using DockerTestResolver().
// If docker returns !0 or if there's a matching string entry from FatalLogMessages in stdout/stderr,
// this will return an error
func (tr *DockerTestRunner) RunTestsOnDocker(ctx context.Context) error {
	log := logp.L()
	if tr.Basepath == "" {
		tr.Basepath = "./..."
	}

	if tr.Container == "" {
		tr.Container = "golang:latest"
	}

	// setup and run

	apiClient, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error creating new docker client: %w", err)
	}
	defer apiClient.Close()

	// create monitored process, if we need to
	tr.createMonitoredProcess(ctx)

	resp, err := tr.createTestContainer(ctx, apiClient)
	if err != nil {
		return fmt.Errorf("error creating container: %w", err)
	}

	log.Infof("running test...")
	result, err := tr.runContainerTest(ctx, apiClient, resp)
	if err != nil {
		return fmt.Errorf("error running container: %w", err)
	}

	// check for failures

	if result.ReturnCode != 0 {
		return fmt.Errorf("got return code %d; \nstdout: %s\nstderr: %s", result.ReturnCode, result.Stdout, result.Stderr)
	}

	// iterate by lines to make this easier to read
	if len(tr.FatalLogMessages) > 0 {
		for _, badLine := range tr.FatalLogMessages {
			for _, line := range strings.Split(result.Stdout, "\n") {
				if strings.Contains(line, badLine) {
					return fmt.Errorf("got bad line in stdout: %s", line)
				}
			}
			for _, line := range strings.Split(result.Stderr, "\n") {
				if strings.Contains(line, badLine) {
					return fmt.Errorf("got bad line in stderr: %s", line)
				}
			}
		}

	}

	if tr.Verbose {
		fmt.Fprintf(os.Stdout, "stderr: %s\n", result.Stderr)
		fmt.Fprintf(os.Stdout, "stdout: %s\n", result.Stdout)
	}

	return nil

}

// createTestContainer creates a with the given test path and test name
func (tr *DockerTestRunner) createTestContainer(ctx context.Context, apiClient *client.Client) (container.CreateResponse, error) {
	reader, err := apiClient.ImagePull(ctx, tr.Container, image.PullOptions{})
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("error pulling image: %w", err)
	}
	defer reader.Close()

	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("error copying container: %w", err)
	}

	wdCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	wdPath, err := wdCmd.CombinedOutput()
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("error fetching top level dir: %w", err)
	}
	cwd := strings.TrimSpace(string(wdPath))
	logp.L().Infof("using cwd: %s", cwd)

	testRunCmd := []string{"go", "test", "-v", tr.Basepath}
	if tr.Testname != "" {
		testRunCmd = append(testRunCmd, "-run", tr.Testname)
	}

	mountPath := "/hostfs"

	containerEnv := []string{fmt.Sprintf("HOSTFS=%s", mountPath)}
	if tr.Privileged {
		containerEnv = append(containerEnv, "PRIVILEGED=1")
	}

	if tr.MonitorPID != 0 {
		containerEnv = append(containerEnv, fmt.Sprintf("MONITOR_PID=%d", tr.MonitorPID))
	}

	resp, err := apiClient.ContainerCreate(ctx, &container.Config{
		Image:      tr.Container,
		Cmd:        testRunCmd,
		Tty:        false,
		WorkingDir: "/app",
		Env:        containerEnv,
		User:       tr.RunAsUser,
	}, &container.HostConfig{
		CgroupnsMode: tr.CgroupNSMode,
		Privileged:   tr.Privileged,
		Binds:        []string{fmt.Sprintf("/:%s", mountPath), fmt.Sprintf("%s:/app", cwd)},
	}, nil, nil, "")
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("error creating container: %w", err)
	}

	return resp, nil
}

func (tr *DockerTestRunner) runContainerTest(ctx context.Context, apiClient *client.Client, resp container.CreateResponse) (RunResult, error) {
	err := apiClient.ContainerStart(ctx, resp.ID, container.StartOptions{})
	if err != nil {
		return RunResult{}, fmt.Errorf("error starting container: %w", err)
	}

	res := RunResult{}

	statusCh, errCh := apiClient.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return res, fmt.Errorf("error during container wait: %w", err)
		}
	case status := <-statusCh:
		res.ReturnCode = status.StatusCode
	}

	out, err := apiClient.ContainerLogs(ctx, resp.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return RunResult{}, fmt.Errorf("error fetching container logs: %w", err)
	}

	stdout := bytes.NewBufferString("")
	stderr := bytes.NewBufferString("")
	_, err = stdcopy.StdCopy(stdout, stderr, out)
	if err != nil {
		return RunResult{}, fmt.Errorf("error copying logs from container: %w", err)
	}
	res.Stderr = stderr.String()
	res.Stdout = stdout.String()

	return res, nil
}

func (tr *DockerTestRunner) createMonitoredProcess(ctx context.Context) {
	log := logp.L()
	// if user has specified a process to monitor, start it now
	if tr.CreateHostProcess != nil {
		// We don't need to do this in a channel, but it prevents races between this goroutine
		// and the rest of test framework
		startPid := make(chan int)
		log.Infof("Creating test Process...")
		go func() {
			err := tr.CreateHostProcess.Start()
			// if the process fails to start up, the resulting tests will fail, so just log it
			if err != nil {
				log.Errorf("error starting process %s", err)
				return
			}
			startPid <- tr.CreateHostProcess.Process.Pid

		}()
		select {
		case pid := <-startPid:
			tr.MonitorPID = pid
		case <-ctx.Done():
		}
		log.Infof("Monitoring pid %d", tr.MonitorPID)
	}
}