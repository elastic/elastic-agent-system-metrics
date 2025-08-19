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

//go:build (darwin && cgo) || (freebsd && cgo) || linux || windows
// +build darwin,cgo freebsd,cgo linux windows

package report

import (
	"fmt"
	"runtime"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/process"
)

var (
	processStats *process.Stats
)

// monitoringCgroupsHierarchyOverride is an undocumented environment variable which
// overrides the cgroups path under /sys/fs/cgroup, which should be set to "/" when running
// Elastic Agent under Docker.
const monitoringCgroupsHierarchyOverride = "LIBBEAT_MONITORING_CGROUPS_HIERARCHY_OVERRIDE"

// SetupMetrics creates a basic suite of metrics handlers for monitoring, including build info and system resources
//
// Deprecated: use SetupMetricsOptions
func SetupMetrics(logger *logp.Logger, name, version string) error {
	return SetupMetricsOptions(MetricOptions{
		Name:           name,
		Version:        version,
		EphemeralID:    ephemeralID.String(),
		Logger:         logger,
		SystemMetrics:  monitoring.Default.GetOrCreateRegistry("system"),
		ProcessMetrics: monitoring.Default.GetOrCreateRegistry("beat"),
	})
}

// SetupMetricsOptions performs creation of metrics handlers using specified options.
func SetupMetricsOptions(opts MetricOptions) error {
	monitoring.NewFunc(opts.SystemMetrics, "cpu", ReportSystemCPUUsage, monitoring.Report)

	opts.Name = processName(opts.Name)
	processStats = &process.Stats{
		Procs:        []string{opts.Name},
		EnvWhitelist: nil,
		CPUTicks:     true,
		CacheCmdLine: true,
		IncludeTop:   process.IncludeTopConfig{},
		Logger:       opts.Logger,
	}

	err := processStats.Init()
	if err != nil {
		return fmt.Errorf("failed to init process stats for agent: %w", err)
	}

	monitoring.NewFunc(opts.ProcessMetrics, "memstats", MemStatsReporter(opts.Logger, processStats), monitoring.Report)
	monitoring.NewFunc(opts.ProcessMetrics, "cpu", InstanceCPUReporter(opts.Logger, processStats), monitoring.Report)
	monitoring.NewFunc(opts.ProcessMetrics, "runtime", ReportRuntime, monitoring.Report)
	monitoring.NewFunc(opts.ProcessMetrics, "info", infoReporter(opts.Name, opts.Version, opts.EphemeralID), monitoring.Report)

	setupPlatformSpecificMetrics(opts.Logger, processStats, opts.SystemMetrics, opts.ProcessMetrics)

	return nil
}

// processName truncates the name if it is longer than 15 characters, so we don't fail process checks later on
// On *nix, the process name comes from /proc/PID/stat, which uses a comm value of 16 bytes, plus the null byte
func processName(name string) string {
	if (isLinux() || isDarwin()) && len(name) > 15 {
		name = name[:15]
	}
	return name
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func infoReporter(serviceName, version, ephemeralID string) func(_ monitoring.Mode, V monitoring.Visitor) {
	return func(_ monitoring.Mode, V monitoring.Visitor) {
		V.OnRegistryStart()
		defer V.OnRegistryFinished()

		delta := time.Since(startTime)
		uptime := int64(delta / time.Millisecond)
		monitoring.ReportNamespace(V, "uptime", func() {
			monitoring.ReportInt(V, "ms", uptime)
		})

		monitoring.ReportString(V, "ephemeral_id", ephemeralID)
		monitoring.ReportString(V, "name", serviceName)
		monitoring.ReportString(V, "version", version)
	}
}

func setupPlatformSpecificMetrics(logger *logp.Logger, processStats *process.Stats, systemMetrics, processMetrics *monitoring.Registry) {
	if isLinux() {
		monitoring.NewFunc(processMetrics, "cgroup", InstanceCroupsReporter(logger, monitoringCgroupsHierarchyOverride), monitoring.Report)
	}

	if isWindows() {
		SetupWindowsHandlesMetrics(logger, systemMetrics)
	} else {
		monitoring.NewFunc(systemMetrics, "load", ReportSystemLoadAverage(logger), monitoring.Report)
	}

	SetupLinuxBSDFDMetrics(logger, processMetrics, processStats)
}
