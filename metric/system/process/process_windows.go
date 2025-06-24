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

package process

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
	gowindows "github.com/elastic/go-windows"
)

var (
	ntQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
)

// FetchPids returns a map and array of pids
func (procStats *Stats) FetchPids() (ProcsMap, []ProcState, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, nil, fmt.Errorf("EnumProcesses failed: %w", err)
	}

	procMap := make(ProcsMap, len(pids))
	plist := make([]ProcState, 0, len(pids))
	var wrappedErr error
	// This is probably the only implementation that doesn't benefit from our
	// little fillPid callback system. We'll need to iterate over everything
	// manually.
	for _, pid := range pids {
		procMap, plist, err = procStats.pidIter(int(pid), procMap, plist)
		wrappedErr = errors.Join(wrappedErr, err)
	}

	return procMap, plist, toNonFatal(wrappedErr)
}

// GetSelfPid is the darwin implementation; see the linux version in
// process_linux_common.go for more context.
func GetSelfPid(hostfs resolve.Resolver) (int, error) {
	return os.Getpid(), nil
}

// GetInfoForPid returns basic info for the process
func GetInfoForPid(_ resolve.Resolver, pid int) (ProcState, error) {
	var err error
	var errs []error
	state := ProcState{Pid: opt.IntWith(pid)}
	if pid == 0 {
		// we cannot open pid 0. Skip it and move forward.
		// we will call getIdleMemory and getIdleProcessTime in FillPidMetrics()
		state.Username = "NT AUTHORITY\\SYSTEM"
		state.Name = "System Idle Process"
		state.State = Running
		return state, nil
	}

	name, err := getProcName(pid)
	if err != nil {
		errs = append(errs, fmt.Errorf("error fetching name: %w", err))
	} else {
		state.Name = name
	}

	// system/process doesn't need this here, but system/process_summary does.
	status, err := getPidStatus(pid)
	if err != nil {
		errs = append(errs, fmt.Errorf("error fetching status: %w", err))
	} else {
		state.State = status
	}

	if err := errors.Join(errs...); err != nil {
		return state, fmt.Errorf("could not get all information for PID %d: %w",
			pid, err)
	}

	return state, nil
}

func FetchNumThreads(pid int) (int, error) {
	targetProcessHandle, err := syscall.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid))
	if err != nil {
		return 0, fmt.Errorf("OpenProcess failed for PID %d: %w", pid, err)
	}
	defer func() {
		_ = syscall.CloseHandle(targetProcessHandle)
	}()

	currentProcessHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("GetCurrentProcess failed for PID %d: %w", pid, err)
	}
	// The pseudo handle need not be closed when it is no longer
	// needed, calling CloseHandle has no effect.  Adding here to
	// remind us to close any handles we open.
	defer func() {
		_ = syscall.CloseHandle(currentProcessHandle)
	}()

	var snapshotHandle syscall.Handle
	err = PssCaptureSnapshot(targetProcessHandle, PSSCaptureThreads, 0, &snapshotHandle)
	if err != nil {
		return 0, fmt.Errorf("PssCaptureSnapshot failed for PID %d: %w", pid, err)
	}

	info := PssThreadInformation{}
	buffSize := unsafe.Sizeof(info)
	queryErr := PssQuerySnapshot(snapshotHandle, PssQueryThreadInformation, &info, uint32(buffSize))
	freeErr := PssFreeSnapshot(currentProcessHandle, snapshotHandle)
	if queryErr != nil || freeErr != nil {
		//Join discards any nil errors
		return 0, errors.Join(
			fmt.Errorf("PssQuerySnapshot failed: %w", queryErr),
			fmt.Errorf("PssFreeSnapshot failed: %w", freeErr))
	}

	return int(info.ThreadsCaptured), nil
}

// FillPidMetrics is the windows implementation
func FillPidMetrics(_ resolve.Resolver, pid int, state ProcState, _ func(string) bool) (ProcState, error) {
	if pid == 0 {
		// get metrics for idle process
		return fillIdleProcess(state)
	}
	user, _ := getProcCredName(pid)
	state.Username = user // we cannot access process token for system-owned protected processes

	if ppid, err := getParentPid(pid); err == nil {
		state.Ppid = opt.IntWith(ppid)
	}

	wss, size, err := procMem(pid)
	if err != nil {
		return state, fmt.Errorf("error fetching memory: %w", err)
	}
	state.Memory.Rss.Bytes = opt.UintWith(wss)
	state.Memory.Size = opt.UintWith(size)

	ps := process.Process{
		Pid: int32(pid),
	}

	stat, err := ps.Times()
	if err != nil {
		return state, fmt.Errorf("error getting CPU times: %w", err)
	}

	sysTime := uint64(time.Duration(stat.System) / time.Millisecond)
	userTime := uint64(time.Duration(stat.User) / time.Millisecond)

	state.CPU.System.Ticks = opt.UintWith(sysTime)
	state.CPU.User.Ticks = opt.UintWith(userTime)
	state.CPU.Total.Ticks = opt.UintWith(userTime + sysTime)

	startTime, err := ps.CreateTime()
	if err != nil {
		return state, fmt.Errorf("error getting process CreateTime: %w", err)
	}

	state.CPU.StartTime = unixTimeMsToTime(uint64(startTime))

	return state, nil
}

// FillMetricsRequiringMoreAccess
// All calls that need more access rights than
// windows.PROCESS_QUERY_LIMITED_INFORMATION
func FillMetricsRequiringMoreAccess(pid int, state ProcState) (ProcState, error) {
	argList, err := getProcArgs(pid)
	if err != nil {
		return state, fmt.Errorf("error fetching process args: %w", NonFatalErr{Err: err})
	}
	state.Args = argList

	if numThreads, err := FetchNumThreads(pid); err != nil {
		return state, fmt.Errorf("error fetching num threads: %w", NonFatalErr{Err: err})
	} else {
		state.NumThreads = opt.IntWith(numThreads)
	}

	return state, nil
}

func getProcArgs(pid int) ([]string, error) {
	ps := process.Process{
		Pid: int32(pid),
	}

	args, err := ps.CmdlineSlice()
	if err != nil {
		return nil, fmt.Errorf("error fetching cmdline: %w", err)
	}

	return args, nil
}

// procMem gets the memory usage for the given PID.
// The current implementation calls
// GetProcessMemoryInfo (https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)
// We only need `PROCESS_QUERY_LIMITED_INFORMATION` because we do not support
// Windows Server 2003 or Windows XP
func procMem(pid int) (uint64, uint64, error) {
	ps := process.Process{
		Pid: int32(pid),
	}

	info, err := ps.MemoryInfo()
	if err != nil {
		return 0, 0, fmt.Errorf("error retrieving memory for pid=%v: %w", pid, err)
	}
	return info.RSS, info.VMS, nil
}

// getProcName returns the process name associated with the PID.
func getProcName(pid int) (string, error) {
	ps := process.Process{
		Pid: int32(pid),
	}

	filename, err := ps.Name()

	//nolint:nilerr // safe to ignore this error
	if err != nil {
		if isNonFatal(err) {
			// if we're able to open the handle but GetProcessImageFileName fails with access denied error,
			// then the process doesn't have any executable associated with it.
			return "", nil
		}
		return "", err
	}

	return filename, nil
}

// getProcStatus returns the status of a process.
func getPidStatus(pid int) (PidState, error) {
	handle, err := syscall.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return Unknown, fmt.Errorf("OpenProcess failed for pid=%v: %w", pid, err)
	}
	defer func() {
		_ = syscall.CloseHandle(handle)
	}()

	var exitCode uint32
	err = syscall.GetExitCodeProcess(handle, &exitCode)
	if err != nil {
		return Unknown, fmt.Errorf("GetExitCodeProcess failed for pid=%v: %w", pid, err)
	}

	if exitCode == 259 { // still active
		return Running, nil
	}
	return Sleeping, nil
}

// getParentPid returns the parent process ID of a process.
func getParentPid(pid int) (int, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, fmt.Errorf("OpenProcess failed for pid=%v: %w", pid, err)
	}
	defer func() {
		_ = windows.CloseHandle(handle)
	}()

	ppid, err := getppid(handle)
	if err != nil {
		return 0, fmt.Errorf("NtQueryProcessBasicInformation failed for pid=%v: %w", pid, err)
	}

	return ppid, nil
}

type ProcessBasicInformation struct {
	ExitStatus                   uint
	PebBaseAddress               uintptr
	AffinityMask                 uint
	BasePriority                 uint
	UniqueProcessID              uint
	InheritedFromUniqueProcessID uint
}

func getppid(handle windows.Handle) (int, error) {
	var processBasicInfo ProcessBasicInformation
	processBasicInfoPtr := unsafe.Pointer(&processBasicInfo)
	size := uint32(unsafe.Sizeof(processBasicInfo))
	err := windows.NtQueryInformationProcess(handle, 0, processBasicInfoPtr, size, nil)
	if err != nil {
		return 0, fmt.Errorf("NtQueryInformationProcess failed: %w", err)
	}

	return int(processBasicInfo.InheritedFromUniqueProcessID), nil
}

//nolint:unused // this is actually used while dereferencing the pointer, but results in lint failure.
type systemProcessInformation struct {
	NextEntryOffset uint32
	NumberOfThreads uint32
	Reserved1       [48]byte
	ImageName       struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	}
	BasePriority           int32
	UniqueProcessID        windows.Handle
	Reserved2              uintptr
	HandleCount            uint32
	SessionID              uint32
	Reserved3              uintptr
	PeakVirtualSize        uint64
	VirtualSize            uint64
	Reserved4              uint32
	PeakWorkingSetSize     uint64
	WorkingSetSize         uint64
	Reserved5              uintptr
	QuotaPagedPoolUsage    uint64
	Reserved6              uintptr
	QuotaNonPagedPoolUsage uint64
	PagefileUsage          uint64
	PeakPagefileUsage      uint64
	PrivatePageCount       uint64
	Reserved7              [6]int64
}

func getProcCredName(pid int) (string, error) {
	handle, err := syscall.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("OpenProcess failed for pid=%v: %w", pid, err)
	}
	defer func() {
		_ = syscall.CloseHandle(handle)
	}()

	// Find process token via win32.
	var token syscall.Token
	err = syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return "", fmt.Errorf("OpenProcessToken failed for pid=%v: %w", pid, err)
	}
	// Close token to prevent handle leaks.
	defer token.Close()

	// Find the token user.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenInformation failed for pid=%v: %w", pid, err)
	}

	// Look up domain account by SID.
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		sid, sidErr := tokenUser.User.Sid.String()
		if sidErr != nil {
			return "", fmt.Errorf("failed while looking up account name for pid=%v: %w", pid, err)
		}
		return "", fmt.Errorf("failed while looking up account name for SID=%v of pid=%v: %w", sid, pid, err)
	}

	return fmt.Sprintf(`%s\%s`, domain, account), nil
}

func getIdleProcessTime() (float64, float64, error) {
	idle, kernel, user, err := gowindows.GetSystemTimes()
	if err != nil {
		return 0, 0, toNonFatal(err)
	}

	// Average by cpu because GetSystemTimes returns summation of across all cpus
	numCpus := float64(runtime.NumCPU())
	idleTime := float64(idle) / numCpus
	kernelTime := float64(kernel) / numCpus
	userTime := float64(user) / numCpus
	// Calculate total CPU time, averaged by cpu
	totalTime := idleTime + kernelTime + userTime
	return totalTime, idleTime, nil
}

func getIdleProcessMemory(state ProcState) (ProcState, error) {
	systemInfo := make([]byte, 1024*1024)
	var returnLength uint32

	_, _, err := ntQuerySystemInformation.Call(windows.SystemProcessInformation, uintptr(unsafe.Pointer(&systemInfo[0])), uintptr(len(systemInfo)), uintptr(unsafe.Pointer(&returnLength)))
	// NtQuerySystemInformation returns "operation permitted successfully"(i.e. errorno 0) on success.
	// Hence, we can ignore syscall.Errno(0).
	if err != nil && !errors.Is(err, syscall.Errno(0)) {
		return state, toNonFatal(err)
	}

	// Process the returned data
	for offset := uintptr(0); offset < uintptr(returnLength); {
		processInfo := (*systemProcessInformation)(unsafe.Pointer(&systemInfo[offset]))
		if processInfo.UniqueProcessID == 0 { // PID 0 is System Idle Process
			state.Memory.Rss.Bytes = opt.UintWith(processInfo.WorkingSetSize)
			state.Memory.Size = opt.UintWith(processInfo.PrivatePageCount)
			state.NumThreads = opt.IntWith(int(processInfo.NumberOfThreads))
			break
		}
		offset += uintptr(processInfo.NextEntryOffset)
		if processInfo.NextEntryOffset == 0 {
			break
		}
	}
	return state, nil
}

func fillIdleProcess(state ProcState) (ProcState, error) {
	state, err := getIdleProcessMemory(state)
	if err != nil {
		return state, err
	}
	_, idle, err := getIdleProcessTime()
	if err != nil {
		return state, err
	}
	state.CPU.Total.Ticks = opt.UintWith(uint64(idle / 1e6))
	state.CPU.Total.Value = opt.FloatWith(idle)
	return state, nil
}
