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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
)

/*
#include <procinfo.h>
#include <sys/types.h>
*/
import "C"

// FetchPids returns a map and array of pids
func (procStats *Stats) FetchPids() (ProcsMap, []ProcState, error) {

	info := C.struct_procsinfo64{}
	pid := C.pid_t(0)

	procMap := make(ProcsMap, 0)
	var wrappedErr error
	var plist []ProcState
	for {
		// getprocs first argument is a void*
		num, err := C.getprocs(unsafe.Pointer(&info), C.sizeof_struct_procsinfo64, nil, 0, &pid, 1)
		if err != nil {
			return nil, nil, fmt.Errorf("error fetching PIDs: %w", err)
		}
		procMap, plist, err = procStats.pidIter(int(pid), procMap, plist)
		wrappedErr = errors.Join(wrappedErr, err)

		if num == 0 {
			break
		}
	}
	return procMap, plist, toNonFatal(wrappedErr)
}

// GetInfoForPid returns basic info for the process
func GetInfoForPid(_ resolve.Resolver, pid int) (ProcState, error) {
	info := C.struct_procsinfo64{}
	cpid := C.pid_t(pid)

	num, err := C.getprocs(unsafe.Pointer(&info), C.sizeof_struct_procsinfo64, nil, 0, &cpid, 1)
	if err != nil {
		return ProcState{}, fmt.Errorf("error in getprocs: %w", err)
	}
	if num != 1 {
		return ProcState{}, syscall.ESRCH
	}

	state := ProcState{}
	state.Pid = opt.IntWith(pid)

	state.Name = C.GoString(&info.pi_comm[0])
	state.Ppid = opt.IntWith(int(info.pi_ppid))
	state.Pgid = opt.IntWith(int(info.pi_pgrp))

	switch info.pi_state {
	case C.SACTIVE:
		state.State = Running
	case C.SIDL:
		state.State = Idle
	case C.SSTOP:
		state.State = Stopped
	case C.SZOMB:
		state.State = Zombie
	case C.SSWAP:
		state.State = Sleeping
	default:
		state.State = Unknown
	}

	// Get process username. Fallback to UID if username is not available.
	uid := strconv.Itoa(int(info.pi_uid))
	userID, err := user.LookupId(uid)
	if err == nil && userID.Username != "" {
		state.Username = userID.Username
	} else {
		state.Username = uid
	}

	return state, nil
}

// FillPidMetrics is the aix implementation
func FillPidMetrics(_ resolve.Resolver, pid int, state ProcState, filter func(string) bool) (ProcState, error) {
	pagesize := uint64(os.Getpagesize())
	info := C.struct_procsinfo64{}
	cpid := C.pid_t(pid)

	num, err := C.getprocs(unsafe.Pointer(&info), C.sizeof_struct_procsinfo64, nil, 0, &cpid, 1)
	if err != nil {
		return state, fmt.Errorf("error in getprocs: %w", err)
	}
	if num != 1 {
		return state, syscall.ESRCH
	}

	state.Memory.Size = opt.UintWith(uint64(info.pi_size) * pagesize)
	state.Memory.Share = opt.UintWith(uint64(info.pi_sdsize) * pagesize)
	state.Memory.Rss.Bytes = opt.UintWith(uint64(info.pi_drss+info.pi_trss) * pagesize)

	state.CPU.StartTime = unixTimeMsToTime(uint64(info.pi_start) * 1000)
	state.CPU.User.Ticks = opt.UintWith(uint64(info.pi_utime) * 1000)
	state.CPU.System.Ticks = opt.UintWith(uint64(info.pi_stime) * 1000)
	state.CPU.Total.Ticks = opt.UintWith(opt.SumOptUint(state.CPU.User.Ticks, state.CPU.System.Ticks))

	// Get Proc Args
	/* If buffer is not large enough, args are truncated */
	buf := make([]byte, 8192)
	info.pi_pid = C.pid_t(pid)

	if _, err := C.getargs(unsafe.Pointer(&info), C.sizeof_struct_procsinfo64, (*C.char)(&buf[0]), 8192); err != nil {
		return state, fmt.Errorf("error in getargs: %w", err)
	}

	bbuf := bytes.NewBuffer(buf)
	var args []string

	for {
		arg, err := bbuf.ReadBytes(0)
		if err == io.EOF || arg[0] == 0 {
			break
		}
		if err != nil {
			return state, fmt.Errorf("error reading args buffer: %w", err)
		}

		args = append(args, stripNullByte(arg))
	}
	state.Args = args
	state.Exe = args[0]

	// get env vars
	buf = make([]byte, 8192)

	if _, err := C.getevars(unsafe.Pointer(&info), C.sizeof_struct_procsinfo64, (*C.char)(&buf[0]), 8192); err != nil {
		return state, fmt.Errorf("error in getevars: %w", err)
	}

	if state.Env != nil {
		return state, nil
	}

	bbuf = bytes.NewBuffer(buf)
	delim := []byte{61} // "="
	vars := mapstr.M{}
	for {
		line, err := bbuf.ReadBytes(0)
		if errors.Is(err, io.EOF) || line[0] == 0 {
			break
		}
		if err != nil {
			return state, fmt.Errorf("error: %w", err)
		}

		pair := bytes.SplitN(stripNullByteRaw(line), delim, 2)
		if len(pair) != 2 {
			return state, fmt.Errorf("error reading environment: %w", err)
		}
		eKey := string(pair[0])
		if filter == nil || filter(eKey) {
			vars[string(pair[0])] = string(pair[1])
		}

	}
	state.Env = vars

	return state, nil
}

func FillMetricsRequiringMoreAccess(_ int, state ProcState) (ProcState, error) {
	return state, nil
}

func GetSelfPid(hostfs resolve.Resolver) (int, error) {
	return os.Getpid(), nil
}
