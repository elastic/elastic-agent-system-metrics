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
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	getLogicalProcessorInformationEx = modkernel32.NewProc("GetLogicalProcessorInformationEx")
)

type SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX struct {
	Relationship uint32
	Size         uint32
}

type GROUP_RELATIONSHIP struct {
	MaximumGroupCount uint16
	ActiveGroupCount  uint16
	Reserved          [20]uint8
	// variable size array of PROCESSOR_GROUP_INFO
	ProcesorGrupInfo []PROCESSOR_GROUP_INFO
}

type PROCESSOR_GROUP_INFO struct {
	MaximumProcessorCount byte
	ActiveProcessorCount  byte
	Reserved              [38]byte
	ActiveProcessorMask   uint64
}

func convertByteTpProcessorInformationStruct(data []byte) (inf SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) {
	inf.Relationship = binary.LittleEndian.Uint32(data)
	inf.Size = binary.LittleEndian.Uint32(data[4:])
	return
}

func convertByteToGroupStruct(data []byte) (group GROUP_RELATIONSHIP) {
	group.MaximumGroupCount = binary.LittleEndian.Uint16(data)
	group.ActiveGroupCount = binary.LittleEndian.Uint16(data[2:4])
	if group.ActiveGroupCount > 0 {
		groups := make([]PROCESSOR_GROUP_INFO, group.ActiveGroupCount)
		for i := uint16(0); i < group.ActiveGroupCount; i++ {
			groups[i].MaximumProcessorCount = data[24] // need to account for 20 reserved bytes
			groups[i].ActiveProcessorCount = data[25]
			groups[i].ActiveProcessorMask = binary.LittleEndian.Uint64(data[63:]) // need to account for 20 reserved bytes + 38 reserved bytes
		}
		group.ProcesorGrupInfo = groups
	}
	return
}

// getCPU implements NumCPU on windows
// For now, this is a bit of a hack that just asks for per-CPU performance data, and reports the CPU count
func getCPU() (int, bool, error) {
	var bufLen uint32 = 0
	_, _, err := getLogicalProcessorInformationEx.Call(uintptr(4), uintptr(0), uintptr(unsafe.Pointer(&bufLen)))
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return -1, false, err
	}
	if bufLen == 0 {
		return -1, false, windows.Errno(1)
	}
	buf := make([]byte, bufLen)
	_, _, err = getLogicalProcessorInformationEx.Call(uintptr(4), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufLen)))
	if err != nil && err != windows.ERROR_SUCCESS {
		return -1, false, err
	}
	index := 0
	numCpus := 0
	for index < int(bufLen) {
		processorInformation := convertByteTpProcessorInformationStruct(buf[index:])
		group := convertByteToGroupStruct(buf[index+8:]) // the parent struct is of 8 bytes
		index += int(processorInformation.Size)
		for _, groupInfo := range group.ProcesorGrupInfo {
			// count cores per processor group
			numCpus += int(groupInfo.ActiveProcessorCount)
		}
	}
	return numCpus, true, nil
}
