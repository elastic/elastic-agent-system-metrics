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

//go:build aix
// +build aix

package filesystem

import (
	"fmt"
	"unsafe"
)

/*
#include <sys/types.h>
#include <sys/mntctl.h>
#include <sys/vmount.h>
*/
import "C"

// get the list of mounts on aix
func parseMounts(_ string, filter func(FSStat) bool) ([]FSStat, error) {
	buf, ret, err := aixVmount()
	if err != nil {
		return nil, fmt.Errorf("error fetching mounts: %w", err)
	}

	fsList := []FSStat{}

	// iterate through every vmount struct contained in buf
	var nextBufIdx uint
	for i := 0; i < int(ret); i++ {
		vmt := (*C.struct_vmount)(unsafe.Pointer(&buf[nextBufIdx]))
		nextBufIdx += uint(vmt.vmt_length)

		// Parse fields
		vmt_object := vmtDataToString(vmt, vmt.vmt_data[C.VMT_OBJECT])
		vmt_stub := vmtDataToString(vmt, vmt.vmt_data[C.VMT_STUB])
		vmt_hostname := vmtDataToString(vmt, vmt.vmt_data[C.VMT_HOSTNAME])
		vmt_args := vmtDataToString(vmt, vmt.vmt_data[C.VMT_ARGS])

		device := vmt_object
		if vmt_hostname != "-" && vmt_hostname != "" {
			device = device + vmt_hostname
		}

		fs := FSStat{
			Device:    device,
			Directory: vmt_stub,
			Type:      aixGetFsName(int(vmt.vmt_gfstype)),
			Options:   vmt_args,
		}

		if filter(fs) {
			fsList = append(fsList, fs)
		}
	}

	return fsList, nil
}

// aixVmount calls the vmount MCTL_QUERY function and returns the buffer
// with the number of vmount structs.
func aixVmount() ([]C.char, int, error) {
	bufSize := 8 * 1024 // sane initial buffer size
	buf := make([]C.char, bufSize)

	// First call to vmount
	ret, errno := C.mntctl(C.MCTL_QUERY, (C.ulong)(bufSize), &buf[0])
	if ret == -1 {
		return nil, 0, fmt.Errorf("mntctl failed with errno %d", errno)
	}

	// Check if our buffer was to small
	if ret == 0 {
		// Now use the proposed buffer size, which is stored as a word (4 bytes) in our previous buffer.
		bufSize := int(*((*C.uint)(unsafe.Pointer(&buf[0]))))
		if bufSize < 4 {
			return nil, 0, fmt.Errorf("something is wrong, the proposed buffer of %d bytes can't even store a new proposal", bufSize)
		}

		// Create a new buffer with the proposed size and try again
		buf = make([]C.char, bufSize)

		ret, errno = C.mntctl(C.MCTL_QUERY, (C.ulong)(bufSize), &buf[0])
		if ret == -1 {
			return nil, 0, fmt.Errorf("second call to mntctl failed with errno %d", errno)
		}

		if ret == 0 {
			return nil, 0, fmt.Errorf("second call to mntctl with buffer size %d bytes failed and proposed again a new buffer size", bufSize)
		}
	}

	return buf, int(ret), nil
}

// vmtDataToString decodes the vmt_data structures of vmount as Go string
func vmtDataToString(vmt *C.struct_vmount, data C.struct_vmt_data) string {
	ptr := unsafe.Pointer(vmt)
	ptr = unsafe.Add(ptr, data.vmt_off)
	return C.GoString((*C.char)(ptr))
}

// aixGetFsName maps the gfs_type to the string values as described in vmount.h
func aixGetFsName(gfstype int) string {
	fsmap := map[int]string{
		C.MNT_J2:      "jfs2",
		C.MNT_NAMEFS:  "namefs",
		C.MNT_NFS:     "nfs",
		C.MNT_JFS:     "jfs",
		C.MNT_CDROM:   "cdrom",
		C.MNT_PROCFS:  "procfs",
		C.MNT_SFS:     "sfs",
		C.MNT_CACHEFS: "cachefs",
		C.MNT_NFS3:    "nfs3",
		C.MNT_AUTOFS:  "autofs",
		C.MNT_POOLFS:  "poolfs",
		C.MNT_VXFS:    "vxfs",
		C.MNT_VXODM:   "vxodm",
		C.MNT_UDF:     "udf",
		C.MNT_NFS4:    "nfs4",
		C.MNT_RFS4:    "rfs4",
		C.MNT_CIFS:    "cifs",
		C.MNT_PMEMFS:  "pmemfs",
		C.MNT_AHAFS:   "ahafs",
		C.MNT_STNFS:   "stnfs",
		C.MNT_ASMFS:   "asmfs",
		C.MNT_SMBC:    "smb",
	}

	fsname, ok := fsmap[gfstype]
	if !ok {
		return "unknown"
	}

	return fsname
}
