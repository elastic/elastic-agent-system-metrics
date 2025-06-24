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

package filesystem

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent-libs/opt"
)

func parseMounts(_ string, filter func(FSStat) bool) ([]FSStat, error) {
	drives, err := getAccessPaths()
	if err != nil {
		return nil, fmt.Errorf("GetAccessPaths failed: %w", err)
	}

	driveList := []FSStat{}
	for _, drive := range drives {
		fsType, err := getFilesystemType(drive)
		if err != nil {
			return nil, fmt.Errorf("GetFilesystemType failed: %w", err)
		}
		fs := FSStat{
			Directory: drive,
			Device:    drive,
			Type:      fsType,
		}
		if fsType != "" && filter(fs) {
			driveList = append(driveList, fs)
		}
	}

	return driveList, nil
}

func (fs *FSStat) GetUsage() error {
	directoryNamePtr, err := windows.UTF16PtrFromString(fs.Directory)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed for directoryName=%v: %w", fs.Directory, err)
	}

	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	err = windows.GetDiskFreeSpaceEx(directoryNamePtr, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)
	if err != nil {
		return fmt.Errorf("GetDiskFreeSpaceEx failed: %w", err)
	}

	fs.Total = opt.UintWith(totalNumberOfBytes)
	fs.Free = opt.UintWith(totalNumberOfFreeBytes)
	fs.Avail = opt.UintWith(freeBytesAvailable)

	fs.fillMetrics()

	return nil
}

func getAccessPaths() ([]string, error) {
	volumes, err := getVolumes()
	if err != nil {
		return nil, fmt.Errorf("GetVolumes failed: %w", err)
	}

	var paths []string
	for _, volumeName := range volumes {
		volumePaths, err := getVolumePathsForVolume(volumeName)
		if err != nil {
			return nil, fmt.Errorf("failed to get list of access paths for volume '%s': %w", volumeName, err)
		}
		if len(volumePaths) == 0 {
			continue
		}

		// Get only the first path
		paths = append(paths, volumePaths[0])
	}

	return paths, nil
}

// MAX_PATH is the maximum length for a path in Windows.
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
const MAX_PATH = 260

func getVolumes() ([]string, error) {
	buffer := make([]uint16, MAX_PATH+1)

	var volumes []string

	h, err := windows.FindFirstVolume(&buffer[0], uint32(len(buffer)))
	if err != nil {
		return nil, fmt.Errorf("FindFirstVolumeW failed: %w", err)
	}
	defer windows.FindVolumeClose(h)

	for {
		volumes = append(volumes, windows.UTF16ToString(buffer))

		err = windows.FindNextVolume(h, &buffer[0], uint32(len(buffer)))
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, fmt.Errorf("FindNextVolumeW failed: %w", err)
		}
	}

	return volumes, nil
}

func getVolumePathsForVolume(volumeName string) ([]string, error) {
	volumeNamePtr, err := windows.UTF16PtrFromString(volumeName)
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString failed for volumeName=%v: %w", volumeName, err)
	}

	var length uint32
	err = windows.GetVolumePathNamesForVolumeName(volumeNamePtr, nil, 0, &length)
	if errors.Is(err, windows.ERROR_MORE_DATA) {
		return nil, fmt.Errorf("GetVolumePathNamesForVolumeNameW failed to get needed buffer length: %w", err)
	}
	if length == 0 {
		// Not mounted, no paths, that's ok
		return nil, nil
	}

	buffer := make([]uint16, length*(MAX_PATH+1))
	err = windows.GetVolumePathNamesForVolumeName(volumeNamePtr, &buffer[0], length, &length)
	if err != nil {
		return nil, fmt.Errorf("GetVolumePathNamesForVolumeNameW failed: %w", err)
	}

	return UTF16SliceToStringSlice(buffer), nil
}

func UTF16SliceToStringSlice(buffer []uint16) []string {
	// Split the uint16 slice at null-terminators.
	var startIdx int
	var stringsUTF16 [][]uint16
	for i, value := range buffer {
		if value == 0 {
			stringsUTF16 = append(stringsUTF16, buffer[startIdx:i])
			startIdx = i + 1
		}
	}

	// Convert the utf16 slices to strings.
	result := make([]string, 0, len(stringsUTF16))
	for _, stringUTF16 := range stringsUTF16 {
		if len(stringUTF16) > 0 {
			result = append(result, windows.UTF16ToString(stringUTF16))
		}
	}

	return result
}

func getFilesystemType(rootPathName string) (string, error) {
	rootPathNamePtr, err := windows.UTF16PtrFromString(rootPathName)
	var systemType = "unavailable"
	if err != nil {
		return "", fmt.Errorf("UTF16PtrFromString failed for rootPathName=%v: %w", rootPathName, err)
	}
	buffer := make([]uint16, MAX_PATH+1)
	// _GetVolumeInformation will fail for external drives like CD-ROM or other type with error codes as ERROR_NOT_READY. ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, etc., these types of errors will be ignored
	err = windows.GetVolumeInformation(rootPathNamePtr, nil, 0, nil, nil, nil, &buffer[0], MAX_PATH)
	if err == nil {
		systemType = strings.ToLower(windows.UTF16ToString(buffer))
	}
	return systemType, nil
}
