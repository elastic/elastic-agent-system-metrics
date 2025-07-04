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

//go:build freebsd || linux || aix || solaris
// +build freebsd linux aix solaris

package filesystem

import (
	"fmt"
	"os"
	"strings"
)

// actually get the list of mounts on linux
func parseMounts(path string, filter func(FSStat) bool) ([]FSStat, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading mount file %s: %w", path, err)
	}
	fsList := []FSStat{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		fs := FSStat{
			Device:    fields[0],
			Directory: fields[1],
			Type:      fields[2],
			Options:   fields[3],
		}
		if filter(fs) {
			fsList = append(fsList, fs)
		}
	}

	return fsList, nil
}
