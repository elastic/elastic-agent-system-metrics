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

package stringutil

import (
	"strings"
	"unsafe"
)

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

// FieldsN splits the string s around each instance of one or more consecutive space
// characters, filling f with substrings of s.
// If s contains more fields than n, the last element of f is set to the
// unparsed remainder of s starting with the first non-space character.
// f will stay untouched if s is empty or contains only white space.
// if n is greater than len(f), 0 is returned without doing any parsing.
//
// Apart from the mentioned differences, FieldsN is like an allocation-free strings.Fields.
func FieldsN(s string, f []string) int {
	n := len(f)
	si := 0
	for i := 0; i < n-1; i++ {
		// Find the start of the next field.
		for si < len(s) && asciiSpace[s[si]] != 0 {
			si++
		}
		fieldStart := si

		// Find the end of the field.
		for si < len(s) && asciiSpace[s[si]] == 0 {
			si++
		}
		if fieldStart >= si {
			return i
		}

		f[i] = s[fieldStart:si]
	}

	// Find the start of the next field.
	for si < len(s) && asciiSpace[s[si]] != 0 {
		si++
	}

	// Put the remainder of s as last element of f.
	if si < len(s) {
		f[n-1] = s[si:]
		return n
	}

	return n - 1
}

// SplitN splits the string around each instance of sep, filling f with substrings of s.
// If s contains more fields than n, the last element of f is set to the
// unparsed remainder of s starting with the first non-space character.
// f will stay untouched if s is empty or contains only white space.
// if n is greater than len(f), 0 is returned without doing any parsing.
//
// Apart from the mentioned differences, SplitN is like an allocation-free strings.SplitN.
func SplitN(s, sep string, f []string) int {
	n := len(f)
	i := 0
	for ; i < n-1 && s != ""; i++ {
		fieldEnd := strings.Index(s, sep)
		if fieldEnd < 0 {
			f[i] = s
			return i + 1
		}
		f[i] = s[:fieldEnd]
		s = s[fieldEnd+len(sep):]
	}

	// Put the remainder of s as last element of f.
	f[i] = s
	return i + 1
}

// ByteSlice2String converts a byte slice into a string without a heap allocation.
// Be aware that the byte slice and the string share the same memory - which makes
// the string mutable.
func ByteSlice2String(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func SplitInline(s, sep string) []string {
	// Use a fixed-size slice to avoid allocations.
	fields := make([]string, strings.Count(s, sep)+1)
	SplitN(s, sep, fields)
	return fields
}
