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

package bytesutil

import (
	"iter"
)

var asciiSpace = [256]bool{'\t': true, '\n': true, '\v': true, '\f': true, '\r': true, ' ': true}

// Fields returns an iterator that yields the fields of byte array b split around each single
// ASCII white space character (space, tab, newline, vertical tab, form feed, carriage return).
// It can be used with range loops like this:
//
//	for i, field := range stringutil.Fields(b) {
//	    fmt.Printf("Field %d: %v\n", i, field)
//	}
func Fields(b []byte) iter.Seq2[int, []byte] {
	return func(yield func(int, []byte) bool) {
		for i, bi := 0, 0; bi < len(b); i++ {
			fieldStart := bi
			// Find the end of the field
			for bi < len(b) && !asciiSpace[b[bi]] {
				bi++
			}
			if !yield(i, b[fieldStart:bi]) {
				return
			}
			bi++
		}
	}
}

// Split returns an iterator that yields the fields of byte array b split around
// the given character.
// It can be used with range loops like this:
//
//	for i, field := range stringutil.Split(b, ',') {
//	    fmt.Printf("Field %d: %v\n", i, field)
//	}
func Split(b []byte, sep byte) iter.Seq2[int, []byte] {
	return func(yield func(int, []byte) bool) {
		for i, bi := 0, 0; bi < len(b); i++ {
			fieldStart := bi
			// Find the end of the field
			for bi < len(b) && b[bi] != sep {
				bi++
			}
			if !yield(i, b[fieldStart:bi]) {
				return
			}
			bi++
		}
	}
}
