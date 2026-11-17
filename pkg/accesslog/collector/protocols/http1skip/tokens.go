// Licensed to Apache Software Foundation (ASF) under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Apache Software Foundation (ASF) licenses this file to you under
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

package http1skip

import (
	"bytes"
	"strings"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
)

// startTokens are what the analyzer takes a message start by (reader.IdentityMessageType)
var startTokens = reader.StartTokens()

// maxTokenLen is the length of the longest start token
var maxTokenLen = func() int {
	n := 0
	for _, t := range startTokens {
		n = max(n, len(t))
	}
	return n
}()

// anchor is a start token and the offset of a byte of it that the scan looks for
type anchor struct {
	token  string
	offset int
}

// anchors finds every start token by one of two bytes: all but HEAD have a 'T', HEAD has a 'D'
var anchors = func() (result [2][]anchor) {
	for _, t := range startTokens {
		if i := strings.IndexByte(t, 'T'); i >= 0 {
			result[0] = append(result[0], anchor{token: t, offset: i})
			continue
		}
		i := strings.IndexByte(t, 'D')
		if i < 0 {
			panic("a start token without an anchor byte: " + t)
		}
		result[1] = append(result[1], anchor{token: t, offset: i})
	}
	return result
}()

var anchorBytes = [2]byte{'T', 'D'}

// firstBytes are the first bytes of the start tokens
var firstBytes = func() (result [256]bool) {
	for _, t := range startTokens {
		result[t[0]] = true
	}
	return result
}()

// tokenFree tells that the analyzer cannot take any position of the data for a message start: no start
// token begins anywhere in it, and it does not end with the first bytes of one (a peek there would go on
// into the next call). The analyzer then never parses a head in these bytes, wherever it stands in them,
// and a call that is token free reads the same to it with or without its bytes.
func tokenFree(data []byte) bool {
	for i, c := range anchorBytes {
		for from := 0; from < len(data); {
			k := bytes.IndexByte(data[from:], c)
			if k < 0 {
				break
			}
			p := from + k
			for _, a := range anchors[i] {
				start := p - a.offset
				if start >= 0 && start+len(a.token) <= len(data) && string(data[start:start+len(a.token)]) == a.token {
					return false
				}
			}
			from = p + 1
		}
	}
	// a token cut by the end of the data
	for k := max(0, len(data)-maxTokenLen+1); k < len(data); k++ {
		if !firstBytes[data[k]] {
			continue
		}
		rest := data[k:]
		for _, t := range startTokens {
			if len(rest) < len(t) && string(rest) == t[:len(rest)] {
				return false
			}
		}
	}
	return true
}

// edgesTokenFree is tokenFree for the edges of the data: it does not start with a start token or the first
// bytes of one, and no start token begins so close to its end that the peek there reads into the next call.
// It costs nothing against the size of a call, unlike a scan of all of it.
func edgesTokenFree(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	for _, t := range startTokens {
		if data[0] != t[0] {
			continue
		}
		n := min(len(t), len(data))
		if string(data[:n]) == t[:n] {
			return false
		}
	}
	return tokenFree(data[max(0, len(data)-peekSize+1):])
}

// tailTokenFree tells that no start token begins in tail, the bytes the analyzer reads right before data,
// whether it ends in tail or runs on into data: a peek for a message start from anywhere in tail (shorter
// than peekSize) would read into data. Unlike the edges of data, tail may be the end of calls that were not
// checked: too small to skip, uploaded in chunks or truncated.
func tailTokenFree(tail, data []byte) bool {
	for p := 0; p < len(tail); p++ {
		if !firstBytes[tail[p]] {
			continue
		}
		rest := tail[p:]
		for _, t := range startTokens {
			if t[0] != rest[0] {
				continue
			}
			if len(rest) >= len(t) {
				if string(rest[:len(t)]) == t {
					return false
				}
				continue
			}
			if string(rest) != t[:len(rest)] {
				continue
			}
			more := t[len(rest):]
			n := min(len(more), len(data))
			if string(data[:n]) == more[:n] {
				return false
			}
		}
	}
	return true
}
