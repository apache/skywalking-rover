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

package reader

import (
	"bufio"
	"bytes"
	"net/http"
)

// StartTokens are the prefixes IdentityMessageType takes a message start by: the request methods and
// "HTTP" of a status line
func StartTokens() []string {
	return append(append([]string(nil), requestMethods...), "HTTP")
}

// Head is the head of a message HeadParser accepted
type Head struct {
	Request    bool
	Method     string // of a request
	StatusCode int    // of a response
	// Header holds the headers the fast scanner keeps (fastHeaderNames)
	Header http.Header
	// Length is the size of the start line, the header lines and the blank line
	Length int
}

// HeadParser parses the head of a message that starts a byte slice the way the analyzer starts reading
// it: IdentityMessageType, then the fast scanner over a bufio reader of the same size, so a head it
// accepts is one the analyzer reads the same, ending at the same byte. It only accepts what the fast
// scanner accepts, the textproto fallback is never tried. Not safe for concurrent use.
type HeadParser struct {
	src bytes.Reader
	br  *bufio.Reader
}

// Parse returns the head the data starts with, false when the data does not start with a complete head
// the fast scanner accepts
func (p *HeadParser) Parse(data []byte) (Head, bool) {
	var head Head
	if len(data) < 16 {
		return head, false // IdentityMessageType needs 16 bytes
	}
	if p.br == nil {
		p.br = bufio.NewReader(nil) // the size of the analyzer's pooled readers
	}
	p.src.Reset(data)
	p.br.Reset(&p.src)
	switch {
	case hasMethodPrefix(data):
		req := readRequestHeadFast(p.br)
		if req == nil {
			return head, false
		}
		head.Request, head.Method, head.Header = true, req.Method, req.Header
	case bytes.HasPrefix(data, []byte("HTTP")):
		resp := readResponseHeadFast(p.br) //nolint:bodyclose // the response is parsed from captured socket data, it has no body to close
		if resp == nil {
			return head, false
		}
		head.StatusCode, head.Header = resp.StatusCode, resp.Header
	default:
		return head, false
	}
	head.Length = len(data) - p.src.Len() - p.br.Buffered()
	return head, true
}

// hasMethodPrefix is the request test of IdentityMessageType
func hasMethodPrefix(data []byte) bool {
	for _, method := range requestMethods {
		if len(data) >= len(method) && string(data[:len(method)]) == method {
			return true
		}
	}
	return false
}
