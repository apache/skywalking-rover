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
	"fmt"
	"math/rand"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
)

// headTestCompare: a head HeadParser accepts in the first call is the head the analyzer reads there, up
// to the same byte, whatever follows in the next call
func headTestCompare(t *testing.T, first, next string) bool {
	t.Helper()
	var p HeadParser
	head, ok := p.Parse([]byte(first))
	if !ok {
		return false
	}
	buf := buffer2(first, next)
	r := NewReader()
	typ, err := r.IdentityMessageType(buf)
	if err != nil {
		t.Fatalf("%q: identity: %v", first, err)
	}
	var length int64
	var header map[string][]string
	if head.Request {
		if typ != MessageTypeRequest {
			t.Fatalf("%q: identity %d", first, typ)
		}
		req, _, err := r.ReadRequest(buf, false)
		if err != nil || req == nil {
			t.Fatalf("%q: the analyzer rejects the request: %v", first, err)
		}
		if req.Original().Method != head.Method {
			t.Fatalf("%q: method %s, want %s", first, head.Method, req.Original().Method)
		}
		length, header = req.HeaderBuffer().DataSize(), req.Headers()
	} else {
		if typ != MessageTypeResponse {
			t.Fatalf("%q: identity %d", first, typ)
		}
		resp, _, err := r.ReadResponse(nil, buf, false)
		if err != nil || resp == nil || resp.Headers() == nil {
			t.Fatalf("%q: the analyzer rejects the response: %v", first, err)
		}
		//nolint:bodyclose // the response is parsed from captured socket data, it has no body to close
		if resp.Original().StatusCode != head.StatusCode {
			t.Fatalf("%q: status %d, want %d", first, head.StatusCode, resp.Original().StatusCode)
		}
		length, header = resp.HeaderBuffer().DataSize(), resp.Headers()
	}
	if length != int64(head.Length) {
		t.Fatalf("%q: head length %d, the analyzer reads %d", first, head.Length, length)
	}
	for _, name := range []string{"Content-Length", "Transfer-Encoding"} {
		if fmt.Sprint(header[name]) != fmt.Sprint(head.Header[name]) {
			t.Fatalf("%q: %s %v, the analyzer reads %v", first, name, head.Header[name], header[name])
		}
	}
	return true
}

// buffer2 is a buffer of two calls
func buffer2(first, next string) *buffer.Buffer {
	b := buffer.NewBuffer()
	b.AppendDataEvent(&fastTestEvent{dataID: 1, start: true, finished: true, data: []byte(first)})
	if next != "" {
		b.AppendDataEvent(&fastTestEvent{dataID: 2, prevDataID: 1, start: true, finished: true, data: []byte(next)})
	}
	b.PrepareForReading()
	return b
}

func TestHeadParserReadsWhatTheAnalyzerReads(t *testing.T) {
	accepted := []string{
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
		"POST /orders?id=1 HTTP/1.1\r\nHost: orders:8080\r\nContent-Length: 12\r\n\r\nhello world!",
		"PUT /x HTTP/1.0\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n",
		"DELETE /a HTTP/1.1\r\ncontent-length: 7\r\nx-a: GET / HTTP/1.1\r\n\r\n",
	}
	for _, head := range accepted {
		if !headTestCompare(t, head, "next call bytes") {
			t.Fatalf("not accepted: %q", head)
		}
	}
	rejected := []string{
		"GET / HTTP/1.1\r\nHost: a\r\n",       // incomplete
		"GET / HTTP/1.1\r\n Host: a\r\n\r\n",  // obs-fold
		"GETX / HTTP/1.1\r\nHost: a\r\n\r\n",  // not a method
		"GET / HTTP/2.0\r\nHost: a\r\n\r\n",   // version
		"HTTP/1.1 2000 OK\r\nHost: a\r\n\r\n", // status
		"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost a\r\n\r\n",  // no colon
		"get / HTTP/1.1\r\nHost: a\r\n\r\n", // not a method
		"xx",
	}
	for _, head := range rejected {
		if headTestCompare(t, head, "") {
			t.Fatalf("accepted: %q", head)
		}
	}
}

func TestHeadParserRandomHeads(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	bases := []string{
		"POST /orders HTTP/1.1\r\nHost: orders:8080\r\nContent-Length: 100\r\nAccept: */*\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: text/plain\r\nDate: Mon, 09 Nov 2026 10:00:00 GMT\r\n\r\n",
	}
	alphabet := []byte("abcAZ09 :\r\n\t/-%?")
	accepted := 0
	for i := 0; i < 20000; i++ {
		data := []byte(bases[i%2])
		for n := rnd.Intn(4); n > 0; n-- {
			k := rnd.Intn(len(data))
			switch rnd.Intn(3) {
			case 0:
				data[k] = alphabet[rnd.Intn(len(alphabet))]
			case 1:
				data = append(data[:k], data[k+1:]...)
			default:
				data = append(data[:k], append([]byte{alphabet[rnd.Intn(len(alphabet))]}, data[k:]...)...)
			}
		}
		if headTestCompare(t, string(data)+"tail", "GET / HTTP/1.1\r\n") {
			accepted++
		}
	}
	if accepted < 1000 {
		t.Fatalf("only %d accepted", accepted)
	}
}
