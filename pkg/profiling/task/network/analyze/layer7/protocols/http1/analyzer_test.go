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

package http1

import (
	"bufio"
	"container/list"
	"net/http"
	"reflect"
	"strings"
	"testing"

	base2 "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
)

var unknown, request, response = 0, 1, 2
var finished, notFinished = 1, 0

// nolint
func TestBuildHTTP1(t *testing.T) {
	tests := []struct {
		name   string
		events []struct {
			dataID   int
			dataType int
			sequence int
			finished int
			data     string
		}
		http []struct {
			start int
			end   int
		}
		residueID []int
	}{
		{
			name: "simple",
			events: []struct {
				dataID   int
				dataType int
				sequence int
				finished int
				data     string
			}{
				{1, request, 0, notFinished, ""},
				{1, request, 1, notFinished, ""},
				{1, request, 2, finished, ""},
				{2, response, 0, notFinished, ""},
				{2, response, 1, finished, ""},

				{3, request, 0, finished, ""},
				{4, response, 0, finished, ""},
			},
			http: []struct {
				start int
				end   int
			}{
				{1, 2},
				{3, 4},
			},
			residueID: []int{},
		},
		{
			name: "response before request",
			events: []struct {
				dataID   int
				dataType int
				sequence int
				finished int
				data     string
			}{
				{2, response, 0, finished, ""},
				{1, request, 1, finished, ""},
				{1, request, 0, notFinished, ""},

				{3, request, 0, notFinished, ""},
				{3, request, 1, notFinished, ""},
				{4, response, 1, finished, ""},
				{4, response, 0, notFinished, ""},
				{3, request, 2, finished, ""},

				{5, request, 0, notFinished, ""},
				{5, request, 1, notFinished, ""},
				{6, response, 1, finished, ""},
				{6, response, 0, notFinished, ""},
				{5, request, 2, finished, ""},
			},
			http: []struct {
				start int
				end   int
			}{
				{1, 2},
				{3, 4},
				{5, 6},
			},
			residueID: []int{},
		},
		{
			name: "residue requests",
			events: []struct {
				dataID   int
				dataType int
				sequence int
				finished int
				data     string
			}{
				{1, request, 0, finished, ""},
				{2, response, 1, finished, ""},
				{2, response, 0, notFinished, ""},

				{3, request, 0, finished, ""},
				{4, response, 0, notFinished, ""},

				{5, request, 1, finished, ""},
				{6, response, 0, finished, ""},
			},
			http: []struct {
				start int
				end   int
			}{
				{1, 2},
			},
			residueID: []int{3, 4, 5, 6},
		},
		{
			name: "multiple request",
			events: []struct {
				dataID   int
				dataType int
				sequence int
				finished int
				data     string
			}{
				{1, request, 0, finished, ""},
				{2, request, 0, finished, ""},
			},
			http: []struct {
				start int
				end   int
			}{},
			residueID: []int{1, 2},
		},
		{
			name: "multiple response",
			events: []struct {
				dataID   int
				dataType int
				sequence int
				finished int
				data     string
			}{
				{1, request, 0, finished, ""},
				{3, response, 1, finished, ""},
				{4, response, 0, finished, ""},
			},
			http: []struct {
				start int
				end   int
			}{},
			residueID: []int{1, 3, 4},
		},
		{
			name: "unfinished response",
			events: []struct {
				dataID   int
				dataType int
				sequence int
				finished int
				data     string
			}{
				{42, response, 0, notFinished, ""},
				{42, response, 1, notFinished, ""},
				{42, response, 2, finished, ""},

				{48, request, 0, finished, ""},
				{50, response, 0, notFinished, ""},
				{50, response, 1, notFinished, ""},
				{50, response, 2, finished, ""},
			},
			http: []struct {
				start int
				end   int
			}{
				{48, 50},
			},
			residueID: []int{42, 42, 42},
		},
		{
			name: "unknown data",
			events: []struct {
				dataID   int
				dataType int
				sequence int
				finished int
				data     string
			}{
				{1, unknown, 0, notFinished, "GET / HTTP/1.1\r\n"},
				{1, unknown, 1, notFinished, "Host: test.com\n\r\n"},
				{2, response, 0, finished, ""},

				{3, unknown, 1, notFinished, "Host: test.com\n\r\n"},
				{4, response, 0, finished, ""},
				{3, unknown, 0, notFinished, "GET / HTTP/1.1\r\n"},

				{6, unknown, 1, notFinished, "Host: test.com\n\r\n"},
				{5, request, 0, finished, ""},
				{6, unknown, 0, notFinished, "HTTP/1.1 200 OK\r\n"},

				// request not finished
				{7, unknown, 1, notFinished, "Host: test.com\n"},
				{8, response, 0, finished, ""},
				{7, unknown, 0, notFinished, "GET / HTTP/1.1\r\n"},
				{9, request, 0, finished, ""},
				{10, response, 0, finished, ""},
			},
			http: []struct {
				start int
				end   int
			}{
				{1, 2},
				{3, 4},
				{5, 6},
				{9, 10},
			},
			residueID: []int{7, 7, 8},
		},
	}

	for _, testCase := range tests {
		//t.Run(testCase.name, func(t *testing.T) {
		analyzer := NewHTTP1Analyzer().(*Analyzer)
		l := list.New()
		var events = make([]struct {
			start, end int
		}, 0)
		for _, event := range testCase.events {
			req, resp := analyzer.buildHTTP1(l, &base2.SocketDataUploadEvent{
				DataID:   uint64(event.dataID),
				MsgType:  base.SocketMessageType(event.dataType),
				Sequence: uint16(event.sequence),
				Finished: uint8(event.finished),
				Buffer:   bufferConvert(event.data),
				DataLen:  uint16(len(event.data)),
			})
			if req != nil && resp != nil {
				events = append(events, struct{ start, end int }{start: req.MinDataID(), end: resp.MaxDataID()})
			}
		}

		if !reflect.DeepEqual(testCase.http, events) {
			t.Fatalf("excepted http: %v, actual: %v", testCase.http, events)
		}

		exceptedList := testCase.residueID
		if exceptedList == nil {
			exceptedList = make([]int, 0)
		}
		actualList := make([]int, 0)
		for element := l.Front(); element != nil; element = element.Next() {
			actualList = append(actualList, int(element.Value.(*base2.SocketDataUploadEvent).DataID))
		}
		if !reflect.DeepEqual(exceptedList, actualList) {
			t.Fatalf("excepted residue data list: %v, actual: %v", exceptedList, actualList)
		}
		//})
	}
}

var defaultBuffer [2048]byte

func bufferConvert(data string) [2048]byte {
	if data == "" {
		return defaultBuffer
	}
	var buffer [2048]byte
	for inx, d := range []byte(data) {
		buffer[inx] = d
	}
	return buffer
}

func TestParseSimpleHTTP1Response(t *testing.T) {
	s := `HTTP/1.0 200 OK\r\n`
	h := &http.Request{}
	analyzer := NewHTTP1Analyzer().(*Analyzer)
	resp, err := analyzer.tryingToReadResponseWithoutHeaders(bufio.NewReader(strings.NewReader(s)), h)
	if err != nil {
		t.Fatalf("reading simple response error: %v", err)
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
}
