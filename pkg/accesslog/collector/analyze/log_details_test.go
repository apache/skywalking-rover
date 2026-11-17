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

package analyze

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"google.golang.org/protobuf/proto"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
)

// TestMessageDetailsMatchesDetachThenMerge: messageDetails gives what detaching every socket call and
// merging the copies gives, without touching the events of the buffer and without sharing one of them
func TestMessageDetailsMatchesDetachThenMerge(t *testing.T) {
	base := bpfNow()
	var calls []*events.SocketDataUploadEvent
	var buffers []buffer.SocketDataBuffer
	funcs := []enums.SocketFunctionName{enums.SocketFunctionNameRead, enums.SocketFunctionNameRead, enums.SocketFunctionNameRead,
		enums.SocketFunctionNameWrite, enums.SocketFunctionNameWrite, enums.SocketFunctionNameRead}
	for i, f := range funcs {
		e := &events.SocketDataUploadEvent{DataID0: uint64(i + 1), FunctionName: uint32(f), StartTime0: base + uint64(i),
			EndTime0: base + uint64(i) + 10, L4PackageCount: 1, L4TotalPackageSize: uint64(100 + i), Buffer: []byte("data")}
		calls = append(calls, e)
		buffers = append(buffers, e)
		if i == 1 {
			// a second chunk of the same socket call
			chunk := *e
			chunk.Sequence0 = 1
			buffers = append(buffers, &chunk)
		}
	}
	for _, merge := range []bool{false, true} {
		common.SetMergeKernelLogs(merge)
		var expected []events.SocketDetail
		for _, e := range calls {
			expected = append(expected, e.Detach())
		}
		if merge {
			expected = events.MergeDetails(expected)
		}
		before := make([]events.SocketDataUploadEvent, len(calls))
		for i, e := range calls {
			before[i] = *e
		}
		got := messageDetails(buffers)
		if len(got) != len(expected) {
			t.Fatalf("merge=%t: %d details, expected %d", merge, len(got), len(expected))
		}
		for i := range got {
			g, e := got[i].(*events.SocketDataUploadEvent), expected[i].(*events.SocketDataUploadEvent)
			if !reflect.DeepEqual(*g, *e) {
				t.Fatalf("merge=%t: detail %d is %+v, expected %+v", merge, i, *g, *e)
			}
			for _, c := range calls {
				if g == c {
					t.Fatalf("merge=%t: detail %d is the event of the buffer itself", merge, i)
				}
			}
		}
		for i, e := range calls {
			if !reflect.DeepEqual(*e, before[i]) {
				t.Fatalf("merge=%t: the event %d of the buffer was changed", merge, i)
			}
		}
	}
	common.SetMergeKernelLogs(false)
}

// TestMessageDetailsOfDataIDZero: a first call of data id 0 has its detail like any other
func TestMessageDetailsOfDataIDZero(t *testing.T) {
	common.SetMergeKernelLogs(false)
	base := bpfNow()
	var buffers []buffer.SocketDataBuffer
	for i := 0; i < 2; i++ {
		buffers = append(buffers, &events.SocketDataUploadEvent{DataID0: uint64(i), FunctionName: uint32(enums.SocketFunctionNameWrite),
			StartTime0: base + uint64(i), EndTime0: base + uint64(i) + 10, Buffer: []byte("data")})
	}
	if details := messageDetails(buffers); len(details) != 2 || details[0].DataID() != 0 {
		t.Fatalf("%d details", len(details))
	}
}

// TestMessageDetailsNeedNoSecondMerge: merging the details of messageDetails again gives the same details,
// so taking them as they are (HTTPProtocolLog.build) and common.NewProtocolLogEvent give the same log. The calls repeat
// chunks, alternate between operations and cross minutes.
func TestMessageDetailsNeedNoSecondMerge(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	funcs := []enums.SocketFunctionName{enums.SocketFunctionNameRead, enums.SocketFunctionNameRecvfrom,
		enums.SocketFunctionNameWrite, enums.SocketFunctionNameWritev}
	for _, merge := range []bool{false, true} {
		common.SetMergeKernelLogs(merge)
		for round := 0; round < 500; round++ {
			var buffers []buffer.SocketDataBuffer
			at := bpfNow()
			for i := 0; i < 1+r.Intn(12); i++ {
				at += uint64(r.Int63n(int64(20 * time.Second)))
				e := &events.SocketDataUploadEvent{DataID0: uint64(i + 1), FunctionName: uint32(funcs[r.Intn(len(funcs))]),
					StartTime0: at, EndTime0: at + 10, L4PackageCount: 1, L4TotalPackageSize: uint64(r.Intn(2000))}
				buffers = append(buffers, e)
				if r.Intn(4) == 0 {
					chunk := *e
					chunk.Sequence0 = 1
					buffers = append(buffers, &chunk)
				}
			}
			details := messageDetails(buffers)
			again := common.NewProtocolLogEvent(details, &v3.AccessLogProtocolLogs{}).RelateKernelLogs()
			if len(again) != len(details) {
				t.Fatalf("merge=%t round %d: %d details merged again, %d", merge, round, len(again), len(details))
			}
			for i := range again {
				if again[i] != details[i] {
					t.Fatalf("merge=%t round %d: detail %d differs", merge, round, i)
				}
			}
		}
	}
	common.SetMergeKernelLogs(false)
}

// messageLogBuffers is the calls of a message: 4 reads then 4 writes
func messageLogBuffers() []buffer.SocketDataBuffer {
	base := bpfNow()
	var buffers []buffer.SocketDataBuffer
	for i := 0; i < 8; i++ {
		f := enums.SocketFunctionNameRead
		if i >= 4 {
			f = enums.SocketFunctionNameWrite
		}
		buffers = append(buffers, &events.SocketDataUploadEvent{DataID0: uint64(i + 1), FunctionName: uint32(f),
			StartTime0: base + uint64(i), EndTime0: base + uint64(i) + 10, L4PackageCount: 1, L4TotalPackageSize: 100})
	}
	return buffers
}

// TestHTTPProtocolLogAsTheMessages: the log built in one allocation is the log of the messages built one by one,
// down to the bytes proto.Marshal gives
func TestHTTPProtocolLogAsTheMessages(t *testing.T) {
	details := messageDetails(messageLogBuffers())
	for i, c := range []struct {
		version     v3.AccessLogHTTPProtocolVersion
		start, end  uint64
		path, host  string
		method      v3.AccessLogHTTPProtocolRequestMethod
		status      int32
		sizes       [4]uint64
		sni, tlsSNI string
	}{
		{version: v3.AccessLogHTTPProtocolVersion_HTTP1, start: bpfNow(), end: bpfNow() + 99, path: "/a", host: "h:80",
			method: v3.AccessLogHTTPProtocolRequestMethod_Post, status: 200, sizes: [4]uint64{40, 1024, 30, 2048}, sni: "s"},
		{version: v3.AccessLogHTTPProtocolVersion_HTTP2, start: ^uint64(0), end: 1, path: "/caf\u00e9", status: -1,
			sizes: [4]uint64{1 << 40, 0, 7, 0}},
		{},
	} {
		startTime, endTime := forwarder.BuildOffsetTimestamps(c.start, c.end)
		request := &v3.AccessLogHTTPProtocolRequest{Method: c.method, Path: c.path, SizeOfHeadersBytes: c.sizes[0],
			SizeOfBodyBytes: c.sizes[1], Host: c.host}
		response := &v3.AccessLogHTTPProtocolResponse{StatusCode: c.status, SizeOfHeadersBytes: c.sizes[2], SizeOfBodyBytes: c.sizes[3]}
		want := NewNamedProtocolLog(&common.ProtocolEventData{KernelLogs: details, ProtocolLogData: &v3.AccessLogProtocolLogs{
			Protocol: &v3.AccessLogProtocolLogs_Http{Http: &v3.AccessLogHTTPProtocol{
				StartTime: startTime, EndTime: endTime, Version: c.version, Request: request, Response: response,
			}},
		}}, c.sni, c.host)
		bundle := &HTTPProtocolLog{
			HTTP: v3.AccessLogHTTPProtocol{Version: c.version},
			Request: v3.AccessLogHTTPProtocolRequest{Method: c.method, Path: c.path, SizeOfHeadersBytes: c.sizes[0],
				SizeOfBodyBytes: c.sizes[1], Host: c.host},
			Response: v3.AccessLogHTTPProtocolResponse{StatusCode: c.status, SizeOfHeadersBytes: c.sizes[2], SizeOfBodyBytes: c.sizes[3]},
		}
		got, ok := bundle.Build(details, c.start, c.end, c.sni, c.host).(*NamedProtocolLog)
		if !ok || got.SNI != want.SNI || got.Host != want.Host || !reflect.DeepEqual(got.RelateKernelLogs(), want.RelateKernelLogs()) {
			t.Fatalf("case %d: log %+v, expected %+v", i, got, want)
		}
		if !proto.Equal(got.ProtocolLog(), want.ProtocolLog()) {
			t.Fatalf("case %d: %v, expected %v", i, got.ProtocolLog(), want.ProtocolLog())
		}
		gotBytes, err1 := proto.MarshalOptions{Deterministic: true}.Marshal(got.ProtocolLog())
		wantBytes, err2 := proto.MarshalOptions{Deterministic: true}.Marshal(want.ProtocolLog())
		if err1 != nil || err2 != nil || !bytes.Equal(gotBytes, wantBytes) {
			t.Fatalf("case %d: %x (%v), expected %x (%v)", i, gotBytes, err1, wantBytes, err2)
		}
	}
}
