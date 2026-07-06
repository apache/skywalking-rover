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

package protocols

import (
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	analyzeevents "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// buildDetailBuffer builds a minimal, fully-captured buffer that holds a single detail event with
// the given data id, so BuildDetails() is non-empty and BuildTotalDataIDRange() covers it.
func buildDetailBuffer(dataID, start, end uint64) *buffer.Buffer {
	b := buffer.NewBuffer()
	b.AppendDataEvent(&analyzeevents.SocketDataUploadEvent{
		DataID0: dataID, DataLen: 1, StartTime0: start, EndTime0: end, Finished: 1,
	})
	b.AppendDetailEvent(&aclevents.SocketDetailEvent{DataID0: dataID, StartTime: start, EndTime: end})
	b.PrepareForReading()
	return b
}

type noopQueueConsumer struct{}

func (noopQueueConsumer) Consume(_ chan common.KernelLog, _ chan common.ProtocolLog) {}

// TestAppendSocketDetailsFromBuffer covers the buffer-classification logic at the heart of the panic
// fix: a nil (absent) buffer is skipped, a present-but-empty buffer is incomplete, and a
// fully-captured buffer contributes its details.
func TestAppendSocketDetailsFromBuffer(t *testing.T) {
	// a nil buffer with allInclude=true must be skipped, not marked incomplete (the core fix).
	if _, idRange, include := AppendSocketDetailsFromBuffer(nil, nil, nil, true); !include || idRange != nil {
		t.Fatalf("nil buffer should be skipped: include=%v idRange=%v", include, idRange)
	}
	// once incomplete, a following nil buffer keeps the stream incomplete.
	if _, _, include := AppendSocketDetailsFromBuffer(nil, nil, nil, false); include {
		t.Fatal("incomplete state must be propagated through a nil buffer")
	}
	// a present-but-empty buffer is treated as incomplete.
	if _, _, include := AppendSocketDetailsFromBuffer(nil, buffer.NewBuffer(), nil, true); include {
		t.Fatal("empty buffer should be marked incomplete")
	}
	// a present buffer whose details fall outside its captured data-id range (e.g. dropped perf
	// samples left a gap) is incomplete, not skipped.
	incomplete := buffer.NewBuffer()
	incomplete.AppendDataEvent(&analyzeevents.SocketDataUploadEvent{DataID0: 1, DataLen: 1, Finished: 1})
	incomplete.AppendDetailEvent(&aclevents.SocketDetailEvent{DataID0: 5})
	incomplete.PrepareForReading()
	if _, _, include := AppendSocketDetailsFromBuffer(nil, incomplete, nil, true); include {
		t.Fatal("buffer with details outside its data-id range should be incomplete")
	}

	// a fully-captured buffer contributes its detail and stays complete.
	details, idRange, include := AppendSocketDetailsFromBuffer(nil, buildDetailBuffer(1, 10, 20), nil, true)
	if !include || len(details) != 1 || idRange == nil || idRange.From != 1 || idRange.To != 1 {
		t.Fatalf("complete buffer: include=%v len=%d idRange=%v", include, len(details), idRange)
	}
}

func TestDataIDRangeBounds(t *testing.T) {
	if from, to := DataIDRangeBounds(nil); from != 0 || to != 0 {
		t.Fatalf("nil range must be (0,0), got (%d,%d)", from, to)
	}
	if from, to := DataIDRangeBounds(&buffer.DataIDRange{From: 3, To: 9}); from != 3 || to != 9 {
		t.Fatalf("expected (3,9), got (%d,%d)", from, to)
	}
}

// TestHTTP2HandleWholeStreamIncompleteNoPanic guards against the SIGSEGV that used to happen when a
// stream reached HandleWholeStream without a fully-captured set of detail events. The error path
// previously dereferenced possibly-nil buffers (stream.RespBodyBuffer.LastSocketBuffer().DataID());
// it must now return an error safely instead of panicking.
func TestHTTP2HandleWholeStreamIncompleteNoPanic(t *testing.T) {
	r := &HTTP2Protocol{}
	tests := []struct {
		name   string
		stream *HTTP2Streaming
	}{
		{
			name:   "all buffers absent",
			stream: &HTTP2Streaming{ReqHeader: map[string]string{}, RespHeader: map[string]string{}},
		},
		{
			name: "present but empty request header buffer, bodies absent",
			stream: &HTTP2Streaming{
				ReqHeader:       map[string]string{},
				RespHeader:      map[string]string{},
				ReqHeaderBuffer: buffer.NewBuffer(),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := r.HandleWholeStream(nil, test.stream)
			if err == nil {
				t.Fatal("expected an error when detail events are incomplete, got nil")
			}
		})
	}
}

// TestHTTP2HandleWholeStreamReportsWhenBodiless proves the root-cause fix: a stream with request and
// response headers but no bodies (e.g. a GET with a 204/304 response that ends on the HEADERS frame)
// must now be reported instead of being dropped/panicking on the nil body buffers.
func TestHTTP2HandleWholeStreamReportsWhenBodiless(t *testing.T) {
	r := &HTTP2Protocol{ctx: &common.AccessLogContext{
		Queue: common.NewQueue(100, time.Minute, noopQueueConsumer{}),
	}}
	stream := &HTTP2Streaming{
		ReqHeader:        map[string]string{":path": "/", ":authority": "example"},
		RespHeader:       map[string]string{":status": "204"},
		ReqHeaderBuffer:  buildDetailBuffer(1, 10, 20),
		RespHeaderBuffer: buildDetailBuffer(2, 30, 40),
		// ReqBodyBuffer and RespBodyBuffer are intentionally nil (bodiless).
	}
	if err := r.HandleWholeStream(nil, stream); err != nil {
		t.Fatalf("bodiless stream should be reported, got error: %v", err)
	}
}

func TestHTTP2ParseHTTPMethod(t *testing.T) {
	r := &HTTP2Protocol{}
	tests := []struct {
		method string
		expect v3.AccessLogHTTPProtocolRequestMethod
	}{
		{"", v3.AccessLogHTTPProtocolRequestMethod_Get},      // absent method defaults to GET
		{"post", v3.AccessLogHTTPProtocolRequestMethod_Post}, // lower-cased method is upper-cased first
		{"patch", v3.AccessLogHTTPProtocolRequestMethod_Patch},
		{"weird", v3.AccessLogHTTPProtocolRequestMethod_Get}, // unknown method falls back to GET
	}
	for _, test := range tests {
		stream := &HTTP2Streaming{ReqHeader: map[string]string{}}
		if test.method != "" {
			stream.ReqHeader[":method"] = test.method
		}
		if got := r.ParseHTTPMethod(stream); got != test.expect {
			t.Fatalf("method %q: expected %v, got %v", test.method, test.expect, got)
		}
	}
}

func TestHTTP2FirstDetail(t *testing.T) {
	r := &HTTP2Protocol{}
	def := &aclevents.SocketDetailEvent{DataID0: 99}
	if got := r.FirstDetail(nil, def); got != def {
		t.Fatal("nil buffer should return the default detail")
	}
	if got := r.FirstDetail(buffer.NewBuffer(), def); got != def {
		t.Fatal("empty buffer should return the default detail")
	}
	if got := r.FirstDetail(buildDetailBuffer(7, 1, 2), def); got == def || got.DataID() != 7 {
		t.Fatalf("present buffer should return its own first detail, got DataID=%d", got.DataID())
	}
}

func TestHTTP2BufferSizeOfZero(t *testing.T) {
	r := &HTTP2Protocol{}
	if size := r.BufferSizeOfZero(nil); size != 0 {
		t.Fatalf("nil buffer size must be 0, got %d", size)
	}
	if size := r.BufferSizeOfZero(buildDetailBuffer(1, 1, 2)); size == 0 {
		t.Fatal("present buffer size must be non-zero")
	}
}
