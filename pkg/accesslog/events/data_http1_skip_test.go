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

package events

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols/http1skip"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// http1Record is a perf record of a single chunk HTTP/1 call of connection 900
func http1Record(t testing.TB, dataID, prevDataID uint64, data []byte) []byte {
	var record bytes.Buffer
	wire := &socketDataUploadWire{Protocol0: enums.ConnectionProtocolHTTP, Finished: 1, DataLen: uint16(len(data)),
		ConnectionID: 900, RandomID: 3, DataID0: dataID, PrevDataID0: prevDataID, TotalSize0: uint64(len(data)),
		Direction0: enums.SocketDataDirectionIngress, StartTime0: 1000 + dataID, FunctionName: 7, L4PackageCount: 2}
	if err := binary.Write(&record, binary.LittleEndian, wire); err != nil {
		t.Fatal(err)
	}
	record.Write(data)
	return record.Bytes()
}

func http1SkipBody(n int) []byte {
	return bytes.Repeat([]byte("abcdefghij"), n/10)
}

// TestHTTP1BodyCallDecodedWithoutItsBytes: a body call is decoded as the same event without its bytes and
// without a pooled buffer, and the calls that are not skipped are decoded as without the tracker
func TestHTTP1BodyCallDecodedWithoutItsBytes(t *testing.T) {
	http1skip.ResetRegistry()
	head := []byte("POST /orders HTTP/1.1\r\nHost: orders\r\nContent-Length: 12000\r\n\r\n")
	records := [][]byte{http1Record(t, 1, 0, head), http1Record(t, 2, 1, http1SkipBody(6000)),
		http1Record(t, 3, 2, http1SkipBody(6000))}
	var plain []*SocketDataUploadEvent
	for _, r := range records {
		plain = append(plain, readUploadEvent(t, r))
	}
	// what an event without pooled buffer is charged
	inflight := buffer.InflightBytes()
	if !buffer.AcquireEvent() {
		t.Fatal("the memory protection is off in the test")
	}
	small := readUploadEvent(t, uploadRecord(t, []byte("tiny")))
	eventCharge := buffer.InflightBytes() - inflight
	small.Discard()
	SetHTTP1BodySkipper(http1skip.NewTracker(InlineDataSize + 1))
	defer SetHTTP1BodySkipper(nil)
	for i, r := range records {
		inflight := buffer.InflightBytes()
		if !buffer.AcquireEvent() {
			t.Fatal("the memory protection is off in the test")
		}
		e := readUploadEvent(t, r)
		if e.DecodeSequence() == 0 {
			t.Fatalf("call %d: no decode sequence", i)
		}
		want := *plain[i]
		want.Buffer, want.DecodeSeq0 = nil, e.DecodeSeq0
		got := *e
		got.Buffer = nil
		if i == 0 {
			if e.PayloadSkipped() || !bytes.Equal(e.BufferData(), head) || !reflect.DeepEqual(got, want) {
				t.Fatalf("the head is not decoded as without the tracker")
			}
			e.Discard()
			continue
		}
		want.PayloadSkipped0 = PayloadSkippedHTTP1Body
		if !e.PayloadSkipped() || !e.BodyPayloadSkipped() || e.Buffer != nil || e.BufferData() != nil ||
			e.BufferLen() != 6000 || !reflect.DeepEqual(got, want) {
			t.Fatalf("call %d: skipped %t, buffer %d, len %d", i, e.PayloadSkipped(), len(e.Buffer), e.BufferLen())
		}
		// the event is charged its struct only
		if held := buffer.InflightBytes() - inflight; held != eventCharge {
			t.Fatalf("call %d: in-flight charge %d, want %d", i, held, eventCharge)
		}
		if d := e.Detach(); !d.PayloadSkipped() || d.BufferLen() != 6000 {
			t.Fatalf("the detached copy lost the skip")
		}
		e.Discard()
		if buffer.InflightBytes() != inflight {
			t.Fatalf("call %d: in-flight %d after the release, %d before", i, buffer.InflightBytes(), inflight)
		}
	}
}

// TestDroppedSampleObserverFindsTheConnection: a record dropped before the decode leaves the connection
// out of step
func TestDroppedSampleObserverFindsTheConnection(t *testing.T) {
	http1skip.ResetRegistry()
	tracker := http1skip.NewTracker(InlineDataSize + 1)
	SetHTTP1BodySkipper(tracker)
	defer SetHTTP1BodySkipper(nil)
	readUploadEvent(t, http1Record(t, 1, 0, []byte("POST /orders HTTP/1.1\r\nHost: orders\r\nContent-Length: 30000\r\n\r\n")))
	if e := readUploadEvent(t, http1Record(t, 2, 1, http1SkipBody(10000))); !e.PayloadSkipped() {
		t.Fatalf("not skipped")
	}
	DroppedSampleObserver(tracker)(http1Record(t, 3, 2, http1SkipBody(10000)))
	if e := readUploadEvent(t, http1Record(t, 4, 3, http1SkipBody(10000))); e.PayloadSkipped() {
		t.Fatalf("skipped behind a dropped call")
	}
}

// TestHTTP1BodySkipOfAShortSample: a sample shorter than the length it announces is not decided by the tracker (it
// would note a call the reader then fails to decode)
func TestHTTP1BodySkipOfAShortSample(t *testing.T) {
	http1skip.ResetRegistry()
	SetHTTP1BodySkipper(http1skip.NewTracker(InlineDataSize + 1))
	defer SetHTTP1BodySkipper(nil)
	record := http1Record(t, 1, 0, []byte("POST /orders HTTP/1.1\r\nHost: orders\r\nContent-Length: 12000\r\n\r\n"))
	short := record[:len(record)-10]
	var e SocketDataUploadEvent
	reader := btf.NewReader(short)
	e.ReadFrom(reader)
	if reader.HasError() == nil {
		t.Fatal("a short sample reads")
	}
	if e.DecodeSeq0 != 0 || e.PayloadSkipped() {
		t.Fatal("the tracker decided on a short sample")
	}
}
