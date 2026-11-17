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

package collector

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// gapTestRecord writes a raw upload record in the order events.SocketDataUploadEvent.ReadFrom reads it
func gapTestRecord(t *testing.T, ssl uint8, sequence uint16, data []byte) []byte {
	return gapTestRecordMarked(t, ssl, sequence, 0, data)
}

// gapTestRecordMarked is gapTestRecord with the payload_skipped mark
func gapTestRecordMarked(t *testing.T, ssl uint8, sequence uint16, mark uint8, data []byte) []byte {
	var b bytes.Buffer
	w := func(v any) {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	w(uint8(enums.ConnectionProtocolHTTP)) // protocol
	w(uint8(0))                            // have reduce
	w(uint8(1))                            // l4 package count
	w(uint8(1))                            // finished
	w(sequence)
	w(uint16(len(data)))
	w(uint32(3)) // function
	w(ssl)
	w(uint8(0))  // pad
	w(uint16(0)) // in flight
	w(uint64(100))
	w(uint64(200))
	w(uint64(0x1122334455667788)) // connection id
	w(uint64(0x0102030405060708)) // random id
	w(uint64(4242))               // data id
	w(uint64(4241))               // prev data id
	w(uint64(len(data)))          // total size
	w(uint64(0))                  // l4 total package size
	w(uint8(enums.SocketDataDirectionIngress))
	w(mark)      // payload skipped
	w(uint16(1)) // local port
	w(uint16(2)) // remote port
	w(uint16(0)) // data id span
	w(uint32(0)) // summarised bytes in front
	w(uint32(0)) // the stream of the run in front
	w(uint16(0)) // the frames of the run
	w(uint16(0)) // pad
	b.Write(data)
	return b.Bytes()
}

// TestDecodeDroppedRecordMatchesReadFrom: the offsets the gap handling reads a refused record at are the
// fields the event decoder reads
func TestDecodeDroppedRecordMatchesReadFrom(t *testing.T) {
	for _, tc := range []struct {
		ssl      uint8
		sequence uint16
		data     string
		starts   bool
	}{
		{0, 0, "POST /upload HTTP/1.1\r\nContent-Length: 10\r\n\r\n", true},
		{0, 1, "POST /upload HTTP/1.1\r\n", false},
		{0, 0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{1, 0, "HTTP/1.1 200 OK\r\n\r\n", false},
	} {
		record := gapTestRecord(t, tc.ssl, tc.sequence, []byte(tc.data))
		decoded, ok := decodeDroppedRecord(record)
		if !ok {
			t.Fatal("the record was not decoded")
		}
		if !buffer.AcquireEvent() {
			t.Fatal("the memory protection is off in the test")
		}
		e := &events.SocketDataUploadEvent{}
		reader := btf.NewReader(record)
		e.ReadFrom(reader)
		if err := reader.HasError(); err != nil {
			t.Fatal(err)
		}
		if decoded.connectionID != e.ConnectionID || decoded.randomID != e.RandomID || decoded.dataID != e.DataID0 ||
			decoded.protocol != e.Protocol0 || decoded.sequence != e.Sequence0 || decoded.ssl != (e.SSL != 0) {
			t.Fatalf("decoded %+v, the event reads %+v", decoded, e)
		}
		if decoded.startsRequest != tc.starts || !bytes.Equal(record[recordDataOffset:], e.BufferData()) {
			t.Fatalf("starts request %t, want %t; data %q", decoded.startsRequest, tc.starts, record[recordDataOffset:])
		}
		e.Discard()
	}
	if _, ok := decodeDroppedRecord(make([]byte, recordDataOffset-1)); ok {
		t.Fatal("a short record must be ignored")
	}
}

func TestDroppedSampleObserverChain(t *testing.T) {
	var calls []int
	observe := droppedSampleObserver(func([]byte) { calls = append(calls, 1) }, func([]byte) { calls = append(calls, 2) })
	observe(nil)
	if len(calls) != 2 || calls[0] != 1 || calls[1] != 2 {
		t.Fatalf("calls %v", calls)
	}
}

// TestShedRecord: an event BPF sent without its data under memory pressure is told by its mark, at the
// offset the event decoder reads payload_skipped at, counts as dropped, is noted for the gap handling like
// a refused event (the request start told by the first bytes it carries), and decodes into an event
// without a protocol that keeps every detail of its call (the kernel log) and no data
func TestShedRecord(t *testing.T) {
	_, dropped0, _, _ := buffer.MemoryStats()
	shed := gapTestRecordMarked(t, 0, 0, recordPayloadShed, []byte("OPTIONS "))
	// the size of the call, not of the bytes it carries
	binary.LittleEndian.PutUint64(shed[recordTotalSizeOffset:], 70_000)
	if !isShedRecord(shed) {
		t.Fatal("the shed record is not told")
	}
	if decoded, ok := decodeDroppedRecord(shed); !ok || !decoded.startsRequest || decoded.dataID != 4242 {
		t.Fatalf("the shed record decodes as %+v", decoded)
	}
	e := supplyShedEvent().(*events.SocketDataUploadEvent)
	reader := btf.NewReader(shed)
	e.ReadFrom(reader)
	if err := reader.HasError(); err != nil {
		t.Fatal(err)
	}
	if !e.Shed() || e.Protocol0 != enums.ConnectionProtocolUnknown || e.DataLen != 0 || e.BufferLen() != 0 ||
		e.PayloadSkipped0 != 0 || e.TotalSize0 != 70_000 || e.StartTime0 != 100 || e.EndTime0 != 200 ||
		e.FunctionName != 3 || e.L4PackageCount != 1 || e.ConnectionID != 0x1122334455667788 || e.DataID0 != 4242 ||
		e.PrevDataID0 != 4241 || e.Direction0 != enums.SocketDataDirectionIngress || e.LocalPort != 1 || e.RemotePort != 2 {
		t.Fatalf("the shed event decodes as %+v", *e)
	}
	buffer.ReleaseEvent(e.ReleaseBuffer())
	for _, mark := range []uint8{0, 1, 2} {
		if isShedRecord(gapTestRecordMarked(t, 0, 0, mark, []byte("GET "))) {
			t.Fatalf("a record marked %d is not shed", mark)
		}
	}
	if isShedRecord(shed[:recordDataOffset-1]) {
		t.Fatal("a short record is not shed")
	}
	if _, dropped, _, _ := buffer.MemoryStats(); dropped-dropped0 != 1 {
		t.Fatalf("the shed record counts as dropped once, counted %d", dropped-dropped0)
	}
}

// TestCountDroppedRecord: the calls and the bytes the memory protection dropped are counted by reason: a
// shed record is one call of its total size, a refused record its data, the call with its first chunk
func TestCountDroppedRecord(t *testing.T) {
	shedCalls0, shedBytes0 := buffer.DroppedCalls(buffer.DropReasonKernelShed)
	memCalls0, memBytes0 := buffer.DroppedCalls(buffer.DropReasonMemory)
	shed := gapTestRecordMarked(t, 0, 0, recordPayloadShed, []byte("GET "))
	binary.LittleEndian.PutUint64(shed[recordTotalSizeOffset:], 50_000)
	countDroppedRecord(shed)
	countDroppedRecord(shed)
	first := gapTestRecord(t, 0, 0, bytes.Repeat([]byte{'a'}, 300))
	second := gapTestRecord(t, 0, 1, bytes.Repeat([]byte{'b'}, 200))
	countDroppedRecord(first)
	countDroppedRecord(second)
	countDroppedRecord(first[:recordDataOffset-1])
	shedCalls, shedBytes := buffer.DroppedCalls(buffer.DropReasonKernelShed)
	memCalls, memBytes := buffer.DroppedCalls(buffer.DropReasonMemory)
	if shedCalls-shedCalls0 != 2 || shedBytes-shedBytes0 != 100_000 || memCalls-memCalls0 != 1 || memBytes-memBytes0 != 500 {
		t.Fatalf("kernel shed %d calls %d bytes, memory %d calls %d bytes", shedCalls-shedCalls0, shedBytes-shedBytes0,
			memCalls-memCalls0, memBytes-memBytes0)
	}
}
