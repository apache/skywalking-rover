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

package buffer

import (
	"errors"
	"io"
	"testing"
)

// skippedEvent stands for a socket call BPF uploaded without its bytes (skip_h2c_data_payload)
type skippedEvent struct {
	testEvent
	size int
}

func (e *skippedEvent) TotalSize() uint64    { return uint64(e.size) }
func (e *skippedEvent) PayloadSkipped() bool { return true }

// truncatedEvent is the last chunk of a socket call BPF truncated: total bytes were transferred
type truncatedEvent struct {
	testEvent
	total int
}

func (e *truncatedEvent) TotalSize() uint64              { return uint64(e.total) }
func (e *truncatedEvent) HaveReduceDataAfterChunk() bool { return true }

func skipTestBuffer(view bool, events ...SocketDataBuffer) *Buffer {
	b := NewBuffer()
	if view {
		b = NewViewBuffer(NewBuffer())
	}
	for _, e := range events {
		b.AppendDataEvent(e)
	}
	b.PrepareForReading()
	return b
}

// TestDiscardBytesCountsSkippedCalls: the discard steps over the skipped calls with their sizes, reports
// them as virtual, and stops in the call behind them where the n bytes end
func TestDiscardBytesCountsSkippedCalls(t *testing.T) {
	b := skipTestBuffer(true,
		&testEvent{dataID: 1, data: []byte("headAAAA")},
		&skippedEvent{testEvent: testEvent{dataID: 2}, size: 1000},
		&skippedEvent{testEvent: testEvent{dataID: 3}, size: 500},
		&testEvent{dataID: 4, data: []byte("BBnext")})
	head := make([]byte, 4)
	if err := b.ReadUntilBufferFull(head); err != nil || string(head) != "head" {
		t.Fatalf("read the head: %q %v", head, err)
	}
	consumed, virtual, err := discard(b, 4+1000+500+2)
	if err != nil || consumed != 1506 || virtual != 1500 {
		t.Fatalf("discard: consumed %d virtual %d err %v", consumed, virtual, err)
	}
	rest := make([]byte, 4)
	if err := b.ReadUntilBufferFull(rest); err != nil || string(rest) != "next" {
		t.Fatalf("the bytes behind the payload: %q %v", rest, err)
	}
}

// TestDiscardBytesEndingWithASkippedCall: the payload ends with the skipped call, the reader stands on
// it, and removing the read elements removes it too
func TestDiscardBytesEndingWithASkippedCall(t *testing.T) {
	b := skipTestBuffer(true,
		&testEvent{dataID: 1, data: []byte("head")},
		&skippedEvent{testEvent: testEvent{dataID: 2}, size: 100},
		&testEvent{dataID: 3, data: []byte("next")})
	if consumed, virtual, err := discard(b, 104); err != nil || consumed != 104 || virtual != 100 {
		t.Fatalf("discard: %d %d %v", consumed, virtual, err)
	}
	if b.Position().DataID() != 2 {
		t.Fatalf("the reader must stand on the skipped call, it is on %d", b.Position().DataID())
	}
	if b.RemoveReadElements(false) {
		t.Fatalf("the call behind is still there")
	}
	if !b.PrepareForReading() || b.Position().DataID() != 3 || b.DataLength() != 1 {
		t.Fatalf("the skipped call must be removed with the read elements")
	}
}

// TestDiscardBytesWaitsAndRefuses: the discard waits for a call that has not arrived yet, refuses to end
// inside a skipped call, and a plain read never enters one or starts on one
func TestDiscardBytesWaitsAndRefuses(t *testing.T) {
	b := skipTestBuffer(true, &testEvent{dataID: 1, data: []byte("ab")},
		&skippedEvent{testEvent: testEvent{dataID: 2}, size: 10})
	if consumed, virtual, err := discard(b, 20); !errors.Is(err, io.EOF) || consumed != 12 || virtual != 10 {
		t.Fatalf("a payload that goes on behind the buffer must wait: %d %d %v", consumed, virtual, err)
	}
	b.PrepareForReading()
	if consumed, _, err := discard(b, 5); !errors.Is(err, ErrPayloadSkipped) || consumed != 2 {
		t.Fatalf("a payload that ends inside a skipped call is out of sync: %d %v", consumed, err)
	}
	b.PrepareForReading()
	p := make([]byte, 4)
	if n, err := b.Read(p); n != 2 || err != nil {
		t.Fatalf("read the first call: %d %v", n, err)
	}
	if _, err := b.Read(p); !errors.Is(err, ErrPayloadSkipped) {
		t.Fatalf("a read must not enter a skipped call: %v", err)
	}
	if _, err := b.Peek(p); !errors.Is(err, ErrPayloadSkipped) {
		t.Fatalf("a peek must not read across a skipped call: %v", err)
	}
	b.RemoveCurrentElement()
	b.PrepareForReading()
	if _, err := b.Read(p); !errors.Is(err, ErrPayloadSkipped) {
		t.Fatalf("a read must not start on a skipped call: %v", err)
	}
}

// TestDiscardBytesPastATruncatedCall: a payload that runs on behind a truncated call counts the bytes the
// call did not upload and continues in the next call; one that ends among them stops there
func TestDiscardBytesPastATruncatedCall(t *testing.T) {
	events := func() []SocketDataBuffer {
		return []SocketDataBuffer{
			&testEvent{dataID: 1, data: []byte("0123456789"), notFinished: true},
			&truncatedEvent{testEvent: testEvent{dataID: 1, seq: 1, data: []byte("abcdefghij")}, total: 50},
			&skippedEvent{testEvent: testEvent{dataID: 2}, size: 40},
			&testEvent{dataID: 3, data: []byte("tailNEXT")},
		}
	}
	// without followTruncation (skip_h2c_data_payload off) the discard stops at the truncation as before
	b := skipTestBuffer(true, events()...)
	if consumed, virtual, err := discard(b, 20+30+40+4); !errors.Is(err, ErrTruncated) || consumed != 20 || virtual != 0 {
		t.Fatalf("without following, a truncated call stops the discard: %d %d %v", consumed, virtual, err)
	}

	b = skipTestBuffer(true, events()...)
	b.SetFollowTruncation(true)
	consumed, virtual, err := discard(b, 20+30+40+4)
	if err != nil || consumed != 94 || virtual != 70 {
		t.Fatalf("discard past the truncation: %d %d %v", consumed, virtual, err)
	}
	next := make([]byte, 4)
	if err := b.ReadUntilBufferFull(next); err != nil || string(next) != "NEXT" {
		t.Fatalf("the bytes behind: %q %v", next, err)
	}

	b = skipTestBuffer(true, events()...)
	b.SetFollowTruncation(true)
	if consumed, virtual, err = discard(b, 20+29); !errors.Is(err, ErrTruncated) || consumed != 20 || virtual != 0 {
		t.Fatalf("a payload that ends in the bytes the call did not upload: %d %d %v", consumed, virtual, err)
	}
	// a payload that ends exactly with the call is complete, also before the next call arrived
	b = skipTestBuffer(true, events()[:2]...)
	b.SetFollowTruncation(true)
	if consumed, virtual, err = discard(b, 20+30); err != nil || consumed != 50 || virtual != 30 {
		t.Fatalf("a payload that ends exactly with the truncated call: %d %d %v", consumed, virtual, err)
	}
	if b.RemoveReadElements(false); b.DataLength() != 0 {
		t.Fatalf("the truncated call is read to its end and must be removed")
	}
	// a plain buffer (not a per direction view) does not stop at the truncation
	b = skipTestBuffer(false, &testEvent{dataID: 1, data: []byte("ab")},
		&truncatedEvent{testEvent: testEvent{dataID: 2, data: []byte("cd")}, total: 9}, &testEvent{dataID: 3, data: []byte("ef")})
	if consumed, virtual, err = discard(b, 6); err != nil || consumed != 6 || virtual != 0 {
		t.Fatalf("plain buffer: %d %d %v", consumed, virtual, err)
	}
}

// TestSkippedCallInSlices: a slice over skipped calls keeps them as zero length elements, its data size
// is the uploaded bytes plus the virtual ones, and a combination of such slices keeps both
func TestSkippedCallInSlices(t *testing.T) {
	b := skipTestBuffer(true,
		&testEvent{dataID: 1, data: []byte("hdr:body")},
		&skippedEvent{testEvent: testEvent{dataID: 2}, size: 100},
		&testEvent{dataID: 3, data: []byte("tail|x")})
	head := make([]byte, 4)
	_ = b.ReadUntilBufferFull(head)
	start := b.Position()
	_, virtual, err := discard(b, 4+100+4)
	if err != nil {
		t.Fatal(err)
	}
	slice := b.Slice(true, start, b.Position())
	slice.AddVirtualBytes(virtual)
	if got := slice.DataSize(); got != 108 {
		t.Fatalf("the slice is %d bytes, expected 108", got)
	}
	if n := len(slice.TotalBuffer()); n != 3 {
		t.Fatalf("the slice must keep the 3 calls, it has %d", n)
	}
	if !IsPayloadSkipped(slice.TotalBuffer()[1]) || IsPayloadSkipped(slice.TotalBuffer()[2]) {
		t.Fatalf("the skipped call is not recognized in the slice")
	}
	combined := CombineSlices(true, b, slice, slice)
	if got := combined.DataSize(); got != 216 {
		t.Fatalf("the combination is %d bytes, expected 216", got)
	}
	// a slice that ends on the skipped call wraps it, and the wrapper still tells it
	end := &Position{element: start.element.Next(), bufIndex: 0}
	if last := b.Slice(true, start, end).LastSocketBuffer(); !IsPayloadSkipped(last) || last.BufferLen() != 0 {
		t.Fatalf("the wrapped skipped call: %v %d", IsPayloadSkipped(last), last.BufferLen())
	}
}

// TestOutOfOrderInsertBehindTheHeadKeepsThePosition: an event inserted out of order behind the reading
// head must not reset the reading to the front, which would drop the offset RemoveReadElements kept in a
// partially read event (HTTP/1 would read the headers again as body bytes); one inserted before the head
// must
func TestOutOfOrderInsertBehindTheHeadKeepsThePosition(t *testing.T) {
	b := NewBuffer()
	b.AppendDataEvent(&testEvent{dataID: 10, data: []byte("HEADERbody")})
	b.AppendDataEvent(&testEvent{dataID: 21, data: []byte("later")})
	if !b.PrepareForReading() {
		t.Fatal("expected data")
	}
	headers := make([]byte, 6)
	if err := b.ReadUntilBufferFull(headers); err != nil || string(headers) != "HEADER" {
		t.Fatalf("read the headers: %q %v", headers, err)
	}
	b.RemoveReadElements(false)
	// 20 is delivered after 21 by another CPU: it goes between 10 and 21, behind the head
	b.AppendDataEvent(&testEvent{dataID: 20, data: []byte("middle")})
	if !b.PrepareForReading() {
		t.Fatal("expected data")
	}
	if pos := b.Position(); pos.DataID() != 10 || pos.Offset() != 6 {
		t.Fatalf("the reading position moved to data id %d offset %d", pos.DataID(), pos.Offset())
	}
	rest := make([]byte, 4)
	if err := b.ReadUntilBufferFull(rest); err != nil || string(rest) != "body" {
		t.Fatalf("read on: %q %v", rest, err)
	}
	// an event before the head becomes the first one: the reading starts over from it
	b.AppendDataEvent(&testEvent{dataID: 5, data: []byte("early")})
	if !b.PrepareForReading() {
		t.Fatal("expected data")
	}
	if pos := b.Position(); pos.DataID() != 5 || pos.Offset() != 0 {
		t.Fatalf("an insert before the head must restart the reading, it is at %d offset %d", pos.DataID(), pos.Offset())
	}
}

func discard(b *Buffer, n int) (consumed int, virtual int64, err error) {
	result, err := b.DiscardBytes(n)
	return result.Consumed, result.Virtual, err
}

// TestDiscardBytesReportsTheUnreadBytes: a discard that stops at a truncated call reports the bytes the
// call did not upload, with and without following, so the caller does not walk the buffer again
func TestDiscardBytesReportsTheUnreadBytes(t *testing.T) {
	for _, follow := range []bool{false, true} {
		b := skipTestBuffer(true, &testEvent{dataID: 1, data: []byte("0123456789"), notFinished: true},
			&truncatedEvent{testEvent: testEvent{dataID: 1, seq: 1, data: []byte("abcdefghij")}, total: 50})
		b.SetFollowTruncation(follow)
		result, err := b.DiscardBytes(40)
		if (!errors.Is(err, ErrTruncated) && !errors.Is(err, io.EOF)) || result.Consumed != 20 || result.Unread != 30 {
			t.Fatalf("follow=%t: %+v %v", follow, result, err)
		}
	}
}
