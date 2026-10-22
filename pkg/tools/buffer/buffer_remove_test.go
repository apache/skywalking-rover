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
	"io"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

type testEvent struct {
	dataID      uint64
	seq         int
	start       uint64
	data        []byte
	notFinished bool // the socket call continues in a following chunk
}

func (e *testEvent) Protocol() enums.ConnectionProtocol   { return enums.ConnectionProtocolHTTP2 }
func (e *testEvent) GenerateConnectionID() string         { return "1_1" }
func (e *testEvent) BufferData() []byte                   { return e.data }
func (e *testEvent) TotalSize() uint64                    { return uint64(len(e.data)) }
func (e *testEvent) Direction() enums.SocketDataDirection { return enums.SocketDataDirectionIngress }
func (e *testEvent) BufferStartPosition() int             { return 0 }
func (e *testEvent) BufferLen() int                       { return len(e.data) }
func (e *testEvent) DataID() uint64                       { return e.dataID }
func (e *testEvent) PrevDataID() uint64                   { return e.dataID - 1 }
func (e *testEvent) DataSequence() int                    { return e.seq }
func (e *testEvent) IsStart() bool                        { return e.seq == 0 }
func (e *testEvent) IsFinished() bool                     { return !e.notFinished }
func (e *testEvent) HaveReduceDataAfterChunk() bool       { return false }
func (e *testEvent) StartTime() uint64                    { return e.start }
func (e *testEvent) EndTime() uint64                      { return 2 }
func (e *testEvent) ReleaseBuffer() *[20480]byte          { return nil }

// TestRemoveCurrentElementThenAppend: after the last element is removed, appending a new event must
// not dereference the (now empty) current position, and reading must continue with the new event.
func TestRemoveCurrentElementThenAppend(t *testing.T) {
	b := NewBuffer()
	b.AppendDataEvent(&testEvent{dataID: 1, data: []byte("garbage")})
	if !b.PrepareForReading() {
		t.Fatal("expected data")
	}
	if !b.RemoveCurrentElement() {
		t.Fatal("removing the only element must report the end")
	}
	b.AppendDataEvent(&testEvent{dataID: 2, data: []byte("abc")}) // panicked before the fix
	if !b.PrepareForReading() {
		t.Fatal("expected the new event")
	}
	out := make([]byte, 3)
	if err := b.ReadUntilBufferFull(out); err != nil || string(out) != "abc" {
		t.Fatalf("unexpected read: %q %v", out, err)
	}
	if _, err := b.Read(out); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// TestReadUntilBufferFullSpansElements: the payload must be filled sequentially across elements
func TestReadUntilBufferFullSpansElements(t *testing.T) {
	b := NewBuffer()
	b.AppendDataEvent(&testEvent{dataID: 1, data: []byte("hello ")})
	b.AppendDataEvent(&testEvent{dataID: 2, data: []byte("world")})
	b.PrepareForReading()
	out := make([]byte, 11)
	if err := b.ReadUntilBufferFull(out); err != nil || string(out) != "hello world" {
		t.Fatalf("unexpected read: %q %v", out, err)
	}
}

// TestAppendDataEventOrdering: events arriving out of order end up sorted by data id, sequence and time
func TestAppendDataEventOrdering(t *testing.T) {
	type ev struct {
		id  uint64
		seq int
		t   uint64
	}
	mk := func(e ev) *testEvent { return &testEvent{dataID: e.id, seq: e.seq, start: e.t, data: []byte("x")} }
	b := NewBuffer()
	for _, e := range []ev{{3, 0, 30}, {1, 0, 10}, {2, 1, 21}, {2, 0, 20}, {5, 0, 52}, {5, 0, 51}, {4, 0, 40}} {
		b.AppendDataEvent(mk(e))
	}
	var got []ev
	for _, e := range b.TotalBuffer() {
		got = append(got, ev{e.DataID(), e.DataSequence(), e.StartTime()})
	}
	want := []ev{{1, 0, 10}, {2, 0, 20}, {2, 1, 21}, {3, 0, 30}, {4, 0, 40}, {5, 0, 51}, {5, 0, 52}}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("unexpected order: got %v want %v", got, want)
		}
	}
}

// TestExpiredHeadElementRestartsReading: the expiry removes the element the reading head still
// points at; the head must then restart from the first element that is still in the list instead of
// walking a detached one (whose Next() is nil, so the reader reported the end of the data)
func TestExpiredHeadElementRestartsReading(t *testing.T) {
	b := NewBuffer()
	now := uint64(time.Since(host.BootTime))
	old := now - uint64(2*time.Minute)
	b.AppendDataEvent(&testEvent{dataID: 1, start: old, data: []byte("old-")})
	b.AppendDataEvent(&testEvent{dataID: 2, start: now, data: []byte("new!")})
	if !b.PrepareForReading() {
		t.Fatal("expected data")
	}
	if b.Position().DataID() != 1 {
		t.Fatalf("the head must start at the first event, got %d", b.Position().DataID())
	}

	if removed := b.DeleteExpireEvents(time.Minute); removed != 1 {
		t.Fatalf("the expired event must be removed, removed: %d", removed)
	}
	if !b.PrepareForReading() {
		t.Fatal("the buffer still holds the second event")
	}
	if id := b.Position().DataID(); id != 2 {
		t.Fatalf("reading must restart at the event that is still in the list, got %d", id)
	}
	data := make([]byte, 4)
	if err := b.ReadUntilBufferFull(data); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "new!" {
		t.Fatalf("unexpected data: %q", data)
	}
}

// TestUploadedBytesAccounting: the buffer counts the bytes BPF uploaded per socket call, so the
// bytes a truncated call did not upload are exact even when the reader starts in a later chunk
func TestUploadedBytesAccounting(t *testing.T) {
	b := NewBuffer()
	b.AppendDataEvent(&testEvent{dataID: 10, seq: 0, data: make([]byte, 20), notFinished: true})
	b.AppendDataEvent(&testEvent{dataID: 10, seq: 1, data: make([]byte, 20)})
	if got := b.UploadedBytes(10); got != 40 {
		t.Fatalf("expected 40 uploaded bytes of the socket call, got %d", got)
	}
	if got := b.UploadedBytes(11); got != 0 {
		t.Fatalf("an unknown socket call has no accounting, got %d", got)
	}
	if !b.PrepareForReading() {
		t.Fatal("expected data")
	}
	if b.RemoveCurrentElement() {
		t.Fatal("the second chunk is still there")
	}
	if got := b.UploadedBytes(10); got != 40 {
		t.Fatalf("removing a chunk must not lose the accounting of the call, got %d", got)
	}
}
