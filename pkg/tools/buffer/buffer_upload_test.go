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
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// uploadEvent is a socket data event whose chunk fields are all free, for the upload accounting tests
type uploadEvent struct {
	dataID   uint64
	seq      int
	start    uint64
	size     int
	total    uint64
	finished bool
	reduce   bool
}

func (e *uploadEvent) Protocol() enums.ConnectionProtocol   { return enums.ConnectionProtocolHTTP2 }
func (e *uploadEvent) GenerateConnectionID() string         { return "1_1" }
func (e *uploadEvent) BufferData() []byte                   { return make([]byte, e.size) }
func (e *uploadEvent) TotalSize() uint64                    { return e.total }
func (e *uploadEvent) Direction() enums.SocketDataDirection { return enums.SocketDataDirectionIngress }
func (e *uploadEvent) BufferStartPosition() int             { return 0 }
func (e *uploadEvent) BufferLen() int                       { return e.size }
func (e *uploadEvent) DataID() uint64                       { return e.dataID }
func (e *uploadEvent) PrevDataID() uint64                   { return e.dataID - 1 }
func (e *uploadEvent) DataSequence() int                    { return e.seq }
func (e *uploadEvent) IsStart() bool                        { return e.seq == 0 }
func (e *uploadEvent) IsFinished() bool                     { return e.finished }
func (e *uploadEvent) HaveReduceDataAfterChunk() bool       { return e.reduce }
func (e *uploadEvent) StartTime() uint64                    { return e.start }
func (e *uploadEvent) EndTime() uint64                      { return e.start }
func (e *uploadEvent) ReleaseBuffer() []byte                { return nil }

// uploadModel is the accounting every event used to get: a count per data id for each appended event,
// deleted when a finished event of the id is removed or any event of the id expires
type uploadModel map[uint64]int64

func listedEvents(b *Buffer) map[SocketDataBuffer]bool {
	result := make(map[SocketDataBuffer]bool)
	for _, e := range b.TotalBuffer() {
		result[e] = true
	}
	return result
}

// forgetRemoved applies the old rule to the events that left the buffer
func (m uploadModel) forgetRemoved(before, after map[SocketDataBuffer]bool, expired bool) {
	for e := range before {
		if !after[e] && (expired || e.IsFinished()) {
			delete(m, e.DataID())
		}
	}
}

// TestSparseUploadMatchesFullAccounting drives a sparse buffer with random appends (shared data ids,
// chunks, truncated calls, late events) and removals, and checks that UploadedBytes of every id always
// equals the accounting that counts every event.
func TestSparseUploadMatchesFullAccounting(t *testing.T) {
	sparseUploadMatchesFullAccounting(t, false)
}

// TestSparseUploadWithGapsMatchesFullAccounting is TestSparseUploadMatchesFullAccounting with summary gaps (which
// upload nothing) put in front of events, as the HTTP/2 analyzer puts them in its direction views
func TestSparseUploadWithGapsMatchesFullAccounting(t *testing.T) {
	sparseUploadMatchesFullAccounting(t, true)
}

func sparseUploadMatchesFullAccounting(t *testing.T, gaps bool) {
	now := uint64(time.Since(host.BootTime))
	old := uint64(time.Hour)
	for seed := int64(0); seed < 300; seed++ {
		rnd := rand.New(rand.NewSource(seed))
		b := NewBuffer()
		model := uploadModel{}
		const ids = 12
		for step := 0; step < 400; step++ {
			before := listedEvents(b)
			switch op := rnd.Intn(20); {
			case op < 12:
				e := &uploadEvent{dataID: uint64(1 + rnd.Intn(ids)), size: 1 + rnd.Intn(30), start: now + uint64(rnd.Intn(5)),
					finished: rnd.Intn(4) != 0}
				if rnd.Intn(3) == 0 {
					e.seq = rnd.Intn(3)
				}
				if e.finished && rnd.Intn(5) == 0 {
					e.reduce, e.total = true, uint64(e.size+rnd.Intn(100))
				}
				if rnd.Intn(8) == 0 {
					e.start = now - old // expires on the next expiry
				}
				model[e.dataID] += int64(e.size)
				if gaps && rnd.Intn(2) == 0 {
					// the gap goes in first, as the analyzer appends it, or after the event (a late one)
					gap := &SummaryGap{DataID0: e.dataID, PrevDataID0: e.dataID - 1, StartTime0: e.start, Size: uint64(1 + rnd.Intn(5000))}
					if rnd.Intn(4) == 0 {
						b.AppendDataEvent(e)
						b.AppendDataEvent(gap)
					} else {
						b.AppendDataEvent(gap)
						b.AppendDataEvent(e)
					}
					break
				}
				b.AppendDataEvent(e)
			case op < 15:
				if b.PrepareForReading() {
					b.RemoveCurrentElement()
				}
				model.forgetRemoved(before, listedEvents(b), false)
			case op < 17:
				if b.PrepareForReading() {
					for i := rnd.Intn(4); i > 0; i-- {
						if _, err := b.DiscardBytes(1 + rnd.Intn(20)); err != nil {
							break
						}
					}
					b.RemoveReadElements(false)
				}
				model.forgetRemoved(before, listedEvents(b), false)
			case op < 19:
				b.DeleteExpireEvents(time.Minute)
				model.forgetRemoved(before, listedEvents(b), true)
			default:
				if b.TakeDataEvents() != nil {
					clear(model) // an empty buffer keeps its accounting
				}
			}
			for id := uint64(0); id <= ids+1; id++ {
				if got, want := b.UploadedBytes(id), model[id]; got != want {
					t.Fatalf("seed %d step %d: uploaded bytes of %d: %d, the full accounting has %d", seed, step, id, got, want)
				}
			}
		}
	}
}

// TestSparseUploadSkipsSingleChunkCalls: the calls of one chunk are not put into the map, the others
// are, and a second event of a data id counts the first one
func TestSparseUploadSkipsSingleChunkCalls(t *testing.T) {
	b := NewBuffer()
	for id := uint64(1); id <= 100; id++ {
		b.AppendDataEvent(&uploadEvent{dataID: id, size: 9, finished: true})
	}
	if len(b.uploadedBytes) != 0 {
		t.Fatalf("single chunk calls must not be tracked, got %d entries", len(b.uploadedBytes))
	}
	if got := b.UploadedBytes(50); got != 9 {
		t.Fatalf("an untracked call counts its own event, got %d", got)
	}
	// the TLS uprobe reports several events with one data id
	b.AppendDataEvent(&uploadEvent{dataID: 50, size: 20480, total: 30000, finished: true, reduce: true, start: 1})
	if got := b.UploadedBytes(50); got != 9+20480 {
		t.Fatalf("the second event of the id must count the first, got %d", got)
	}
	b.AppendDataEvent(&uploadEvent{dataID: 101, size: 20480, total: 40000})
	if got := b.UploadedBytes(101); got != 20480 || len(b.uploadedBytes) != 2 {
		t.Fatalf("a chunk of a longer call is tracked, got %d (%d entries)", got, len(b.uploadedBytes))
	}
}

// TestSparseUploadGapsStayOutOfTheMap: a summary gap in front of a single chunk call puts nothing into the map, and
// both count what the call uploaded
func TestSparseUploadGapsStayOutOfTheMap(t *testing.T) {
	b := NewViewBuffer(NewBuffer())
	for id := uint64(1); id <= 100; id++ {
		b.AppendDataEvent(&SummaryGap{DataID0: id, PrevDataID0: id - 1, StartTime0: id, Size: 16384})
		b.AppendDataEvent(&uploadEvent{dataID: id, size: 9, finished: true, start: id})
	}
	if len(b.uploadedBytes) != 0 {
		t.Fatalf("gaps and single chunk calls must not be tracked, got %d entries", len(b.uploadedBytes))
	}
	for e := b.dataEvents.Front(); e != nil; e = e.Next() {
		ev := e.Value.(SocketDataBuffer)
		if got := b.uploadedBytesAt(e, ev); got != 9 {
			t.Fatalf("uploaded bytes at the element of %d (%T): %d", ev.DataID(), ev, got)
		}
		if got := b.UploadedBytes(ev.DataID()); got != 9 {
			t.Fatalf("uploaded bytes of %d: %d", ev.DataID(), got)
		}
	}
	// the gap and the call are read and removed as the parser does
	for b.PrepareForReading() {
		if b.RemoveCurrentElement() {
			break
		}
	}
	if len(b.uploadedBytes) != 0 || b.dataEvents.Len() != 0 {
		t.Fatalf("after the removal: %d entries, %d events", len(b.uploadedBytes), b.dataEvents.Len())
	}
}

// TestSparseUploadRace appends and analyzes concurrently, as the partition and the analyzer do
func TestSparseUploadRace(t *testing.T) {
	b := NewViewBuffer(NewBuffer())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for id := uint64(1); id <= 2000; id++ {
			finished := id%7 != 0
			b.AppendDataEvent(&uploadEvent{dataID: id / 2, seq: int(id % 2), size: 10, total: 30, finished: finished, reduce: id%5 == 0})
		}
	}()
	for i := 0; i < 2000; i++ {
		if b.PrepareForReading() {
			_ = b.UploadedBytes(uint64(i / 2))
			_, _ = b.DiscardBytes(15)
			b.RemoveReadElements(false)
		}
	}
	wg.Wait()
}
