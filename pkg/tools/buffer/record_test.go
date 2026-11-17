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
	"bytes"
	"runtime"
	"runtime/metrics"
	"sync"
	"testing"
	"unsafe"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// newRecords allocates n records of one connection from data id first on: every third one cut behind 9 bytes
func newRecords(first uint64, n int) []*CompactRecord {
	records := make([]*CompactRecord, 0, n)
	for i := 0; i < n; i++ {
		r := NewCompactRecord()
		fillRecord(r, first+uint64(i))
		records = append(records, r)
	}
	return records
}

func fillRecord(r *CompactRecord, id uint64) {
	*r = CompactRecord{DataID0: id, PrevDataID0: id - 1, StartTime0: id * 10, TotalSize0: 1000,
		Direction0: enums.SocketDataDirectionIngress}
	if id%3 == 1 {
		r.CutLen = 9
		r.SetCut()
		copy(r.CutData[:], bytes.Repeat([]byte{byte(id)}, 9))
	}
}

// TestCompactRecordSize: a record is one allocation of the size class CompactRecordSize names
func TestCompactRecordSize(t *testing.T) {
	if size := unsafe.Sizeof(CompactRecord{}); size != CompactRecordSize {
		t.Fatalf("a record takes %d bytes, CompactRecordSize says %d", size, CompactRecordSize)
	}
}

// TestCompactRecordHeldAsItself: a record appended to a buffer is held as it is, a view takes it over as it
// is, and a record read through a position after its removal is still the record, its cut bytes given back
func TestCompactRecordHeldAsItself(t *testing.T) {
	for _, slab := range []int{1, 32} {
		SetEventListSlab(slab)
		buf := NewBuffer()
		records := newRecords(1, 10)
		for i, r := range records {
			if got := buf.AppendDataEvent(r); got != SocketDataBuffer(r) {
				t.Fatalf("slab %d: record %d is held as %p, appended %p", slab, i, got, r)
			}
		}
		taken := buf.TakeDataEvents()
		if len(taken) != len(records) {
			t.Fatalf("slab %d: %d events taken, %d appended", slab, len(taken), len(records))
		}
		view := NewViewBuffer(buf)
		for i, e := range taken {
			if e != SocketDataBuffer(records[i]) || view.AppendDataEvent(e) != e {
				t.Fatalf("slab %d: event %d is not the appended record", slab, i)
			}
		}
		if !view.PrepareForReading() {
			t.Fatal("nothing to read")
		}
		position := view.Position()
		head := view.HeadDataEvent().(*CompactRecord)
		if head != records[0] || len(head.BufferData()) != 9 {
			t.Fatalf("slab %d: the head record %+v", slab, head)
		}
		view.RemoveCurrentElement()
		if head.BufferData() != nil || head.BufferLen() != 9 || position.DataID() != 1 {
			t.Fatalf("slab %d: a released record still has its bytes or lost its fields", slab)
		}
		view.ReleaseAll()
	}
	SetEventListSlab(1)
}

// TestCompactRecordAccounting: the admissions of the records and their charges are given back exactly once,
// whether they are released from a buffer or dropped before, and a record in use costs its own size and the
// bookkeeping of an event in InflightBytes, not the event overhead
func TestCompactRecordAccounting(t *testing.T) {
	inUse0, bytes0, records0, inflight0 := eventsInUse.Load(), bytesInUse.Load(), recordsInUse.Load(), inflightBytes()
	check := func(when string, events int64) {
		t.Helper()
		if got := eventsInUse.Load() - inUse0; got != events {
			t.Fatalf("%s: %d events in use, %d expected", when, got, events)
		}
		if got := recordsInUse.Load() - records0; got != events {
			t.Fatalf("%s: %d records in use, %d expected", when, got, events)
		}
		if got := bytesInUse.Load() - bytes0; got != events*CompactRecordSize {
			t.Fatalf("%s: %d bytes in use, %d expected", when, got, events*CompactRecordSize)
		}
		if got := inflightBytes() - inflight0; got != events*(CompactRecordSize+eventBookkeepingBytes) {
			t.Fatalf("%s: %d bytes in flight, %d expected", when, got, events*(CompactRecordSize+eventBookkeepingBytes))
		}
	}
	buf := NewBuffer()
	var dropped []*CompactRecord
	for i, r := range newRecords(1, 8) {
		if !AcquireEvent() {
			t.Fatal("refused")
		}
		ChargeRecord(r)
		ChargeRecord(r) // charged once
		if i%4 == 3 {
			ReleaseEvent(r.ReleaseBuffer())
			dropped = append(dropped, r)
			continue
		}
		buf.AppendDataEvent(r)
	}
	check("appended", 6)
	// a copy of the metadata is not charged: releasing it gives nothing back
	if c := buf.dataEvents.Front().Value.(*CompactRecord).CopyMetadata(); c.ReleaseBuffer() != nil {
		t.Fatal("a record copy returned a buffer")
	}
	// a record released again (a stale reference) gives no charge back a second time
	for _, r := range dropped {
		r.ReleaseBuffer()
	}
	check("copies and second releases", 6)
	buf.ReleaseAll()
	check("released", 0)
}

// TestCompactRecordAccountingMatchesHeap keeps a backlog of records in the buffers of a connection under a
// sustained stream (appended in batches, taken over by the view of the analysis, the oldest released) and
// compares what the memory protection accounts for them with what they take on the heap: the budget must see
// the records, within the slack of the per event bookkeeping, at every size of the backlog
func TestCompactRecordAccountingMatchesHeap(t *testing.T) {
	SetEventListSlab(32)
	defer SetEventListSlab(1)
	defer SetMemoryBudget(MemoryBudget())
	SetMemoryBudget(0)
	inUse0 := eventsInUse.Load()
	conn := NewBuffer()
	view := NewViewBuffer(conn)
	next := uint64(1)
	stream := func(n, backlog int) {
		for done := 0; done < n; {
			for i := 0; i < 24 && done < n; i++ {
				r := NewCompactRecord()
				fillRecord(r, next)
				next++
				done++
				if !AcquireEvent() {
					t.Fatal("refused")
				}
				ChargeRecord(r)
				conn.AppendDataEvent(r)
			}
			for _, e := range conn.TakeDataEvents() {
				view.AppendDataEvent(e)
			}
			for view.dataEvents.Len() > backlog && view.PrepareForReading() {
				view.RemoveCurrentElement()
			}
		}
	}
	base, inflightBase := liveHeapBytes(), inflightBytes()
	perRecord := int64(CompactRecordSize + eventBookkeepingBytes)
	for _, backlog := range []int{100000, 200000, 300000, 400000} {
		stream(2*backlog, backlog)
		heap, accounted := liveHeapBytes()-base, inflightBytes()-inflightBase
		ratio := float64(accounted) / float64(heap)
		t.Logf("backlog %d records: accounted %d bytes, the live heap grew %d bytes (%.2f), %d records in use",
			backlog, accounted, heap, ratio, recordsInUse.Load())
		if got := int64(view.dataEvents.Len()); got != eventsInUse.Load()-inUse0 {
			t.Fatalf("%d records held, %d in use", got, eventsInUse.Load()-inUse0)
		}
		// a record is its 96 bytes and its share of an element slab (40 bytes), the bookkeeping charges 64
		if ratio < 0.85 || ratio > 1.4 {
			t.Fatalf("backlog %d: accounted %d bytes for a heap of %d (%.2f)", backlog, accounted, heap, ratio)
		}
		if accounted != int64(view.dataEvents.Len())*perRecord {
			t.Fatalf("backlog %d: accounted %d bytes for %d records", backlog, accounted, view.dataEvents.Len())
		}
	}
	// a backlog that shrinks gives its charge back at once (the heap keeps the grown upload map of the view,
	// bookkeeping of the buffer that full events take as well)
	stream(100000, 50000)
	if accounted := inflightBytes() - inflightBase; accounted != int64(view.dataEvents.Len())*perRecord {
		t.Fatalf("shrunk to %d records: accounted %d bytes", view.dataEvents.Len(), accounted)
	}
	view.ReleaseAll()
	conn.ReleaseAll()
	if got := eventsInUse.Load() - inUse0; got != 0 {
		t.Fatalf("%d records still in use", got)
	}
	if accounted := inflightBytes() - inflightBase; accounted != 0 {
		t.Fatalf("%d bytes still accounted", accounted)
	}
}

// TestCompactRecordAppendAllocations: with the slabs of the agent a record costs its own allocation and its
// share of the element slabs, nothing more
func TestCompactRecordAppendAllocations(t *testing.T) {
	SetEventListSlab(32)
	defer SetEventListSlab(1)
	const n = 64
	allocs := testing.AllocsPerRun(50, func() {
		buf := &Buffer{dataEvents: newEventList(), uploadedBytes: map[uint64]int64{}, sparseUpload: true}
		for i := 0; i < n; i++ {
			r := NewCompactRecord()
			r.DataID0 = uint64(i + 1)
			buf.AppendDataEvent(r)
		}
	})
	// the records, the buffer and its list, and the slabs: 4, 8, 16, 32, 32
	t.Logf("%.1f allocations for %d records", allocs, n)
	if allocs > n+12 {
		t.Fatalf("%.1f allocations for %d records", allocs, n)
	}
}

// TestCompactRecordsAcrossGoroutines makes records on one goroutine and appends them on others, as the reader
// and the partitions do (run with -race)
func TestCompactRecordsAcrossGoroutines(t *testing.T) {
	SetEventListSlab(32)
	defer SetEventListSlab(1)
	const partitions, records = 4, 50000
	channels := make([]chan *CompactRecord, partitions)
	buffers := make([]*Buffer, partitions)
	var wg sync.WaitGroup
	for p := range channels {
		channels[p] = make(chan *CompactRecord, 256)
		buffers[p] = NewBuffer()
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			var last uint64
			for r := range channels[p] {
				s := buffers[p].AppendDataEvent(r).(*CompactRecord)
				if s.DataID0 <= last || s.CutData[0] != byte(s.DataID0) {
					t.Errorf("partition %d: record %d after %d with %d", p, s.DataID0, last, s.CutData[0])
				}
				last = s.DataID0
				if buffers[p].DataLength() > 512 {
					buffers[p].ReleaseAll()
				}
			}
		}(p)
	}
	for id := uint64(1); id <= records; id++ {
		r := NewCompactRecord()
		*r = CompactRecord{DataID0: id, CutLen: 1}
		r.SetCut()
		r.CutData[0] = byte(id)
		channels[int(id)%partitions] <- r
	}
	for _, c := range channels {
		close(c)
	}
	wg.Wait()
}

// liveHeapBytes is the live heap after two collections, the cleanups of the sampled allocations run
func liveHeapBytes() int64 {
	runtime.GC()
	runtime.GC()
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	return int64(sample[0].Value.Uint64())
}

// retentionStream streams n records through the buffers of a connection the way the HTTP/2 analysis does: the
// connection buffer takes them in batches, the analysis takes them over (TakeDataEvents, which renews the list)
// into the view of their direction, reads and releases them. Meanwhile it keeps what outlives the analysis in
// the agent: the position of every pass for a while (the end position of a slice, a stream kept open), a
// position in the connection buffer that outlives its renewal, and a record every few for a while (a kernel
// log of a dropped event waiting for the flush), in rings that the newest replace.
type retentionStream struct {
	conn, view    *Buffer
	positions     [256]*Position
	connPositions [256]*Position
	kept          [256]SocketDataBuffer
	next          uint64
	passes        int
}

func newRetentionStream() *retentionStream {
	conn := NewBuffer()
	return &retentionStream{conn: conn, view: NewViewBuffer(conn), next: 1}
}

func (s *retentionStream) run(n int) {
	for done := 0; done < n; {
		for i := 0; i < 24 && done < n; i++ {
			r := NewCompactRecord()
			fillRecord(r, s.next)
			s.next++
			done++
			AcquireEvent()
			ChargeRecord(r)
			s.conn.AppendDataEvent(r)
		}
		if s.conn.PrepareForReading() {
			s.connPositions[s.passes%len(s.connPositions)] = s.conn.Position()
		}
		for _, e := range s.conn.TakeDataEvents() {
			s.view.AppendDataEvent(e)
		}
		s.passes++
		for k := 0; s.view.PrepareForReading(); k++ {
			if k == 0 {
				s.positions[s.passes%len(s.positions)] = s.view.Position()
			}
			if k%8 == 3 {
				s.kept[(s.passes*3+k)%len(s.kept)] = s.view.HeadDataEvent()
			}
			if s.view.RemoveCurrentElement() {
				break
			}
		}
	}
}

// TestCompactRecordsAreNotRetained: streaming records through the buffers with the analysis and the list
// renewals keeps a bounded memory, whatever the number of records: the records and the element slabs that
// nothing refers to anymore are collected, and what the agent keeps (positions, kernel logs) keeps only
// itself and its own slab alive, never a chain of slabs or the records of its neighbours
func TestCompactRecordsAreNotRetained(t *testing.T) {
	SetEventListSlab(32)
	defer SetEventListSlab(1)
	defer SetMemoryBudget(MemoryBudget())
	SetMemoryBudget(0)
	inUse0, records0 := eventsInUse.Load(), recordsInUse.Load()
	s := newRetentionStream()
	s.run(50000)
	base := liveHeapBytes()
	const n = 1000000
	s.run(n)
	grown := liveHeapBytes() - base
	t.Logf("%d records in %d passes: the live heap grew %d bytes", n, s.passes, grown)
	// what the rings keep: a slab per position (32 elements and their records) and a record per kept event,
	// far below the 96MB the streamed records take
	const bound = 4 << 20
	if grown > bound {
		t.Fatalf("the live heap grew %d bytes over %d records, the bound is %d", grown, n, bound)
	}
	if got := eventsInUse.Load() - inUse0; got != 0 {
		t.Fatalf("%d records still in use", got)
	}
	if got := recordsInUse.Load() - records0; got != 0 {
		t.Fatalf("%d records still charged", got)
	}
}

// TestCompactRecordRun is the run a record keeps behind its cut bytes (SetSumRun, SummaryRun)
func TestCompactRecordRun(t *testing.T) {
	r := NewCompactRecord()
	r.SetCut()
	r.CutLen = 9
	copy(r.CutData[:], []byte{0, 0x40, 0, 0, 1, 0, 0, 0, 3})
	if stream, frames := r.SummaryRun(); stream != 0 || frames != 0 {
		t.Fatalf("a new record has a run: %d %d", stream, frames)
	}
	if !r.SetSumRun(0x7fffffff, 0xffff) {
		t.Fatalf("no room behind 9 cut bytes")
	}
	if stream, frames := r.SummaryRun(); stream != 0x7fffffff || frames != 0xffff {
		t.Fatalf("run %d %d", stream, frames)
	}
	if !bytes.Equal(r.BufferData(), []byte{0, 0x40, 0, 0, 1, 0, 0, 0, 3}) {
		t.Fatalf("the cut bytes changed: %v", r.BufferData())
	}
	if !r.SetSumRun(0, 0) {
		t.Fatalf("clearing failed")
	}
	if stream, _ := r.SummaryRun(); stream != 0 {
		t.Fatalf("the run was not cleared")
	}
	r.CutLen = recordRunAt + 1
	if r.SetSumRun(1, 1) {
		t.Fatalf("a run behind %d cut bytes", r.CutLen)
	}
}

// TestCompactRecordH2CFrames is what a record keeps of the frames of its call (SetH2CFrames, H2CFramesOf)
func TestCompactRecordH2CFrames(t *testing.T) {
	r := NewCompactRecord()
	if flags, off, ok := H2CFramesOf(r); !ok || flags != 0 || off != 0xffff {
		t.Fatalf("a new record: %d %d %t", flags, off, ok)
	}
	for _, c := range []struct {
		flags        uint8
		off, wantOff uint16
	}{{H2CFramesKnown | H2CFramesNoHeaderBlock, 0, 0}, {H2CFramesKnown, 7, 7}, {H2CFramesKnown, 0xffff, 0xffff},
		{0, 3, 0xffff}, {H2CFramesKnown | H2CFramesStartsInHeaderBlock, 30, 30}} {
		r.SetH2CFrames(c.flags, c.off)
		if flags, off, _ := H2CFramesOf(r); flags != c.flags || off != c.wantOff {
			t.Fatalf("%+v: %d %d", c, flags, off)
		}
	}
	if r.Protocol() != enums.ConnectionProtocolHTTP2 {
		t.Fatalf("protocol %d", r.Protocol())
	}
}
