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
	"container/list"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var (
	ErrNotComplete = errors.New("socket: not complete event")
	// ErrTruncated: the reader reached the end of a socket call that BPF truncated (the upload chunk
	// limit was hit), so the following bytes of the buffer belong to the next socket call and are not
	// the continuation of the message being read
	ErrTruncated = errors.New("socket: the socket call is truncated by the upload limit")
	// ErrPayloadSkipped: the reader reached a socket call uploaded without its content
	// (PayloadSkippedBuffer). Only DiscardBytes steps over it: a reader that wants the bytes cannot have
	// them, and one that would start there is not where the protocol expects it.
	ErrPayloadSkipped = errors.New("socket: the socket call was uploaded without its content")
	// ErrPayloadReleased: the reader reached a socket call whose bytes were given back to the pool (ReleaseBuffer)
	ErrPayloadReleased = errors.New("socket: the bytes of the socket call were released")
	emptyList          = list.New()

	log = logger.GetLogger("tools", "buffer")

	// bufferClasses are the sizes of the data of socket data events that hold it through a slice,
	// recycled through a free list each (freelist.go). The BPF side sends only the bytes it read, and
	// most socket calls are far smaller than a full chunk, so one list of full sized arrays would spend
	// 20KB on a 200 byte message. The classes are few on purpose: a class that is rarely hit only costs
	// allocations. A buffer always comes back to the class its capacity belongs to.
	// 4096 sits between 2048 and 8192 because that gap is where the common case lives: an HTTP/2 peer
	// splits a body into DATA frames of a few KB, so the receiving side reads a few KB per syscall and
	// a 3KB message would otherwise take an 8KB buffer. buffersTakenByClass says whether that is still
	// true for a given workload.
	bufferClasses = []int{2048, 4096, 8192, MaxEventBufferSize}

	// per class accounting, so whether the classes fit the traffic can be read off the agent instead of a
	// heap profile (the bytes the buffers hold are bytesInUse)
	buffersTakenByClass = make([]atomic.Int64, len(bufferClasses))
)

// MaxEventBufferSize is the largest socket data event, the BPF upload chunk size
const MaxEventBufferSize = 20480

// bufferClassOf returns the index of the smallest class that holds size bytes
func bufferClassOf(size int) int {
	for i, class := range bufferClasses {
		if size <= class {
			return i
		}
	}
	return len(bufferClasses) - 1
}

// Socket data events and the memory they hold.
//
// Every event carries a 20KB data array until the analyzer releases it, so an analysis backlog (slow
// backend, large bodies, truncated messages) grows the process until it is killed. Two things guard
// against that, and both go through this file:
//
//   - admission: while the events in use hold the memory budget (max_memory_percent of the memory
//     limit, see memory.go), new events are refused and counted;
//   - accounting: eventsInUse counts the events that currently hold data and bytesInUse the memory
//     they occupy, so the analysis can be told how much it is still holding. Since the upload is
//     variable length the two are no longer proportional.
//
// An event either embeds its array (AcquireEvent) or points at a pooled one (AcquireEventBuffer);
// ReleaseEvent takes both shapes, driven by what the event's ReleaseBuffer returns.
var (
	eventsInUse atomic.Int64
	// acceptedEvents and acceptedBytes describe what the kernel actually delivers: the two sides of a
	// connection can carry the same bytes in a very different number of socket calls, and the cost of
	// the analysis follows the number of events, not the bytes
	acceptedEvents atomic.Int64
	acceptedBytes  atomic.Int64
	// expiredEvents counts the events released by the expiry rather than by an analyzer: an event
	// that leaves this way belongs to a message that never completed
	expiredEvents atomic.Int64
	// bytesInUse is what the events actually hold, which is no longer the event count times the chunk
	// size now that the upload is variable length
	bytesInUse atomic.Int64
)

// MemoryStats returns the socket data events holding an array, the events dropped by the memory
// protection, the bytes the events in use hold and the budget (0 when the protection is off)
func MemoryStats() (inUse, dropped, inflight, budget int64) {
	return eventsInUse.Load(), droppedByBudget.Load(), InflightBytes(), memoryBudget.Load()
}

// AcquireEvent reports whether a socket data event may be created: not while the events in use hold the
// memory budget (the event is dropped and counted)
func AcquireEvent() bool {
	if budget := memoryBudget.Load(); budget > 0 && InflightBytes() >= budget {
		droppedByBudget.Add(1)
		notePressure()
		return false
	}
	eventsInUse.Add(1)
	acceptedEvents.Add(1)
	return true
}

// AcquireEventBuffer reserves the data of an event that holds it through a slice, for a payload of
// size bytes; nil means the memory protection is active and the event must be dropped. The slice is
// as long as the payload and its capacity is the class it came from, which is what returns it.
func AcquireEventBuffer(size int) []byte {
	if !AcquireEvent() {
		return nil
	}
	return takeBuffer(size)
}

// TakeBuffer is AcquireEventBuffer without the admission check, for an event that has already been
// admitted and only now knows how much data it carries
func TakeBuffer(size int) []byte {
	return takeBuffer(size)
}

func takeBuffer(size int) []byte {
	if size < 0 {
		size = 0
	}
	if size > MaxEventBufferSize {
		size = MaxEventBufferSize
	}
	class := bufferClassOf(size)
	data := freeLists[class].get()
	bytesInUse.Add(int64(cap(data)))
	buffersTakenByClass[class].Add(1)
	return data[:size]
}

// AdmittedEventData is data as the reader hands it to an event: the event admitted (counted in use, whatever the
// budget) and the bytes in a pooled buffer of their size, so ReleaseEvent of the event balances what is counted.
// It is for the events made outside the reader (the tests): a buffer of the heap given back to the pool would
// count bytes out that were never counted in.
func AdmittedEventData(data []byte) []byte {
	eventsInUse.Add(1)
	b := takeBuffer(len(data))
	copy(b, data)
	return b
}

// ReleaseEvent releases one socket data event: `b` is what its ReleaseBuffer returned, so a pooled
// slice goes back to the pool of its class and nil (an event that owns no buffer) only clears the
// accounting
func ReleaseEvent(b []byte) {
	eventsInUse.Add(-1)
	ReleaseBufferOnly(b)
	if pressureOn.Load() {
		checkPressureRelease()
	}
}

// ReleaseBufferOnly returns the data of an event without counting the event itself, for a buffer that
// was taken after the event was admitted
func ReleaseBufferOnly(b []byte) {
	if b == nil {
		return
	}
	capacity := cap(b)
	bytesInUse.Add(-int64(capacity))
	for i, class := range bufferClasses {
		if capacity == class {
			freeLists[i].put(b[:capacity])
			return
		}
	}
}

type SocketDataBuffer interface {
	// Protocol of the buffer
	Protocol() enums.ConnectionProtocol
	// GenerateConnectionID for identity the buffer belong which connection
	GenerateConnectionID() string
	// BufferData of the buffer
	BufferData() []byte
	// TotalSize of socket data, the data may exceed the size of the BufferData()
	TotalSize() uint64
	// Direction of the data, send or receive
	Direction() enums.SocketDataDirection
	// BufferStartPosition the buffer start index
	BufferStartPosition() int
	// BufferLen the buffer data length
	BufferLen() int
	// DataID data id of the buffer
	DataID() uint64
	// PrevDataID the previous data id of the buffer
	PrevDataID() uint64
	// DataSequence the data sequence under same data id
	DataSequence() int
	// IsStart this buffer is start of the same data id
	IsStart() bool
	// IsFinished this buffer is finish of the same data id
	IsFinished() bool
	// HaveReduceDataAfterChunk check have reduced data after current buffer
	HaveReduceDataAfterChunk() bool

	// StartTime the data start timestamp
	StartTime() uint64
	// EndTime the data end timestamp
	EndTime() uint64

	ReleaseBuffer() []byte
}

// PayloadSkippedBuffer is implemented by the socket data events that can stand for a socket call
// uploaded without its content: the event carries no data, only the size of the call as TotalSize. The
// reader never reads such an event, DiscardBytes counts it as TotalSize bytes. Which calls BPF uploads so
// is up to the protocol (h2c DATA payloads, see bpf/accesslog/syscalls/h2c.h and the HTTP/2 parser).
type PayloadSkippedBuffer interface {
	PayloadSkipped() bool
}

// IsPayloadSkipped tells whether the event stands for a socket call BPF uploaded without its bytes, see
// PayloadSkippedBuffer
func IsPayloadSkipped(b SocketDataBuffer) bool {
	if limited, ok := b.(*SocketDataEventLimited); ok {
		b = limited.SocketDataBuffer
	}
	skipped, ok := b.(PayloadSkippedBuffer)
	return ok && skipped.PayloadSkipped()
}

// BodyPayloadSkippedBuffer is implemented by the socket data events that can stand for a socket call
// the reader decoded without its bytes because it lies inside an HTTP/1 body (skip_http1_body_payload).
// Unlike the calls BPF skips, such an event keeps its length (BufferLen), only the bytes are missing, so
// every position in the message is what it is with the bytes. It is a PayloadSkippedBuffer as well.
type BodyPayloadSkippedBuffer interface {
	BodyPayloadSkipped() bool
}

// IsBodyPayloadSkipped tells whether the event is a BodyPayloadSkippedBuffer without its bytes
func IsBodyPayloadSkipped(b SocketDataBuffer) bool {
	if limited, ok := b.(*SocketDataEventLimited); ok {
		b = limited.SocketDataBuffer
	}
	skipped, ok := b.(BodyPayloadSkippedBuffer)
	return ok && skipped.BodyPayloadSkipped()
}

// bodySkipConflicts counts the reads that wanted the bytes of an HTTP/1 body call decoded without them,
// see BodyPayloadSkippedBuffer. The decoder only skips calls the analyzer never reads, so it stays 0.
var bodySkipConflicts atomic.Int64

// BodySkipConflicts is the count of the reads that wanted the bytes of an HTTP/1 body call decoded
// without them
func BodySkipConflicts() int64 {
	return bodySkipConflicts.Load()
}

type SocketDataDetail interface {
	// DataID data id of the buffer
	DataID() uint64
	// Time (BPF) of the detail event
	Time() uint64
}

type DataIDRange struct {
	From                   uint64
	To                     uint64
	IsToBufferReadFinished bool
}

func (i *DataIDRange) String() string {
	return fmt.Sprintf("from: %d, to: %d, isToBufferReadFinished: %t", i.From, i.To, i.IsToBufferReadFinished)
}

type Buffer struct {
	dataEvents   *eventList
	detailEvents *list.List
	validated    bool // the events list is validated or not

	// shouldResetPosition is set when an event was inserted out of order, possibly before the reading
	// position: PrepareForReading then starts over from the first event, unless the head is still the
	// first one, see PrepareForReading
	shouldResetPosition atomic.Bool
	// resetKey is the smallest key of the events inserted out of order since the last PrepareForReading (under the
	// event lock, resetKeySet tells it is set): the reading position stays when every one of them went behind it
	resetKey    eventKey
	resetKeySet bool

	eventLocker sync.RWMutex
	// singleOwner: only one goroutine ever touches the buffer (SetSingleOwner), so the event lock is not taken
	singleOwner bool
	// finger is the element the last out of order event went behind (or in front of): the next one of the
	// same batch most often goes right behind it, so the search for its place starts there, see AppendDataEvent
	finger *eventElement
	// marks index the data event list for the search of the place of an out of order event that the walk from
	// the finger does not find nearby (seek): elements of the list in list order, about markStride apart, planted
	// by the walks of the searches themselves. A mark whose element left the list is dropped when it is met.
	marks []*eventElement
	// markScratch is reused by seek for the marks a backward walk plants
	markScratch []*eventElement

	head    *Position
	current *Position

	// record the latest expired data id in connection for expire the older socket detail
	// because the older socket detail may not be received in buffer
	latestExpiredDataID uint64

	// virtualBytes are bytes of the message that the kernel transferred but BPF did not upload (a socket
	// call larger than the upload chunk limit is truncated), accounted by the protocol reader so the
	// reported size is the real one
	virtualBytes int64
	// sizeOverride, when positive, is the size reported by DataSize (a body whose kept events include
	// framing bytes, e.g. chunked transfer encoding)
	sizeOverride int64

	// originalBuffer record this buffer is from Buffer.Slice or CombineSlices
	// if it's not empty, then when getting the details should query from originalBuffer
	// Because the BPF Queue is unsorted and can be delayed, so the details should query by real buffer
	originalBuffer *Buffer
	// endPosition record the end position of the originalBuffer
	endPosition *Position

	// uploadedBytes counts the bytes BPF uploaded per socket call (data id) as the events are appended,
	// so the bytes a truncated socket call did not upload can be computed exactly even when the reader
	// starts in the middle of the call (TotalSize - uploadedBytes[dataID])
	uploadedBytes map[uint64]int64
	// sparseUpload leaves a single chunk socket call out of uploadedBytes while it is the only event of
	// its data id in the list (most calls), see accountUpload; UploadedBytes then counts that event itself
	sparseUpload bool
	// noUploadAccounting: nothing ever asks the buffer for the bytes uploaded (SetUploadAccounting), so
	// AppendDataEvent does not count them
	noUploadAccounting bool

	// sequenceCheck, when set: the reader continues a message into a following
	// socket call that does not directly follow the current one only when it tells the call's data id ready
	// (every call uploaded before it has been delivered)
	sequenceCheck func(dataID uint64) bool
	// sequenceWaited tells how long the event of a data id sequenceCheck refused has been waiting, and
	// sequenceRefused is the data id it refused last (0: the last read was not refused by it)
	sequenceWaited  func(dataID uint64) time.Duration
	sequenceRefused uint64
	// waitNow and waitThrough, when set, tell the reader's clock and how far on that clock every event read from
	// the rings has reached the buffers (the HTTP/2 parser's delivery clock): when the rest of the current socket
	// call is missing (incomplete*), it is waited for while events read before the reader first missed it may
	// still be on their way (IncompleteInDelivery)
	waitNow, waitThrough func() int64
	incompleteID         uint64
	incompleteSeq        int
	incompleteSince      int64
	incompleteNow        bool
	// stopAtTruncation makes the reader return ErrTruncated instead of silently continuing into the
	// next socket call when the current one was truncated by the BPF upload limit
	stopAtTruncation bool
	// followTruncation lets DiscardBytes count the bytes a truncated socket call did not upload and go on
	// in the next call when the bytes it discards run on past them (or end exactly with them), instead of
	// stopping at the truncation. It is only set where skip_h2c_data_payload is on (SetFollowTruncation):
	// off, the discard stops at every truncated call as it always did.
	followTruncation bool

	// combined marks a buffer CombineSlices or AppendSlices built, whose list is its own: AppendSlices may
	// append onto it in place
	combined bool
	// peeking is set while Peek reads: a peek that reaches a call decoded without its bytes is how the
	// message start is told apart, not a conflict (BodySkipConflicts)
	peeking bool
}

type SocketDataEventLimited struct {
	SocketDataBuffer
	From int
	Size int
}

func (s *SocketDataEventLimited) Protocol() enums.ConnectionProtocol {
	return s.SocketDataBuffer.Protocol()
}

func (s *SocketDataEventLimited) BufferData() []byte {
	data := s.SocketDataBuffer.BufferData()
	if data == nil {
		return nil // a metadata-only copy carries no data
	}
	return data[s.From:s.Size]
}

func (s *SocketDataEventLimited) BufferLen() int {
	return s.Size - s.From
}

func (s *SocketDataEventLimited) BufferStartPosition() int {
	return s.From
}

func (i *DataIDRange) Append(other *DataIDRange) *DataIDRange {
	if other.From < i.From {
		i.From = other.From
	}
	if other.To > i.To {
		i.To = other.To
	}
	i.IsToBufferReadFinished = other.IsToBufferReadFinished
	return i
}

func (i *DataIDRange) DeleteDetails(buf *Buffer) {
	if buf.originalBuffer != nil {
		i.DeleteDetails(buf.originalBuffer)
	}
	// the detail list of the root buffer is appended to by the partition goroutine, so the removal
	// must not run concurrently with an insertion (container/list is not concurrency safe)
	buf.lock()
	defer buf.unlock()
	for e := buf.detailEvents.Front(); e != nil; {
		next := e.Next()
		dataID := e.Value.(SocketDataDetail).DataID()
		if dataID >= i.From && dataID <= i.To {
			if !i.IsToBufferReadFinished && dataID == i.To {
				break
			}
			buf.detailEvents.Remove(e)
			if log.Enable(logrus.DebugLevel) {
				log.Debugf("delete detail event from buffer, data id: %d, ref: %p, range: %d-%d(%t)",
					dataID, buf, i.From, i.To, i.IsToBufferReadFinished)
			}
		}
		e = next
	}
}

type Position struct {
	// element of the event list
	element *eventElement
	// bufIndex the buffer index of the element
	bufIndex int
}

func (p *Position) Clone() *Position {
	return &Position{element: p.element, bufIndex: p.bufIndex}
}

// HasElement reports whether the position points at an event (false at the end of the buffer or when
// every event was removed)
func (p *Position) HasElement() bool {
	return p != nil && p.element != nil && p.element.Value != nil
}

func (p *Position) DataID() uint64 {
	return p.element.Value.(SocketDataBuffer).DataID()
}

func (p *Position) PrevDataID() uint64 {
	return p.element.Value.(SocketDataBuffer).PrevDataID()
}

func (p *Position) Seq() int {
	return p.element.Value.(SocketDataBuffer).DataSequence()
}

// Offset is the read offset inside the element's buffer
func (p *Position) Offset() int {
	return p.bufIndex
}

// StartTime of the element the position points to (BPF time)
func (p *Position) StartTime() uint64 {
	return p.element.Value.(SocketDataBuffer).StartTime()
}

// Direction of the element the position points to
func (p *Position) Direction() enums.SocketDataDirection {
	return p.element.Value.(SocketDataBuffer).Direction()
}

func NewBuffer() *Buffer {
	return &Buffer{
		dataEvents:    newEventList(),
		detailEvents:  list.New(),
		validated:     false,
		uploadedBytes: make(map[uint64]int64),
		sparseUpload:  true,
	}
}

// NewViewBuffer creates an empty buffer whose detail events are resolved from the original buffer.
// It is used to re-partition the data events of a connection (e.g. per direction) while the
// socket detail events stay in the original buffer.
func NewViewBuffer(original *Buffer) *Buffer {
	return &Buffer{
		dataEvents:       newEventList(),
		detailEvents:     list.New(),
		validated:        false,
		originalBuffer:   original,
		uploadedBytes:    make(map[uint64]int64),
		sparseUpload:     true,
		stopAtTruncation: true,
	}
}

// SetSingleOwner tells the buffer that one goroutine alone ever touches it (the per direction views of the
// HTTP/2 analyzer, which only the analysis of their connection reads and appends to), so its event lock is not
// taken. The buffers of a connection, which the partition appends to while the analysis takes from them, must
// keep it. It is set once, before the buffer is used.
func (r *Buffer) SetSingleOwner() {
	r.singleOwner = true
}

func (r *Buffer) lock() {
	if !r.singleOwner {
		r.eventLocker.Lock()
	}
}

func (r *Buffer) unlock() {
	if !r.singleOwner {
		r.eventLocker.Unlock()
	}
}

func (r *Buffer) rlock() {
	if !r.singleOwner {
		r.eventLocker.RLock()
	}
}

func (r *Buffer) runlock() {
	if !r.singleOwner {
		r.eventLocker.RUnlock()
	}
}

// SetSequenceCheck sets sequenceCheck and sequenceWaited, see the fields
func (r *Buffer) SetSequenceCheck(check func(dataID uint64) bool, waited func(dataID uint64) time.Duration) {
	r.sequenceCheck, r.sequenceWaited = check, waited
}

// SetWaitClock sets waitNow and waitThrough, see the fields
func (r *Buffer) SetWaitClock(now, through func() int64) {
	r.waitNow, r.waitThrough = now, through
}

// IncompleteInDelivery tells whether the last read stopped because the rest of the current socket call (a chunk
// event) is not in the buffer while events read before the reader first missed it have not all reached the
// buffers yet: the rest may be one of them
func (r *Buffer) IncompleteInDelivery() bool {
	if !r.incompleteNow || r.waitThrough == nil {
		return false
	}
	return r.waitThrough() < r.incompleteSince
}

// noteIncomplete records that the rest of the current socket call is missing, from when it was first missed
func (r *Buffer) noteIncomplete(cur SocketDataBuffer) {
	if r.waitNow == nil {
		return
	}
	r.incompleteNow = true
	if r.incompleteSince != 0 && r.incompleteID == cur.DataID() && r.incompleteSeq == cur.DataSequence() {
		return
	}
	r.incompleteID, r.incompleteSeq, r.incompleteSince = cur.DataID(), cur.DataSequence(), max(r.waitNow(), 1)
}

// SequenceRefusedWait tells whether the last read stopped because sequenceCheck refused the next socket call,
// and how long that call has been waiting
func (r *Buffer) SequenceRefusedWait() (bool, time.Duration) {
	if r.sequenceRefused == 0 || r.sequenceWaited == nil {
		return false, 0
	}
	return true, r.sequenceWaited(r.sequenceRefused)
}

// SetFollowTruncation sets followTruncation, see the field
func (r *Buffer) SetFollowTruncation(follow bool) {
	r.followTruncation = follow
}

// SetUploadAccounting tells whether the buffer counts the bytes uploaded per socket call as the events are
// appended (the default). A buffer nothing reads but TakeDataEvents (the connection buffer of the HTTP/2
// analyzer, whose per direction views count for themselves) does not need it. Set before the buffer is used.
func (r *Buffer) SetUploadAccounting(on bool) {
	r.lock()
	defer r.unlock()
	r.noUploadAccounting = !on
	if !on {
		clear(r.uploadedBytes)
	}
}

// UploadedBytes returns the bytes BPF uploaded for the socket call, 0 when it is not tracked
func (r *Buffer) UploadedBytes(dataID uint64) int64 {
	r.rlock()
	defer r.runlock()
	return r.uploadedBytesLocked(dataID)
}

// uploadedBytesAt is UploadedBytes for the data id of the event at the element, which is (or was) listed in
// the buffer: a call accountUpload left out that is still listed alone counts itself, found without a search
func (r *Buffer) uploadedBytesAt(e *eventElement, ev SocketDataBuffer) int64 {
	id := ev.DataID()
	if counted, ok := r.uploadedBytes[id]; ok || !r.sparseUpload {
		return counted
	}
	if e != nil && e.list == r.dataEvents && e.list != nil && uploadNeighbor(e.Prev(), id, false) == nil &&
		uploadNeighbor(e.Next(), id, true) == nil {
		return int64(ev.BufferLen())
	}
	return r.uploadedBytesLocked(id)
}

func (r *Buffer) uploadedBytesLocked(dataID uint64) int64 {
	if counted, ok := r.uploadedBytes[dataID]; ok || !r.sparseUpload {
		return counted
	}
	// a call accountUpload left out has at most one event in the list, which counts itself. The list is
	// sorted by data id, so the search from the back stops at the older calls.
	var result int64
	for e := r.dataEvents.Back(); e != nil; e = e.Prev() {
		b, ok := e.Value.(SocketDataBuffer)
		if !ok {
			continue
		}
		if b.DataID() < dataID {
			break
		}
		if b.DataID() == dataID {
			result += int64(b.BufferLen())
		}
	}
	return result
}

// accountUpload adds the event, which goes between prev and next (nil at an end), to uploadedBytes.
//
// With sparseUpload, a single chunk call is left out while no other event of its data id is in the
// list, and UploadedBytes counts that event itself. The list is sorted, so the events of one data id are
// adjacent and prev and next tell whether there is another one. The second event of a data id (several
// can share one, e.g. the TLS uprobe) brings the one already listed into the count, and forgetUpload
// keeps an id counted while another of its events stays: so every data id either has the count all
// events would have, or is not in the map and has at most one listed event, a single chunk call.
func (r *Buffer) accountUpload(event SocketDataBuffer, prev, next *eventElement) {
	id, size := event.DataID(), int64(event.BufferLen())
	if !r.sparseUpload {
		r.uploadedBytes[id] += size
		return
	}
	if _, gap := event.(*SummaryGap); gap {
		// a summary gap uploads nothing (BufferLen 0) and goes in front of the event of its data id: it is left
		// out like a single chunk call, and the event behind it does not count it as a second event of its id
		// (sameUploadID), so a gap does not put every summarized call into the map
		return
	}
	prevSame, nextSame := uploadNeighbor(prev, id, false), uploadNeighbor(next, id, true)
	shared := prevSame != nil || nextSame != nil
	// a call cut behind its first bytes (HaveReduceDataAfterChunk) is single too: what it did not upload is
	// asked for at its element (uploadedBytesAt), which counts it without a search
	single := !shared && event.DataSequence() == 0 && event.IsFinished()
	if single && len(r.uploadedBytes) == 0 {
		return
	}
	if counted, ok := r.uploadedBytes[id]; ok {
		r.uploadedBytes[id] = counted + size
		return
	}
	if single {
		return
	}
	r.uploadedBytes[id] = dataIDBytes(prevSame, id) + dataIDBytes(nextSame, id) + size
}

// forgetUpload drops the count of the data id of the event at e, which leaves the list. When another
// event of the id stays, the count restarts from zero (what a dropped one reads) but stays in the map,
// so UploadedBytes does not count the staying event itself.
func (r *Buffer) forgetUpload(e *eventElement, id uint64) {
	if r.noUploadAccounting {
		return
	}
	if r.sparseUpload && (uploadNeighbor(e.Prev(), id, false) != nil || uploadNeighbor(e.Next(), id, true) != nil) {
		r.uploadedBytes[id] = 0
		return
	}
	if len(r.uploadedBytes) > 0 {
		delete(r.uploadedBytes, id)
	}
}

// uploadNeighbor is the event of the data id next to e (e itself or, past the summary gaps of the id, the next
// one in the direction), nil when there is none: the other event of the id the upload accounting looks for. A
// summary gap uploads nothing and is not counted (see accountUpload), so an id not in the map has at most one
// listed event that is not a gap, and UploadedBytes counts what it counted when the gaps were (as 0 bytes).
func uploadNeighbor(e *eventElement, id uint64, forward bool) *eventElement {
	for e != nil && sameDataID(e, id) {
		if _, gap := e.Value.(*SummaryGap); !gap {
			return e
		}
		if forward {
			e = e.Next()
		} else {
			e = e.Prev()
		}
	}
	return nil
}

func sameDataID(e *eventElement, id uint64) bool {
	if e == nil {
		return false
	}
	if e.keyID != 0 {
		return e.keyID == id
	}
	b, ok := e.Value.(SocketDataBuffer)
	return ok && b.DataID() == id
}

func dataIDBytes(e *eventElement, id uint64) int64 {
	if e == nil {
		return 0
	}
	if b, ok := e.Value.(SocketDataBuffer); ok && b.DataID() == id {
		return int64(b.BufferLen())
	}
	return 0
}

// TakeDataEvents detaches and returns all data events from the buffer (in order) without
// releasing their byte arrays, and resets the reading positions. Detail events are kept.
func (r *Buffer) TakeDataEvents() []SocketDataBuffer {
	return r.TakeDataEventsInto(nil)
}

// TakeDataEventsInto is TakeDataEvents appending the events to dst[:0] (nil when there are none), so a caller
// that takes them every round reuses one slice: it must clear it once done, the slice keeps the events alive
func (r *Buffer) TakeDataEventsInto(dst []SocketDataBuffer) []SocketDataBuffer {
	r.lock()
	defer r.unlock()
	if r.dataEvents.Len() == 0 {
		return nil
	}
	result := dst[:0]
	if cap(result) < r.dataEvents.Len() {
		result = make([]SocketDataBuffer, 0, r.dataEvents.Len())
	}
	for e := r.dataEvents.Front(); e != nil; e = e.Next() {
		if e.Value != nil {
			result = append(result, e.Value.(SocketDataBuffer))
		}
	}
	r.dataEvents = r.dataEvents.renew()
	r.finger = nil
	r.dropMarks()
	// cleared rather than made again: the next batch of the connection refills it, and a new map grows
	// again through every size
	clear(r.uploadedBytes)
	r.head = nil
	r.current = nil
	r.shouldResetPosition.Store(false)
	r.resetKeySet = false
	return result
}

// ReleaseAll removes every data event of the buffer and gives their pooled byte arrays back, so a
// buffer that is thrown away (a removed connection) does not leak the in-use accounting
func (r *Buffer) ReleaseAll() {
	if r == nil {
		return
	}
	r.lock()
	defer r.unlock()
	for e := r.dataEvents.Front(); e != nil; {
		next := e.Next()
		if b, ok := e.Value.(SocketDataBuffer); ok && b != nil {
			ReleaseEvent(b.ReleaseBuffer())
		}
		r.dataEvents.Remove(e)
		e = next
	}
	r.finger = nil
	r.dropMarks()
	clear(r.uploadedBytes)
	r.head = nil
	r.current = nil
	r.endPosition = nil
}

func (r *Buffer) FindFirstDataBuffer(dataID uint64) SocketDataBuffer {
	for e := r.dataEvents.Front(); e != nil; e = e.Next() {
		cur := e.Value.(SocketDataBuffer)
		if cur.DataID() == dataID {
			return cur
		}
	}
	return nil
}

func (r *Buffer) BuildTotalDataIDRange() *DataIDRange {
	if r.dataEvents.Len() == 0 {
		return nil
	}
	var toIndex uint64
	var isToBufferReadFinished bool
	if r.endPosition != nil {
		toIndex = r.endPosition.DataID()
		isToBufferReadFinished = r.endPosition.bufIndex == r.endPosition.element.Value.(SocketDataBuffer).BufferLen()
	} else {
		toIndex = r.current.DataID()
		isToBufferReadFinished = r.current.bufIndex == r.current.element.Value.(SocketDataBuffer).BufferLen()
	}
	return &DataIDRange{
		From:                   r.head.DataID(),
		To:                     toIndex,
		IsToBufferReadFinished: isToBufferReadFinished,
	}
}

func (r *Buffer) Position() *Position {
	if r == nil || r.current == nil {
		return nil
	}
	return r.current.Clone()
}

// PositionInto sets p to the reading position, what Position() returns without allocating a copy, for a position
// the caller keeps for a moment only; false (p unchanged) when there is none
func (r *Buffer) PositionInto(p *Position) bool {
	if r == nil || r.current == nil {
		return false
	}
	*p = *r.current
	return true
}

// CurrentPosition tells what Position() would: the data id, the sequence and the start time of the event at the
// reading position and the offset in it, without a copy of the position; ok is false when there is none
func (r *Buffer) CurrentPosition() (dataID uint64, seq int, startTime uint64, offset int, ok bool) {
	if r == nil || r.current == nil {
		return 0, 0, 0, 0, false
	}
	event := r.current.element.Value.(SocketDataBuffer)
	return event.DataID(), event.DataSequence(), event.StartTime(), r.current.bufIndex, true
}

// resetCurrent moves the reading position to the head. The position is updated in place: the head and
// the reading position are never handed out (Position returns a copy), so nothing else refers to them.
func (r *Buffer) resetCurrent() {
	if r.current == nil {
		r.current = r.head.Clone()
		return
	}
	*r.current = *r.head
}

// setHead moves the head to the element and offset, in place like resetCurrent
func (r *Buffer) setHead(element *eventElement, bufIndex int) {
	if r.head == nil {
		r.head = &Position{element: element, bufIndex: bufIndex}
		return
	}
	r.head.element, r.head.bufIndex = element, bufIndex
}

// Clean drops everything the buffer holds. The data events are released rather than only forgotten:
// their buffers come from the pool and the admission control counts them, so dropping the list alone
// would leak one buffer per event until the garbage collector catches up. A slice, a combination or a
// body (detailEvents is emptyList) only borrows the events of the buffer that owns them: its list is
// dropped and the events are left to their owner, releasing them here would release them twice.
func (r *Buffer) Clean() {
	r.lock()
	defer r.unlock()

	if r.detailEvents != emptyList {
		for e := r.dataEvents.Front(); e != nil; e = e.Next() {
			if b, ok := e.Value.(SocketDataBuffer); ok && b != nil {
				ReleaseEvent(b.ReleaseBuffer())
			}
		}
	}
	r.dataEvents = r.dataEvents.renew()
	r.finger = nil
	r.dropMarks()
	r.detailEvents = list.New()
	clear(r.uploadedBytes)
	r.head = nil
	r.current = nil
	r.endPosition = nil
}

// nolint
func (r *Buffer) Slice(validated bool, start, end *Position) *Buffer {
	dataEvents := newEventList()
	if start.element != end.element && r.isDetached(start.element) {
		// the start element has already been removed from the list (expired or released): walking from
		// it would stop at the first nil Next() and silently drop every element in between, so restart
		// from the first element that is still linked
		log.Debugf("the slice start element is already removed from the buffer, ref: %p", r)
		if r.dataEvents.Front() == nil {
			return nil
		}
		start = &Position{element: r.dataEvents.Front(), bufIndex: 0}
	}
	// the elements of the slice in one allocation: the events before the end, and the end itself
	count := 1
	for nextElement := start.element; nextElement != end.element; nextElement = nextElement.Next() {
		if nextElement == nil || nextElement.Value == nil {
			break
		}
		count++
	}
	dataEvents.reserve(count)
	for nextElement := start.element; nextElement != end.element; nextElement = nextElement.Next() {
		if nextElement == nil || nextElement.Value == nil {
			break
		}
		currentBuffer := nextElement.Value.(SocketDataBuffer)
		dataEvents.PushBack(currentBuffer)
	}
	lastBuffer := end.element.Value.(SocketDataBuffer)
	dataEvents.PushBack(&SocketDataEventLimited{SocketDataBuffer: lastBuffer, Size: end.bufIndex})

	// the details always live in the root buffer, so a slice of a view (or of a slice) resolves them there
	original := r
	if r.originalBuffer != nil {
		original = r.originalBuffer
	}
	return &Buffer{
		dataEvents:     dataEvents,
		detailEvents:   emptyList,
		validated:      validated,
		head:           &Position{element: dataEvents.Front(), bufIndex: start.bufIndex},
		current:        &Position{element: dataEvents.Front(), bufIndex: start.bufIndex},
		originalBuffer: original,
		endPosition:    end,
	}
}

func (r *Buffer) Len() int {
	if r == nil || r.head == nil {
		return 0
	}
	var result int
	var startIndex = r.head.bufIndex
	for e := r.head.element; e != nil; e = e.Next() {
		result += e.Value.(SocketDataBuffer).BufferLen() - startIndex
		startIndex = 0
	}
	return result
}

func (r *Buffer) BuildDetails() *list.List {
	// if the original buffer is not empty, then query the details from original buffer
	if r.originalBuffer != nil {
		if !r.head.HasElement() || (r.endPosition == nil && !r.current.HasElement()) {
			// the slice carries no event (every part of it was absent or already released)
			return list.New()
		}
		// the detail list of the root buffer is appended to by the partition goroutine while this
		// iteration runs on the analyzer goroutine
		r.originalBuffer.rlock()
		defer r.originalBuffer.runlock()
		events := list.New()
		fromDataID := r.head.DataID()
		var endDataID uint64
		if r.endPosition != nil {
			endDataID = r.endPosition.DataID()
		} else {
			endDataID = r.current.DataID()
		}

		for e := r.originalBuffer.detailEvents.Front(); e != nil; e = e.Next() {
			if e.Value == nil {
				continue
			}
			if e.Value.(SocketDataDetail).DataID() >= fromDataID && e.Value.(SocketDataDetail).DataID() <= endDataID {
				events.PushBack(e.Value)
			}
		}
		if events.Len() == 0 && log.Enable(logrus.DebugLevel) {
			dataIDList := make([]uint64, 0)
			for e := r.originalBuffer.detailEvents.Front(); e != nil; e = e.Next() {
				if e.Value != nil {
					dataIDList = append(dataIDList, e.Value.(SocketDataDetail).DataID())
				}
			}
			log.Infof("cannot found details from original buffer, from data id: %d, end data id: %d, "+
				"ref: %p, existing details data id list: %v", fromDataID, endDataID, r.originalBuffer, dataIDList)
		}

		return events
	}
	return r.detailEvents
}

// AddVirtualBytes records bytes of the message that were transferred but not uploaded by BPF
func (r *Buffer) AddVirtualBytes(n int64) {
	if r != nil && n > 0 {
		r.virtualBytes += n
	}
}

// ReducedBytesBetween returns the bytes the kernel transferred but BPF did not upload for the socket
// calls between the two positions (inclusive): a socket call larger than the upload chunk limit ends
// with a finished chunk flagged HaveReduceDataAfterChunk, its TotalSize is the real length.
// A nil end means the end of the buffer.
func (r *Buffer) ReducedBytesBetween(start, end *Position) int64 {
	if r == nil || start == nil || start.element == nil {
		return 0
	}
	var result int64
	var uploaded uploadCounter
	for e := start.element; e != nil; e = e.Next() {
		buf, ok := e.Value.(SocketDataBuffer)
		if !ok || buf == nil {
			break
		}
		uploaded.add(buf.DataID(), int64(buf.BufferLen()))
		if end != nil && e == end.element && end.bufIndex < buf.BufferLen() {
			break // the reduced bytes follow the last byte of the element, which is not consumed yet
		}
		if buf.IsFinished() && buf.HaveReduceDataAfterChunk() {
			result += r.missingAfterChunk(buf, &uploaded)
		}
		if end != nil && e == end.element {
			break
		}
	}
	return result
}

// missingAfterChunk is what ReducedBytesBetween counts for buf, a finished chunk flagged HaveReduceDataAfterChunk:
// the bytes of its socket call BPF did not upload, uploaded holding the bytes of the chunks walked so far
func (r *Buffer) missingAfterChunk(buf SocketDataBuffer, uploaded *uploadCounter) int64 {
	// the chunks of the socket call before `start` were not walked, so the uploaded bytes of the
	// whole call are taken from the buffer's own accounting when it has them
	total := r.UploadedBytes(buf.DataID())
	if counted := uploaded.get(buf.DataID()); total < counted {
		total = counted
	}
	if missing := int64(buf.TotalSize()) - total; missing > 0 {
		return missing
	}
	return 0
}

func (r *Buffer) DataSize() int64 {
	if r == nil {
		return 0
	}
	if r.sizeOverride > 0 {
		return r.sizeOverride
	}
	var result = r.virtualBytes
	var headPosition = r.head
	if headPosition == nil {
		if !r.PrepareForReading() {
			return 0
		}
		defer func() {
			r.ResetForLoopReading()
		}()
		headPosition = r.head
	}

	isFirst := true
	for e := headPosition.element; e != nil; e = e.Next() {
		if isFirst {
			result += int64(e.Value.(SocketDataBuffer).BufferLen() - headPosition.bufIndex)
			isFirst = false
		} else {
			result += int64(e.Value.(SocketDataBuffer).BufferLen())
		}
	}
	return result
}

func (r *Buffer) FirstSocketBuffer() SocketDataBuffer {
	if r == nil || r.dataEvents == nil || r.dataEvents.Len() == 0 {
		return nil
	}
	return r.dataEvents.Front().Value.(SocketDataBuffer)
}

// CurrentSocketBuffer returns the data event at the reading position, nil when there is none. Unlike
// FirstSocketBuffer of a Slice at the position, it is never wrapped in a SocketDataEventLimited.
func (r *Buffer) CurrentSocketBuffer() SocketDataBuffer {
	if r == nil || !r.current.HasElement() {
		return nil
	}
	return r.current.element.Value.(SocketDataBuffer)
}

func (r *Buffer) LastSocketBuffer() SocketDataBuffer {
	if r == nil || r.dataEvents == nil || r.dataEvents.Len() == 0 {
		return nil
	}
	return r.dataEvents.Back().Value.(SocketDataBuffer)
}

func (r *Buffer) TotalBuffer() []SocketDataBuffer {
	if r == nil || r.dataEvents == nil || r.dataEvents.Len() == 0 {
		return nil
	}
	result := make([]SocketDataBuffer, 0, r.dataEvents.Len())
	for e := r.dataEvents.Front(); e != nil; e = e.Next() {
		if e.Value == nil {
			continue
		}
		result = append(result, e.Value.(SocketDataBuffer))
	}
	return result
}

// AppendTotalBuffer appends what TotalBuffer returns to dst, without a slice of its own
func (r *Buffer) AppendTotalBuffer(dst []SocketDataBuffer) []SocketDataBuffer {
	if r == nil || r.dataEvents == nil {
		return dst
	}
	for e := r.dataEvents.Front(); e != nil; e = e.Next() {
		if e.Value == nil {
			continue
		}
		dst = append(dst, e.Value.(SocketDataBuffer))
	}
	return dst
}

// TotalBufferLen is the most events TotalBuffer returns
func (r *Buffer) TotalBufferLen() int {
	if r == nil || r.dataEvents == nil {
		return 0
	}
	return r.dataEvents.Len()
}

// DetectNotSendingLastPosition detect the buffer contains not sending data: the BPF limited socket data count
func (r *Buffer) DetectNotSendingLastPosition() *Position {
	if r == nil || r.dataEvents.Len() == 0 {
		return nil
	}

	for e := r.dataEvents.Front(); e != nil; e = e.Next() {
		buf := e.Value.(SocketDataBuffer)
		// the buffer is sent finished but still have reduced data not send
		if buf.IsFinished() && buf.HaveReduceDataAfterChunk() {
			return &Position{element: e, bufIndex: buf.BufferLen()}
		}
	}
	return nil
}

// CombineSlices returns a new buffer holding the data events of the buffers, in order. It never changes
// any of them: a buffer one message holds can be combined into another message (the HTTP/2 analyzer combines the
// header and body buffers of a stream into the stream's log) and must stay what it was. A single buffer
// is returned as it is.
func CombineSlices(validated bool, originalBuffer *Buffer, buffers ...*Buffer) *Buffer {
	if len(buffers) == 0 {
		return nil
	}
	if len(buffers) == 1 {
		return buffers[0]
	}
	r := &Buffer{
		dataEvents:     newEventList(),
		detailEvents:   emptyList, // for the combined buffer, the details list should be queried from original buffer
		validated:      validated,
		originalBuffer: originalBuffer,
		combined:       true,
	}
	r.appendSlicesTo(buffers)
	r.head = &Position{element: r.dataEvents.Front(), bufIndex: 0}
	r.current = &Position{element: r.dataEvents.Front(), bufIndex: 0}
	r.endPosition = lastEndPosition(buffers)
	return r
}

// AppendSlices appends the buffers onto dst and returns the result, for a message that is assembled slice
// by slice (the body of an HTTP/2 stream, one DATA frame per few KB): copying the whole list again for
// every slice makes the assembly quadratic in the number of frames. dst is changed in place only when
// it is a buffer CombineSlices or AppendSlices built, which belongs to the message that holds it and to
// nothing else; the caller must not have handed it out. Otherwise the result is a new buffer.
func AppendSlices(validated bool, originalBuffer, dst *Buffer, buffers ...*Buffer) *Buffer {
	if dst == nil || !dst.combined || dst.dataEvents == nil || dst.dataEvents.Len() == 0 {
		return CombineSlices(validated, originalBuffer, append([]*Buffer{dst}, buffers...)...)
	}
	// the head and the current position stay valid: the new elements only ever go to the back
	dst.validated = validated
	dst.appendSlicesTo(buffers)
	if end := lastEndPosition(buffers); end != nil {
		dst.endPosition = end
	} else if dst.endPosition == nil {
		dst.endPosition = dst.Position()
	}
	return dst
}

// AppendSliceOf appends to dst what AppendSlices(validated, original, dst, slice) appends, slice being
// src.Slice(validated, start, end) with virtual added to its virtual bytes (AddVirtualBytes), without building
// the slice: the same values in the same wrappers, the same virtual bytes and end position. It is the body of an
// HTTP/2 stream growing by a DATA frame, which made a buffer and a list per frame only to copy them. It only
// appends onto a buffer AppendSlices would append onto in place (built by CombineSlices or AppendSlices, holding
// events); otherwise it returns false and changes nothing, and the caller takes the way through the slice.
//
//nolint:gocyclo // per DATA frame on the HTTP/2 body path, it mirrors Slice and AppendSlices step by step
func AppendSliceOf(validated bool, dst, src *Buffer, start, end *Position, virtual int64) bool {
	if dst == nil || !dst.combined || dst.dataEvents == nil || dst.dataEvents.Len() == 0 {
		return false
	}
	if start.element != end.element && src.isDetached(start.element) {
		// what Slice does with a start element that left the list
		if src.dataEvents.Front() == nil {
			// no slice: AppendSlices appends nothing
			dst.validated = validated
			if dst.endPosition == nil {
				dst.endPosition = dst.Position()
			}
			return true
		}
		start = &Position{element: src.dataEvents.Front(), bufIndex: 0}
	}
	count := 1
	for e := start.element; e != end.element; e = e.Next() {
		if e == nil || e.Value == nil {
			break
		}
		count++
	}
	dst.validated = validated
	if virtual > 0 {
		dst.virtualBytes += virtual
	}
	dst.dataEvents.reserve(count)
	// walkSlices over the slice: its first value is cut at the start offset
	first := true
	push := func(v SocketDataBuffer) {
		if first && start.bufIndex > 0 {
			dst.dataEvents.PushBack(&SocketDataEventLimited{SocketDataBuffer: v, From: start.bufIndex, Size: v.BufferLen()})
		} else {
			dst.dataEvents.PushBack(v)
		}
		first = false
	}
	for e := start.element; e != end.element; e = e.Next() {
		if e == nil || e.Value == nil {
			break
		}
		push(e.Value.(SocketDataBuffer))
	}
	push(&SocketDataEventLimited{SocketDataBuffer: end.element.Value.(SocketDataBuffer), Size: end.bufIndex})
	dst.endPosition = end
	return true
}

// CombineSliceOf returns what AppendSlices(validated, original, dst, slice) returns for a dst it does not append
// onto in place (a slice, not a combination), slice being src.Slice(validated, start, end) with virtual added to
// its virtual bytes: the combination of the two, without building the slice. nil when dst is not such a buffer
// with events, or the slice would not be the plain one (its start element left the list); the caller then takes
// the way through the slice.
func CombineSliceOf(validated bool, original, dst, src *Buffer, start, end *Position, virtual int64) *Buffer {
	if dst == nil || dst.combined || dst.head == nil || dst.dataEvents == nil || dst.dataEvents.Len() == 0 {
		return nil
	}
	if start.element != end.element && src.isDetached(start.element) {
		return nil
	}
	r := &Buffer{
		dataEvents:     newEventList(),
		detailEvents:   emptyList,
		validated:      validated,
		originalBuffer: original,
		combined:       true,
	}
	r.appendSlicesTo([]*Buffer{dst})
	AppendSliceOf(validated, r, src, start, end, virtual)
	r.head = &Position{element: r.dataEvents.Front(), bufIndex: 0}
	r.current = &Position{element: r.dataEvents.Front(), bufIndex: 0}
	return r
}

// appendSlicesTo appends the unread data events of the buffers to the list of r, and their virtual bytes
func (r *Buffer) appendSlicesTo(buffers []*Buffer) {
	size := 0
	for _, b := range buffers {
		if b != nil && b.head != nil {
			r.virtualBytes += b.virtualBytes
			size += b.dataEvents.Len()
		}
	}
	r.dataEvents.reserve(size)
	walkSlices(buffers, func(value interface{}) {
		r.dataEvents.PushBack(value)
	})
}

// CombinedSocketBuffers returns what CombineSlices(validated, original, buffers...).TotalBuffer() returns,
// without building the combined buffer, for a caller that only needs its events
func CombinedSocketBuffers(buffers ...*Buffer) []SocketDataBuffer {
	if len(buffers) == 0 {
		return nil
	}
	if len(buffers) == 1 {
		// CombineSlices returns a single buffer as it is
		return buffers[0].TotalBuffer()
	}
	// size is the length of the combined list, and TotalBuffer returns nil only when that is empty
	size := 0
	for _, b := range buffers {
		if b != nil && b.head != nil {
			size += b.dataEvents.Len()
		}
	}
	if size == 0 {
		return nil
	}
	result := make([]SocketDataBuffer, 0, size)
	walkSlices(buffers, func(value interface{}) {
		// the nil values TotalBuffer skips
		if value != nil {
			result = append(result, value.(SocketDataBuffer))
		}
	})
	return result
}

// walkSlices visits the unread data event values of the buffers in the order CombineSlices combines
// them, skipping nil and headless buffers: a partly read head is wrapped in a SocketDataEventLimited
func walkSlices(buffers []*Buffer, visit func(value interface{})) {
	for _, b := range buffers {
		if b == nil || b.head == nil {
			continue
		}
		e, n := b.dataEvents.Front(), b.dataEvents.Len()
		if b.head.bufIndex > 0 {
			headBuffer := e.Value.(SocketDataBuffer)
			visit(&SocketDataEventLimited{SocketDataBuffer: headBuffer, From: b.head.bufIndex, Size: headBuffer.BufferLen()})
			e, n = e.Next(), n-1
		}
		for ; n > 0; n-- {
			visit(e.Value)
			e = e.Next()
		}
	}
}

// lastEndPosition is the end of the last of the buffers that has one: its end position, or its reading
// position; nil when none has
func lastEndPosition(buffers []*Buffer) *Position {
	for i := len(buffers) - 1; i >= 0; i-- {
		if buffers[i] == nil {
			continue
		}
		if buffers[i].endPosition != nil {
			return buffers[i].endPosition
		}
		if p := buffers[i].Position(); p != nil {
			return p
		}
	}
	return nil
}

func (r *Buffer) Peek(p []byte) (n int, err error) {
	// save the index temporary (a copy of the value: Read moves the position in place)
	tmpPosition := *r.current
	r.peeking = true
	// restore the index
	defer func() {
		*r.current = tmpPosition
		r.peeking = false
	}()
	readIndex := 0
	for readIndex < len(p) {
		count, err := r.Read(p[readIndex:])
		if err != nil {
			return 0, err
		}
		readIndex += count
	}
	return readIndex, nil
}

func (r *Buffer) OffsetPosition(offset int) *Position {
	var nextElement func(e *eventElement) *eventElement
	if offset == 0 {
		return r.current.Clone()
	} else if offset > 0 {
		nextElement = func(e *eventElement) *eventElement {
			return e.Next()
		}
	} else {
		nextElement = func(e *eventElement) *eventElement {
			return e.Prev()
		}
	}

	var curEle = r.current.element
	var curIndex = r.current.bufIndex
	for ; curEle != nil; curEle = nextElement(curEle) {
		nextOffset := curIndex + offset
		bufferLen := curEle.Value.(SocketDataBuffer).BufferLen()
		if nextOffset >= 0 && nextOffset < bufferLen {
			curIndex += offset
			break
		}

		if offset > 0 {
			offset -= bufferLen - curIndex
			curIndex = 0
		} else {
			offset += curIndex
			next := nextElement(curEle)
			if next == nil {
				curEle = next
				break
			}
			curIndex = curEle.Value.(SocketDataBuffer).BufferLen()
		}
	}

	if curEle == nil {
		return nil
	}
	return &Position{element: curEle, bufIndex: curIndex}
}

func (r *Buffer) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.current == nil || r.current.element == nil {
		return 0, io.EOF
	}
	if curEvent := r.current.element.Value.(SocketDataBuffer); IsPayloadSkipped(curEvent) &&
		curEvent.BufferLen() > r.current.bufIndex {
		// an HTTP/1 body call decoded without its bytes keeps its length: there is nothing to copy
		r.noteSkippedRead(curEvent)
		return 0, ErrPayloadSkipped
	}
	if curEvent := r.current.element.Value.(SocketDataBuffer); payloadReleased(curEvent) &&
		curEvent.BufferLen() > r.current.bufIndex {
		return 0, ErrPayloadReleased
	}
	element, n := r.ReadFromCurrent(p)
	if n > 0 {
		return n, nil
	}

	curEvent := element.Value.(SocketDataBuffer)
	if IsPayloadSkipped(curEvent) {
		// only DiscardBytes moves the reader onto such an event, which it consumes as a whole: a read
		// that starts on one does not start on a frame boundary
		return 0, ErrPayloadSkipped
	}
	next, nextEvent, err := r.nextReadable(element, curEvent, true)
	if err != nil {
		return 0, err
	}
	if IsPayloadSkipped(nextEvent) {
		r.noteSkippedRead(nextEvent)
		return 0, ErrPayloadSkipped
	}
	if payloadReleased(nextEvent) {
		return 0, ErrPayloadReleased
	}
	return r.read0(next, nextEvent, p)
}

// payloadReleased tells that the event has a length but no bytes anymore, and was not decoded without them: its
// buffer was released (ReleaseBuffer) while it is still read, which would slice a nil buffer
func payloadReleased(ev SocketDataBuffer) bool {
	return ev.BufferLen() > 0 && len(ev.BufferData()) == 0 && !IsPayloadSkipped(ev)
}

// noteSkippedRead counts a read, not a peek, that wanted the bytes of an HTTP/1 body call decoded
// without them (BodySkipConflicts)
func (r *Buffer) noteSkippedRead(ev SocketDataBuffer) {
	if !r.peeking && IsBodyPayloadSkipped(ev) {
		bodySkipConflicts.Add(1)
	}
}

// nextReadable returns the element the reader continues with once the current one, `element`, is read to
// its end, or why it cannot continue: io.EOF when there is none yet, ErrNotComplete when it does not
// directly follow, ErrTruncated (with stopAtTruncation, when checkTruncation is set) when BPF did not
// upload the rest of the current socket call.
//
//nolint:gocyclo // per element on the read path, its cases are the ways a read can stop
func (r *Buffer) nextReadable(element *eventElement, curEvent SocketDataBuffer, checkTruncation bool) (
	next *eventElement, nextEvent SocketDataBuffer, err error) {
	next = r.nextElement(element)
	if next == nil {
		return nil, nil, io.EOF
	}
	nextEvent = next.Value.(SocketDataBuffer)

	var shouldRead = false
	if r.validated {
		shouldRead = true
		// same data id and sequence orders
	} else if (curEvent.DataID() == nextEvent.DataID() && curEvent.DataSequence()+1 == nextEvent.DataSequence()) ||
		// cur event is finished and next event is start
		(nextEvent.IsStart() && curEvent.IsFinished()) ||
		// same data id and sequence but have difference buffer index
		(curEvent.DataID() == nextEvent.DataID() && curEvent.DataSequence() == nextEvent.DataSequence() &&
			r.current.bufIndex <= nextEvent.BufferStartPosition()) {
		shouldRead = true
	}

	if shouldRead && !r.validated && curEvent.DataID() != nextEvent.DataID() {
		// the message continues in a following socket call
		if checkTruncation && r.isTruncatedAfter(curEvent) {
			// BPF did not upload the rest of the current call: the next bytes of the buffer are the
			// bytes of another call, not the continuation of this message
			return nil, nil, ErrTruncated
		}
		if r.sequenceCheck != nil {
			if nextEvent.PrevDataID() != curEvent.DataID() && !r.sequenceCheck(nextEvent.DataID()) {
				// a socket call uploaded before the later one has not been delivered yet
				shouldRead = false
				r.sequenceRefused = nextEvent.DataID()
			}
		}
	}

	if !shouldRead {
		if r.sequenceRefused != nextEvent.DataID() {
			// not a refusal of the sequence check: a part of the current call is missing
			r.noteIncomplete(curEvent)
		}
		return nil, nil, ErrNotComplete
	}
	return next, nextEvent, nil
}

// DiscardResult is what DiscardBytes got through: Consumed bytes of the stream, Virtual of them never
// uploaded by BPF, and Unread, the bytes BPF did not upload of the truncated socket call the discard
// stopped at the end of (0 when it did not stop at one)
type DiscardResult struct {
	Consumed int
	Virtual  int64
	Unread   int64
	// the part of Virtual that SummaryGaps stood for (summarize_h2c_payload)
	Summarized int64
}

// DiscardBytes moves the reading position forward by n bytes of the stream without copying them.
//
// The bytes BPF never uploaded count as consumed and as virtual: a socket call uploaded without its
// content (PayloadSkippedBuffer) counts as a whole, with its TotalSize; and with followTruncation, the
// bytes a truncated socket call did not upload count when the n bytes run on past them (the next event
// then directly continues the stream) or end exactly with them. Without followTruncation the discard
// stops at a truncated call as Read does.
//
// The errors are those of Read: io.EOF when the rest has not arrived yet, ErrNotComplete when a socket
// call in between is missing, ErrTruncated when the n bytes end inside the bytes a truncated call did not
// upload, and ErrPayloadSkipped when they end inside a call uploaded without its content, which the
// reader should have covered as a whole.
//
// The truncation needs the upload accounting of AppendDataEvent (uploadedBytes): it is meant for a view
// buffer (NewViewBuffer) the events are appended to, not for a slice or a combination.
//
//nolint:gocyclo // one walk over the elements on the body skipping path, its cases read best together
func (r *Buffer) DiscardBytes(n int) (result DiscardResult, err error) {
	if r.current == nil || r.current.element == nil {
		if n <= 0 {
			return result, nil
		}
		return result, io.EOF
	}
	for result.Consumed < n {
		element := r.current.element
		curEvent := element.Value.(SocketDataBuffer)
		if residue := curEvent.BufferLen() - r.current.bufIndex; residue > 0 {
			step := n - result.Consumed
			if residue < step {
				step = residue
			}
			r.current.bufIndex += step
			result.Consumed += step
			continue
		}
		truncated, missing := r.truncatedAfter(element, curEvent)
		if truncated {
			result.Unread = missing
		}
		if truncated && r.followTruncation && missing > 0 {
			// the bytes BPF did not upload of the current call come first. When the n bytes end among
			// them, the rest of the call is not readable; when they end exactly with them, the discard is
			// complete and the next call starts behind it; when they reach past them, the stream goes on
			// in the next socket call.
			left := int64(n - result.Consumed)
			if left < missing {
				return result, ErrTruncated
			}
			if left == missing {
				result.Consumed, result.Virtual = n, result.Virtual+missing
				return result, nil
			}
		} else {
			missing = 0
		}
		// without followTruncation the discard stops at a truncated call as Read does
		next, nextEvent, nextErr := r.nextReadable(element, curEvent, !r.followTruncation)
		if nextErr != nil {
			return result, nextErr
		}
		result.Consumed += int(missing)
		result.Virtual += missing
		result.Unread = 0
		if gap := SummaryRunGap(nextEvent); gap != nil && gap.Headed {
			// a run behind a head (H2C_SUM_RUN_HEAD): the bytes still wanted are the head, the end of the frame in front
			// of the run. The discard stops in front of the gap, which the parser takes where it expects a frame header.
			if left := uint64(n - result.Consumed); left > 0 && left+uint64(gap.Frames)*9 <= gap.Size {
				gap.Head = left
				result.Consumed = n
				result.Virtual += int64(left)
				result.Summarized += int64(left)
				return result, nil
			}
			return result, ErrPayloadSkipped
		}
		if IsPayloadSkipped(nextEvent) {
			size := int(nextEvent.TotalSize())
			if size > n-result.Consumed || SummaryRunGap(nextEvent) != nil {
				// (a run of whole frames is never inside the bytes of a frame: the parser takes it where it
				// expects a frame header)
				return result, ErrPayloadSkipped
			}
			result.Consumed += size
			result.Virtual += int64(size)
			if gap := summaryGapOf(nextEvent); gap != nil {
				result.Summarized += int64(gap.Size)
			}
		}
		r.current.element = next
		r.current.bufIndex = 0
	}
	return result, nil
}

// truncatedAfter reports whether the reader must stop behind ev because BPF truncated its socket call at
// the upload limit (stopAtTruncation, ev being the last chunk of the call), and how many bytes of the
// call were not uploaded
func (r *Buffer) truncatedAfter(e *eventElement, ev SocketDataBuffer) (truncated bool, missing int64) {
	if !r.isTruncatedAfter(ev) {
		return false, 0
	}
	r.rlock()
	defer r.runlock()
	return true, int64(ev.TotalSize()) - r.uploadedBytesAt(e, ev)
}

// isTruncatedAfter is truncatedAfter without the bytes that are missing
func (r *Buffer) isTruncatedAfter(ev SocketDataBuffer) bool {
	return r.stopAtTruncation && !r.validated && ev.IsFinished() && ev.HaveReduceDataAfterChunk()
}

//nolint:revive // exported as in upstream rover, only this package calls it
func (r *Buffer) ReadFromCurrent(p []byte) (element *eventElement, n int) {
	element = r.current.element
	curEvent := element.Value.(SocketDataBuffer)
	residueSize := curEvent.BufferLen() - r.current.bufIndex
	if residueSize > 0 {
		readLen := len(p)
		if residueSize < readLen {
			readLen = residueSize
		}

		n = copy(p, curEvent.BufferData()[r.current.bufIndex:r.current.bufIndex+readLen])
		r.current.bufIndex += n
		return element, n
	}
	return element, 0
}

func (r *Buffer) ReadUntilBufferFull(data []byte) error {
	currentIndex := 0
	for currentIndex < len(data) {
		// read into the not yet filled part, so data spanning multiple elements is not overwritten
		readCount, err := r.Read(data[currentIndex:])
		if err != nil {
			return err
		}
		currentIndex += readCount
	}
	return nil
}

func (r *Buffer) Merge(other *Buffer) {
	if other == nil {
		return
	}
	for e := other.dataEvents.Front(); e != nil; e = e.Next() {
		if v, ok := e.Value.(SocketDataBuffer); ok && v != nil {
			r.AppendDataEvent(v)
		}
	}
	for e := other.detailEvents.Front(); e != nil; e = e.Next() {
		if v, ok := e.Value.(SocketDataDetail); ok && v != nil {
			r.AppendDetailEvent(v)
		}
	}
}

func (r *Buffer) read0(currentElement *eventElement, currentBuffer SocketDataBuffer, p []byte) (n int, err error) {
	readLen := len(p)
	if currentBuffer.BufferLen() < readLen {
		readLen = currentBuffer.BufferLen()
	}

	copy(p, currentBuffer.BufferData()[:readLen])
	r.current.element = currentElement
	r.current.bufIndex = readLen
	return readLen, nil
}

// IsCurrentPacketReadFinished means to validate the current reading package is reading finished
func (r *Buffer) IsCurrentPacketReadFinished() bool {
	return r.current.bufIndex == r.current.element.Value.(SocketDataBuffer).BufferLen()
}

func (r *Buffer) ResetForLoopReading() {
	r.head = nil
	r.current = nil
}

func (r *Buffer) PrepareForReading() bool {
	// a new read: the refusal of the last one is over (the analyzer goroutine owns the field)
	r.sequenceRefused = 0
	r.incompleteNow = false
	r.rlock()
	defer r.runlock()
	if r.dataEvents.Len() == 0 {
		return false
	}
	// an event was inserted out of order: start over from the first event unless every insert went
	// behind the head. An insert before the head always becomes the new first event, and nothing
	// precedes the head otherwise, since RemoveReadElements and RemoveCurrentElement remove what was
	// read before it, so the head, with the offset RemoveReadElements kept in a partially read event,
	// stays valid while it is still the first event. The append path never reads the position (it
	// belongs to the analyzer goroutine); only this check does, here, under the event lock.
	// The head may also have moved past events it skipped (SkipCurrentElement), which stay before it: an insert
	// behind the head (every key of the inserts sorts at or after the head's event) keeps it too, instead of
	// reading those events again.
	if r.shouldResetPosition.Load() && r.shouldResetPosition.CompareAndSwap(true, false) {
		keep := r.head != nil && r.head.element != nil &&
			(r.dataEvents.Front() == r.head.element || (r.resetKeySet && !r.isDetachedLocked(r.head.element) &&
				r.head.element.atOrBefore(&r.resetKey)))
		if !keep {
			r.head = nil
		}
	}
	// the inserts so far are looked at: the next ones start over (the appends wait for the read lock released)
	r.resetKeySet = false
	if r.head != nil && r.head.element != nil && r.isDetachedLocked(r.head.element) {
		// the head element was removed from the list (e.g. expired), restart from the first element
		r.head = nil
	}
	if r.head == nil || r.head.element == nil {
		// read in the first element
		r.head = &Position{element: r.dataEvents.Front(), bufIndex: 0}
	}
	// make sure we can read from head
	r.resetCurrent()
	return true
}

// IsCurrentSocketCallComplete reports whether every chunk of the socket call at the reading head has
// been delivered (its last chunk, the one marked finished, is in the buffer). False means the reader
// is waiting for a chunk of the very socket call it is reading, not for a following one.
func (r *Buffer) IsCurrentSocketCallComplete() bool {
	if r == nil || r.head == nil || r.head.element == nil {
		return true
	}
	cur, ok := r.head.element.Value.(SocketDataBuffer)
	if !ok || cur == nil {
		return true
	}
	dataID := cur.DataID()
	for e := r.head.element; e != nil; e = r.nextElement(e) {
		b, ok := e.Value.(SocketDataBuffer)
		if !ok || b == nil || b.DataID() != dataID {
			return false
		}
		if b.IsFinished() {
			return true
		}
	}
	return false
}

// NextSocketCallDataID returns the data id of the first socket call behind the one at the reading
// head, 0 when the buffer holds no further call
func (r *Buffer) NextSocketCallDataID() uint64 {
	if r == nil || r.head == nil || r.head.element == nil {
		return 0
	}
	cur, ok := r.head.element.Value.(SocketDataBuffer)
	if !ok || cur == nil {
		return 0
	}
	for e := r.nextElement(r.head.element); e != nil; e = r.nextElement(e) {
		b, ok := e.Value.(SocketDataBuffer)
		if !ok || b == nil {
			return 0
		}
		if b.DataID() != cur.DataID() {
			return b.DataID()
		}
	}
	return 0
}

// isDetached reports whether the element is no longer part of the data event list
func (r *Buffer) isDetached(e *eventElement) bool {
	r.rlock()
	defer r.runlock()
	return r.isDetachedLocked(e)
}

func (r *Buffer) isDetachedLocked(e *eventElement) bool {
	return e.Next() == nil && e.Prev() == nil && r.dataEvents.Front() != e
}

// nolint
func (r *Buffer) RemoveReadElements(includeDetails bool) bool {
	r.lock()
	defer r.unlock()

	// delete until the last data id
	if includeDetails && r.head.element != nil && r.current.element != nil {
		firstDataID := r.head.element.Value.(SocketDataBuffer).DataID()
		currentBuffer := r.current.element.Value.(SocketDataBuffer)
		lastDataID := currentBuffer.DataID()
		startDelete := false
		for e := r.detailEvents.Front(); e != nil; {
			event := e.Value.(SocketDataDetail)
			if firstDataID == lastDataID && currentBuffer.BufferLen() != r.current.bufIndex {
				// current buffer is not finished, so the detail cannot be deleted
				break
			}
			if !startDelete && event.DataID() >= firstDataID && event.DataID() <= lastDataID {
				startDelete = true
			} else if startDelete && event.DataID() > lastDataID {
				// out of the data id, just break
				break
			}

			if startDelete {
				tmp := e.Next()
				r.detailEvents.Remove(e)
				if log.Enable(logrus.DebugLevel) {
					log.Debugf("delete detail event from readed buffer, data id: %d, ref: %p", event.DataID(), r)
				}
				e = tmp
			} else {
				e = e.Next()
			}
		}
	}

	// delete until to current position
	next := r.head.element
	stillCurrent := true
	for ; next != nil && next != r.current.element; next = r.removeElement0(next) {
		stillCurrent = false
	}
	// not enough data, then return
	if !stillCurrent && next == nil {
		return true
	}

	if next != nil && next.Value.(SocketDataBuffer).BufferLen() == r.current.bufIndex { // all buffer finished, then delete it
		// the last event already read finished, then delete it
		r.head.element = r.removeElement0(next)
		r.head.bufIndex = 0
	} else {
		if !stillCurrent {
			r.head.element = next
		}
		// still have reduced buffer, then keep reading from current index in next loop
		r.head.bufIndex = r.current.bufIndex
	}
	return false
}

// HeadDataEvent returns the data event the reader head points to: the event RemoveCurrentElement
// would release, so the caller can still report it before it is dropped
func (r *Buffer) HeadDataEvent() SocketDataBuffer {
	r.rlock()
	defer r.runlock()
	if r.head == nil || r.head.element == nil || r.head.element.Value == nil {
		return nil
	}
	event, _ := r.head.element.Value.(SocketDataBuffer)
	return event
}

// RemoveCurrentElement removes the element the reader head points to (the element the current
// message started in) and moves the head to the next element. It returns true when no element is left.
func (r *Buffer) RemoveCurrentElement() bool {
	r.lock()
	defer r.unlock()
	if r.head == nil || r.head.element == nil {
		return true
	}
	r.head.element = r.removeElement0(r.head.element)
	r.head.bufIndex = 0
	r.resetCurrent()
	return r.head.element == nil
}

// SkipCurrentElement skip current element in reader, if return true means have read finished
func (r *Buffer) SkipCurrentElement() bool {
	r.head.element = r.nextElement(r.current.element)
	r.head.bufIndex = 0
	r.current.bufIndex = 0

	return r.head.element == nil
}

func (r *Buffer) removeElement0(element *eventElement) *eventElement {
	if element == nil {
		return nil
	}
	if r.isDetachedLocked(element) {
		// already removed (and released) through a position that outlived it: releasing it again would
		// count the event out twice
		return nil
	}
	result := element.Next()
	b, ok := element.Value.(SocketDataBuffer)
	if ok && b.IsFinished() {
		// the socket call is complete, its upload accounting is not needed anymore (the neighbors
		// are looked at while the element is still linked)
		r.forgetUpload(element, b.DataID())
	}
	if r.finger == element {
		r.finger = nil
	}
	r.dataEvents.Remove(element)
	r.trimMarks()
	if ok {
		ReleaseEvent(b.ReleaseBuffer())
	}
	return result
}

func (r *Buffer) AppendDetailEvent(event SocketDataDetail) {
	r.lock()
	defer r.unlock()

	if r.detailEvents.Len() == 0 {
		r.detailEvents.PushFront(event)
		return
	}
	if r.detailEvents.Back().Value == nil {
		r.detailEvents.PushFront(event)
		return
	}
	if r.detailEvents.Back().Value.(SocketDataDetail).DataID() < event.DataID() {
		r.detailEvents.PushBack(event)
		return
	}
	beenAdded := false
	for element := r.detailEvents.Front(); element != nil; element = element.Next() {
		existEvent, ok := element.Value.(SocketDataDetail)
		if !ok {
			continue
		}
		if existEvent.DataID() > event.DataID() {
			// data id needs order
			beenAdded = true
		}
		if beenAdded {
			r.detailEvents.InsertBefore(event, element)
			break
		}
	}
	if !beenAdded {
		r.detailEvents.PushBack(event)
	}
}

// AppendDataEvent insert the event to the event list following the order, and returns the event the buffer
// holds, which is the event itself
func (r *Buffer) AppendDataEvent(event SocketDataBuffer) SocketDataBuffer {
	r.lock()
	defer r.unlock()

	if r.uploadedBytes == nil {
		r.uploadedBytes = make(map[uint64]int64)
	}
	acceptedBytes.Add(int64(event.BufferLen()))

	// The reading position (head, current) belongs to the analyzer goroutine, which moves it without the
	// lock, so the append never reads it. Instead, an event that is not appended at the back may have
	// gone in before the reading position: then the reader starts over from the front. An event appended
	// at the back sorts at or after every element, the one being read included, so it never needs that.
	key := keyOf(event)
	if r.dataEvents.Len() == 0 {
		r.account(event, nil, nil)
		r.dataEvents.PushFront(event).setKey(&key)
		r.shouldResetPosition.Store(true)
		return event
	}
	back := r.dataEvents.Back()
	if back.atOrBefore(&key) {
		r.account(event, back, nil)
		r.dataEvents.PushBack(event).setKey(&key)
		return event
	}
	// out of order: the event goes behind the last element it sorts at or after (eventAfter), as a search from
	// the back finds it. The records of a per-CPU batch arrive in order among themselves but behind the events
	// other CPUs delivered meanwhile, so a search from the back would walk over those for every record of the
	// batch: it starts where the last out of order event went instead (the finger), which makes merging a
	// batch one walk over the events it goes between, and when the place is not near it, the marks find it
	// (seek). The list is sorted, so the place is the same.
	if element := r.insertionPoint(&key); element != nil {
		r.account(event, element, element.Next())
		r.finger = r.dataEvents.InsertAfter(event, element)
	} else {
		r.account(event, nil, r.dataEvents.Front())
		r.finger = r.dataEvents.PushFront(event)
	}
	r.finger.setKey(&key)
	r.noteResetKey(&key)
	r.shouldResetPosition.Store(true)
	return event
}

// noteResetKey keeps the key of an event inserted out of order when it is the smallest since the last
// PrepareForReading (under the event lock)
func (r *Buffer) noteResetKey(key *eventKey) {
	if !r.resetKeySet || key.before(&r.resetKey) {
		r.resetKey, r.resetKeySet = *key, true
	}
}

func (r *Buffer) account(event SocketDataBuffer, prev, next *eventElement) {
	if !r.noUploadAccounting {
		r.accountUpload(event, prev, next)
	}
}

const (
	// fingerWalk is how far the search for the place of an out of order event walks from the finger before it
	// takes the marks (seek)
	fingerWalk = 16
	// markStride is how many elements apart the walks of seek plant the marks
	markStride = 16
)

// insertionPoint is the last element the event of the key sorts at or after (eventAfter), nil when it sorts
// before every element: the list is sorted, so the elements it sorts at or after are a prefix, and the walk
// from the finger (or the back) towards the event finds the end of that prefix when it is near; otherwise the
// marks do (seek). The finger is used while it is still an element of the list (a removed or replaced element
// is detached and belongs to no list).
func (r *Buffer) insertionPoint(key *eventKey) *eventElement {
	e := r.finger
	if e == nil || e.list != r.dataEvents {
		e = r.dataEvents.Back()
	}
	if e.atOrBefore(key) {
		for i := 0; i < fingerWalk; i++ {
			next := e.Next()
			if next == nil || !next.atOrBefore(key) {
				return e
			}
			e = next
		}
	} else {
		for i := 0; i < fingerWalk; i++ {
			if e = e.Prev(); e == nil || e.atOrBefore(key) {
				return e
			}
		}
	}
	return r.seek(key)
}

// seek is insertionPoint by the marks: the last mark at or before the key, and the walk from it to the end of
// the prefix, which plants a mark every markStride elements it passes; for a key before every mark (or with no
// marks yet), the walk back from the first mark (or the back), which plants them the same way. So a walk is
// long only over a stretch no search went over before: the marks keep the search short in a deep list, where
// the place of a late record can be thousands of events behind the finger.
func (r *Buffer) seek(key *eventKey) *eventElement {
	for {
		i := r.lastMarkAtOrBefore(key)
		if i < 0 {
			return r.seekBack(key)
		}
		if r.marks[i].list != r.dataEvents {
			// the element left the list: the mark goes, and the search starts over
			r.marks = slices.Delete(r.marks, i, i+1)
			continue
		}
		e, steps := r.marks[i], 0
		for {
			next := e.Next()
			if next == nil || !next.atOrBefore(key) {
				return e
			}
			e = next
			steps++
			if steps == markStride {
				// a mark behind the one the walk started from (the marks after it sort after the key)
				i++
				r.marks = slices.Insert(r.marks, i, e)
				steps = 0
			}
		}
	}
}

// lastMarkAtOrBefore is the index of the last mark whose element sorts at or before the key, -1 for none. The
// marks are in list order, those whose elements left the list included: they were in it in that order.
func (r *Buffer) lastMarkAtOrBefore(key *eventKey) int {
	lo, hi := 0, len(r.marks)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if r.marks[m].atOrBefore(key) {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo - 1
}

// seekBack is seek for a key before every mark: the walk back from the first mark, or from the back without
// marks, every element of which sorts after the key
func (r *Buffer) seekBack(key *eventKey) *eventElement {
	r.trimMarks()
	var e *eventElement
	if len(r.marks) > 0 {
		e = r.marks[0]
	} else {
		e = r.dataEvents.Back()
	}
	planted := r.markScratch[:0]
	steps := 0
	for e = e.Prev(); e != nil && !e.atOrBefore(key); e = e.Prev() {
		steps++
		if steps == markStride {
			planted = append(planted, e)
			steps = 0
		}
	}
	if len(planted) > 0 {
		// planted from the back: in list order they go in front of the marks
		for i, j := 0, len(planted)-1; i < j; i, j = i+1, j-1 {
			planted[i], planted[j] = planted[j], planted[i]
		}
		r.marks = slices.Insert(r.marks, 0, planted...)
		clear(planted)
	}
	r.markScratch = planted[:0]
	return e
}

// trimMarks drops the marks in front whose elements left the list (the events are read from the front)
func (r *Buffer) trimMarks() {
	n := 0
	for n < len(r.marks) && r.marks[n].list != r.dataEvents {
		n++
	}
	if n == 0 {
		return
	}
	// resliced, not copied: the events are read from the front, one by one. The slots left behind are
	// cleared, so they keep no element alive, and an append that outgrows the slice leaves them.
	clear(r.marks[:n])
	r.marks = r.marks[n:]
}

func (r *Buffer) dropMarks() {
	clear(r.marks)
	r.marks = r.marks[:0]
}

// eventAfter reports whether event must be ordered after existing: by data id, then sequence, then
// start time (several events can share one data id and sequence, e.g. the TLS uprobe reports every
// library write call with the data id of the enclosing socket call)
func eventAfter(event, existing SocketDataBuffer) bool {
	if event.DataID() != existing.DataID() {
		return event.DataID() > existing.DataID()
	}
	if event.DataSequence() != existing.DataSequence() {
		return event.DataSequence() > existing.DataSequence()
	}
	return event.StartTime() >= existing.StartTime()
}

func (r *Buffer) DeleteExpireEvents(expireDuration time.Duration) int {
	r.lock()
	defer r.unlock()

	expireTime := time.Now().Add(-expireDuration)
	// data event queue
	count := r.deleteEventsWithJudgement(r.dataEvents, func(element *eventElement) bool {
		if element.Value == nil {
			return true
		}
		buffer := element.Value.(SocketDataBuffer)
		startTime := host.Time(buffer.StartTime())
		if expireTime.After(startTime) {
			r.latestExpiredDataID = buffer.DataID()
			r.forgetUpload(element, buffer.DataID())
			ReleaseEvent(buffer.ReleaseBuffer())
			expiredEvents.Add(1)
			return true
		}
		return false
	})

	// detail event queue
	count += deleteDetailsWithJudgement(r.detailEvents, func(element *list.Element) bool {
		detail, ok := element.Value.(SocketDataDetail)
		if !ok {
			return true
		}
		isDelete := r.latestExpiredDataID > 0 && detail.DataID() <= r.latestExpiredDataID ||
			(detail.Time() > 0 && expireTime.After(host.Time(detail.Time())))
		if isDelete {
			if log.Enable(logrus.DebugLevel) {
				log.Debugf("delete expired detail event, data id: %d, buf: %p", detail.DataID(), r)
			}
		}
		return isDelete
	})
	return count
}

func (r *Buffer) DataLength() int {
	if r == nil {
		return 0
	}
	r.rlock()
	defer r.runlock()
	if r.dataEvents == nil {
		return 0
	}
	return r.dataEvents.Len()
}

func (r *Buffer) deleteEventsWithJudgement(l *eventList, checker func(element *eventElement) bool) int {
	count := 0
	for e := l.Front(); e != nil; {
		if checker(e) {
			count++
			cur := e
			e = e.Next()
			if r.finger == cur {
				r.finger = nil
			}
			l.Remove(cur)
			r.trimMarks()
		} else {
			break
		}
	}
	return count
}

// deleteDetailsWithJudgement is deleteEventsWithJudgement for the detail list
func deleteDetailsWithJudgement(l *list.List, checker func(element *list.Element) bool) int {
	count := 0
	for e := l.Front(); e != nil; {
		if checker(e) {
			count++
			cur := e
			e = e.Next()
			l.Remove(cur)
		} else {
			break
		}
	}
	return count
}

func (r *Buffer) nextElement(e *eventElement) *eventElement {
	if e == nil {
		return nil
	}
	r.rlock()
	defer r.runlock()
	return e.Next()
}

// ReleaseEventsBefore releases the data events whose data id is below dataID, with the detail events
// of those data ids, and resets the reading position. It is for a connection whose events before dataID
// can no longer form a complete message (an event between them was dropped by the memory protection),
// so they are given back at once instead of waiting for the expiry. Only the analyzer goroutine calls it,
// between two analyses, as it moves the reading position. It returns the count of released data events.
func (r *Buffer) ReleaseEventsBefore(dataID uint64) int {
	r.lock()
	defer r.unlock()
	count := r.deleteEventsWithJudgement(r.dataEvents, func(element *eventElement) bool {
		b, ok := element.Value.(SocketDataBuffer)
		if !ok || b == nil {
			return true
		}
		if b.DataID() >= dataID {
			return false
		}
		r.forgetUpload(element, b.DataID())
		ReleaseEvent(b.ReleaseBuffer())
		return true
	})
	deleteDetailsWithJudgement(r.detailEvents, func(element *list.Element) bool {
		detail, ok := element.Value.(SocketDataDetail)
		return !ok || detail.DataID() < dataID
	})
	if count > 0 {
		r.head = nil
		r.current = nil
	}
	return count
}

// ReleaseEventsFrom releases the data events whose data id is dataID or above, with their detail events,
// and resets the reading position: the counterpart of ReleaseEventsBefore for the tail of a message that
// can no longer complete. Only the analyzer goroutine calls it, between two analyses. It returns the
// count of released data events.
func (r *Buffer) ReleaseEventsFrom(dataID uint64) int {
	r.lock()
	defer r.unlock()
	count := 0
	for e := r.dataEvents.Back(); e != nil; {
		b, ok := e.Value.(SocketDataBuffer)
		if ok && b != nil && b.DataID() < dataID {
			break
		}
		prev := e.Prev()
		if ok && b != nil {
			r.forgetUpload(e, b.DataID())
			ReleaseEvent(b.ReleaseBuffer())
		}
		if r.finger == e {
			r.finger = nil
		}
		r.dataEvents.Remove(e)
		count++
		e = prev
	}
	for e := r.detailEvents.Back(); e != nil; {
		detail, ok := e.Value.(SocketDataDetail)
		if ok && detail.DataID() < dataID {
			break
		}
		prev := e.Prev()
		r.detailEvents.Remove(e)
		e = prev
	}
	if count > 0 {
		r.head = nil
		r.current = nil
	}
	return count
}

// LastDataEventBefore returns the last data event with a data id below dataID that matches, nil when
// there is none
func (r *Buffer) LastDataEventBefore(dataID uint64, match func(SocketDataBuffer) bool) SocketDataBuffer {
	r.rlock()
	defer r.runlock()
	for e := r.dataEvents.Back(); e != nil; e = e.Prev() {
		b, ok := e.Value.(SocketDataBuffer)
		if !ok || b == nil || b.DataID() >= dataID {
			continue
		}
		if match(b) {
			return b
		}
	}
	return nil
}
