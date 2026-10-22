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
	emptyList    = list.New()

	log = logger.GetLogger("tools", "buffer")

	// pooledBuffer recycles the data arrays of socket data events that hold them through a pointer.
	// Events that embed the array instead (rover's own) never touch it: handing out an interior pointer
	// of a live event would keep that event alive and could alias memory a borrower writes into.
	pooledBuffer = sync.Pool{
		New: func() any {
			return &[20480]byte{}
		},
	}
)

// Socket data events and the memory they hold.
//
// Every event carries a 20KB data array until the analyzer releases it, so an analysis backlog (slow
// backend, large bodies, truncated messages) grows the process until it is killed. Two things guard
// against that, and both go through this file:
//
//   - admission: when the memory usage of the process reaches the configured share of its limit (see
//     memory.go, the same pair the OOM killer looks at), new events are refused and counted, and
//     accepted again once the usage falls back below it;
//   - accounting: eventsInUse counts the events that currently hold an array, so the analysis can be
//     told how much it is still holding.
//
// An event either embeds its array (AcquireEvent) or points at a pooled one (AcquireEventBuffer);
// ReleaseEvent takes both shapes, driven by what the event's ReleaseBuffer returns.
var (
	eventsInUse    atomic.Int64
	droppedByLimit atomic.Int64
)

// MemoryStats returns the socket data events holding an array, the events dropped by the memory
// protection, the last sampled memory usage and the threshold (bytes, 0 when the protection is off)
func MemoryStats() (inUse, dropped, usage, threshold int64) {
	return eventsInUse.Load(), droppedByLimit.Load(), memoryUsage.Load(), memoryThreshold.Load()
}

// AcquireEvent reports whether an event that embeds its data array may be created
func AcquireEvent() bool {
	if memoryProtectionActive.Load() {
		droppedByLimit.Add(1)
		return false
	}
	eventsInUse.Add(1)
	return true
}

// AcquireEventBuffer returns a pooled data array for an event that holds it through a pointer; nil
// means the memory protection is active and the event must be dropped
func AcquireEventBuffer() *[20480]byte {
	if !AcquireEvent() {
		return nil
	}
	return pooledBuffer.Get().(*[20480]byte)
}

// ReleaseEvent releases one socket data event: `b` is what its ReleaseBuffer returned, so a pooled
// array goes back to the pool and nil (an embedded array) only clears the accounting
func ReleaseEvent(b *[20480]byte) {
	eventsInUse.Add(-1)
	if b != nil {
		pooledBuffer.Put(b)
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

	ReleaseBuffer() *[20480]byte
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
	dataEvents   *list.List
	detailEvents *list.List
	validated    bool // the events list is validated or not

	// shouldResetPosition means the buffer have new buffer appended into the buffer
	// so the position should reset to the head, and re-read the buffer
	shouldResetPosition bool

	eventLocker sync.RWMutex

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

	// sequenceBarrier is the data id up to which every socket call of the connection has already been
	// parsed. When it is set (the HTTP/2 per direction views), the reader refuses to continue a message
	// into a following socket call whose previous call has not been seen yet, so a frame is never
	// completed with the bytes of a later call while an earlier one is still missing. 0 disables it.
	sequenceBarrier uint64
	// stopAtTruncation makes the reader return ErrTruncated instead of silently continuing into the
	// next socket call when the current one was truncated by the BPF upload limit
	stopAtTruncation bool
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

func (i *DataIDRange) IsIncludeAllDetails(l *list.List) bool {
	if l.Len() == 0 {
		return false
	}
	for e := l.Front(); e != nil; e = e.Next() {
		if e.Value.(SocketDataDetail).DataID() < i.From || e.Value.(SocketDataDetail).DataID() > i.To {
			return false
		}
	}
	return true
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
	buf.eventLocker.Lock()
	defer buf.eventLocker.Unlock()
	for e := buf.detailEvents.Front(); e != nil; {
		next := e.Next()
		dataID := e.Value.(SocketDataDetail).DataID()
		if dataID >= i.From && dataID <= i.To {
			if !i.IsToBufferReadFinished && dataID == i.To {
				break
			}
			buf.detailEvents.Remove(e)
			log.Debugf("delete detail event from buffer, data id: %d, ref: %p, range: %d-%d(%t)",
				dataID, buf, i.From, i.To, i.IsToBufferReadFinished)
		}
		e = next
	}
}

type Position struct {
	// element of the event list
	element *list.Element
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
		dataEvents:    list.New(),
		detailEvents:  list.New(),
		validated:     false,
		uploadedBytes: make(map[uint64]int64),
	}
}

// NewViewBuffer creates an empty buffer whose detail events are resolved from the original buffer.
// It is used to re-partition the data events of a connection (e.g. per direction) while the
// socket detail events stay in the original buffer.
func NewViewBuffer(original *Buffer) *Buffer {
	return &Buffer{
		dataEvents:       list.New(),
		detailEvents:     list.New(),
		validated:        false,
		originalBuffer:   original,
		uploadedBytes:    make(map[uint64]int64),
		stopAtTruncation: true,
	}
}

// SetSequenceBarrier records the data id up to which every socket call of the connection has been
// parsed, see the field comment. It is reset to 0 by passing 0.
func (r *Buffer) SetSequenceBarrier(dataID uint64) {
	r.sequenceBarrier = dataID
}

// UploadedBytes returns the bytes BPF uploaded for the socket call, 0 when it is not tracked
func (r *Buffer) UploadedBytes(dataID uint64) int64 {
	r.eventLocker.RLock()
	defer r.eventLocker.RUnlock()
	return r.uploadedBytes[dataID]
}

// TakeDataEvents detaches and returns all data events from the buffer (in order) without
// releasing their byte arrays, and resets the reading positions. Detail events are kept.
func (r *Buffer) TakeDataEvents() []SocketDataBuffer {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()
	if r.dataEvents.Len() == 0 {
		return nil
	}
	result := make([]SocketDataBuffer, 0, r.dataEvents.Len())
	for e := r.dataEvents.Front(); e != nil; e = e.Next() {
		if e.Value != nil {
			result = append(result, e.Value.(SocketDataBuffer))
		}
	}
	r.dataEvents = list.New()
	r.uploadedBytes = make(map[uint64]int64)
	r.head = nil
	r.current = nil
	r.shouldResetPosition = false
	return result
}

// ReleaseAll removes every data event of the buffer and gives their pooled byte arrays back, so a
// buffer that is thrown away (a removed connection) does not leak the in-use accounting
func (r *Buffer) ReleaseAll() {
	if r == nil {
		return
	}
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()
	for e := r.dataEvents.Front(); e != nil; {
		next := e.Next()
		if b, ok := e.Value.(SocketDataBuffer); ok && b != nil {
			ReleaseEvent(b.ReleaseBuffer())
		}
		r.dataEvents.Remove(e)
		e = next
	}
	r.uploadedBytes = make(map[uint64]int64)
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

// Clean drops everything the buffer holds. The data events are released rather than only forgotten:
// their buffers come from the pool and the admission control counts them, so dropping the list alone
// would leak one buffer per event until the garbage collector catches up.
func (r *Buffer) Clean() {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	for e := r.dataEvents.Front(); e != nil; e = e.Next() {
		if b, ok := e.Value.(SocketDataBuffer); ok && b != nil {
			ReleaseEvent(b.ReleaseBuffer())
		}
	}
	r.dataEvents = list.New()
	r.detailEvents = list.New()
	r.uploadedBytes = make(map[uint64]int64)
	r.head = nil
	r.current = nil
	r.endPosition = nil
}

// nolint
func (r *Buffer) Slice(validated bool, start, end *Position) *Buffer {
	dataEvents := list.New()
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
		result += r.head.element.Value.(SocketDataBuffer).BufferLen() - startIndex
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
		r.originalBuffer.eventLocker.RLock()
		defer r.originalBuffer.eventLocker.RUnlock()
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
	uploaded := make(map[uint64]int64)
	for e := start.element; e != nil; e = e.Next() {
		buf, ok := e.Value.(SocketDataBuffer)
		if !ok || buf == nil {
			break
		}
		uploaded[buf.DataID()] += int64(buf.BufferLen())
		if end != nil && e == end.element && end.bufIndex < buf.BufferLen() {
			break // the reduced bytes follow the last byte of the element, which is not consumed yet
		}
		if buf.IsFinished() && buf.HaveReduceDataAfterChunk() {
			// the chunks of the socket call before `start` were not walked, so the uploaded bytes of the
			// whole call are taken from the buffer's own accounting when it has them
			total := r.UploadedBytes(buf.DataID())
			if total < uploaded[buf.DataID()] {
				total = uploaded[buf.DataID()]
			}
			if missing := int64(buf.TotalSize()) - total; missing > 0 {
				result += missing
			}
		}
		if end != nil && e == end.element {
			break
		}
	}
	return result
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

func CombineSlices(validated bool, originalBuffer *Buffer, buffers ...*Buffer) *Buffer {
	if len(buffers) == 0 {
		return nil
	}
	if len(buffers) == 1 {
		return buffers[0]
	}
	dataEvents := list.New()
	var virtualBytes int64
	for _, b := range buffers {
		if b == nil || b.head == nil {
			continue
		}
		virtualBytes += b.virtualBytes
		if b.head.bufIndex > 0 {
			headBuffer := b.dataEvents.Front().Value.(SocketDataBuffer)
			dataEvents.PushBack(&SocketDataEventLimited{SocketDataBuffer: headBuffer,
				From: b.head.bufIndex, Size: headBuffer.BufferLen()})
			for next := b.dataEvents.Front().Next(); next != nil; next = next.Next() {
				dataEvents.PushBack(next.Value)
			}
		} else {
			dataEvents.PushBackList(b.dataEvents)
		}
	}

	var endPosition *Position
	for i := len(buffers) - 1; i >= 0; i-- {
		if buffers[i] == nil {
			continue
		}
		if buffers[i].endPosition != nil {
			endPosition = buffers[i].endPosition
			break
		} else if buffers[i].Position() != nil {
			endPosition = buffers[i].Position()
			break
		}
	}
	return &Buffer{
		dataEvents:     dataEvents,
		detailEvents:   emptyList, // for the combined buffer, the details list should be queried from original buffer
		validated:      validated,
		head:           &Position{element: dataEvents.Front(), bufIndex: 0},
		current:        &Position{element: dataEvents.Front(), bufIndex: 0},
		originalBuffer: originalBuffer,
		endPosition:    endPosition,
		virtualBytes:   virtualBytes,
	}
}

func (r *Buffer) Peek(p []byte) (n int, err error) {
	// save the index temporary
	tmpPosition := r.current.Clone()
	// restore the index
	defer func() {
		r.current = tmpPosition
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
	var nextElement func(e *list.Element) *list.Element
	if offset == 0 {
		return r.current.Clone()
	} else if offset > 0 {
		nextElement = func(e *list.Element) *list.Element {
			return e.Next()
		}
	} else {
		nextElement = func(e *list.Element) *list.Element {
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
	element, n := r.ReadFromCurrent(p)
	if n > 0 {
		return n, nil
	}

	curEvent := element.Value.(SocketDataBuffer)
	next := r.nextElement(element)
	if next == nil {
		return 0, io.EOF
	}
	nextEvent := next.Value.(SocketDataBuffer)

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
		if r.stopAtTruncation && curEvent.IsFinished() && curEvent.HaveReduceDataAfterChunk() {
			// BPF did not upload the rest of the current call: the next bytes of the buffer are the
			// bytes of another call, not the continuation of this message
			return 0, ErrTruncated
		}
		if r.sequenceBarrier > 0 && nextEvent.PrevDataID() != curEvent.DataID() &&
			nextEvent.PrevDataID() > r.sequenceBarrier {
			// a socket call between the two has not been delivered yet: completing the message with the
			// bytes of the later call would read across the missing one
			shouldRead = false
		}
	}

	if !shouldRead {
		return 0, ErrNotComplete
	}

	return r.read0(next, nextEvent, p)
}

func (r *Buffer) ReadFromCurrent(p []byte) (element *list.Element, n int) {
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

func (r *Buffer) read0(currentElement *list.Element, currentBuffer SocketDataBuffer, p []byte) (n int, err error) {
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
	if r.dataEvents.Len() == 0 {
		return false
	}
	// if the buffer should reset, then reset the position and cannot be read from current position
	if r.shouldResetPosition {
		r.ResetForLoopReading()
		r.shouldResetPosition = false
		return r.PrepareForReading()
	}
	if r.head != nil && r.head.element != nil && r.isDetached(r.head.element) {
		// the head element was removed from the list (e.g. expired), restart from the first element
		r.head = nil
	}
	if r.head == nil || r.head.element == nil {
		// read in the first element
		r.eventLocker.RLock()
		defer r.eventLocker.RUnlock()
		r.head = &Position{element: r.dataEvents.Front(), bufIndex: 0}
		r.current = r.head.Clone()
	} else {
		// make sure we can read from head
		r.current = r.head.Clone()
	}

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
func (r *Buffer) isDetached(e *list.Element) bool {
	r.eventLocker.RLock()
	defer r.eventLocker.RUnlock()
	return e.Next() == nil && e.Prev() == nil && r.dataEvents.Front() != e
}

// nolint
func (r *Buffer) RemoveReadElements(includeDetails bool) bool {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

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
				log.Debugf("delete detail event from readed buffer, data id: %d, ref: %p", event.DataID(), r)
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
	r.eventLocker.RLock()
	defer r.eventLocker.RUnlock()
	if r.head == nil || r.head.element == nil || r.head.element.Value == nil {
		return nil
	}
	event, _ := r.head.element.Value.(SocketDataBuffer)
	return event
}

// RemoveCurrentElement removes the element the reader head points to (the element the current
// message started in) and moves the head to the next element. It returns true when no element is left.
func (r *Buffer) RemoveCurrentElement() bool {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()
	if r.head == nil || r.head.element == nil {
		return true
	}
	r.head.element = r.removeElement0(r.head.element)
	r.head.bufIndex = 0
	r.current = r.head.Clone()
	return r.head.element == nil
}

// SkipCurrentElement skip current element in reader, if return true means have read finished
func (r *Buffer) SkipCurrentElement() bool {
	r.head.element = r.nextElement(r.current.element)
	r.head.bufIndex = 0
	r.current.bufIndex = 0

	return r.head.element == nil
}

func (r *Buffer) removeElement0(element *list.Element) *list.Element {
	if element == nil {
		return nil
	}
	result := element.Next()
	r.dataEvents.Remove(element)
	if element.Value != nil {
		if b, ok := element.Value.(SocketDataBuffer); ok && b != nil {
			if b.IsFinished() {
				// the socket call is complete, its upload accounting is not needed anymore
				delete(r.uploadedBytes, b.DataID())
			}
			ReleaseEvent(b.ReleaseBuffer())
		}
	}
	return result
}

func (r *Buffer) AppendDetailEvent(event SocketDataDetail) {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

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

// AppendDataEvent insert the event to the event list following the order
func (r *Buffer) AppendDataEvent(event SocketDataBuffer) {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	if r.uploadedBytes == nil {
		r.uploadedBytes = make(map[uint64]int64)
	}
	r.uploadedBytes[event.DataID()] += int64(event.BufferLen())

	defer func() {
		// if the current position is not nil and the current reading data id is bigger than the event data id
		// (the current element is nil once every element has been consumed or removed)
		if r.current != nil && r.current.element != nil && r.current.DataID() > event.DataID() {
			r.shouldResetPosition = true
		}
	}()

	if r.dataEvents.Len() == 0 {
		r.dataEvents.PushFront(event)
		r.shouldResetPosition = true
		return
	}
	if last := r.dataEvents.Back().Value.(SocketDataBuffer); last.DataID() < event.DataID() ||
		(last.DataID() == event.DataID() && last.DataSequence() < event.DataSequence()) ||
		(last.DataID() == event.DataID() && last.DataSequence() == event.DataSequence() && last.StartTime() <= event.StartTime()) {
		r.dataEvents.PushBack(event)
		return
	}
	// out of order events are usually late by a few positions only: search the insertion point from
	// the back (a scan from the front walks the whole list of a busy connection for every late event)
	for element := r.dataEvents.Back(); element != nil; element = element.Prev() {
		if !eventAfter(event, element.Value.(SocketDataBuffer)) {
			continue
		}
		r.dataEvents.InsertAfter(event, element)
		return
	}
	r.dataEvents.PushFront(event)
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
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	expireTime := time.Now().Add(-expireDuration)
	// data event queue
	count := r.deleteEventsWithJudgement(r.dataEvents, func(element *list.Element) bool {
		if element.Value == nil {
			return true
		}
		buffer := element.Value.(SocketDataBuffer)
		startTime := host.Time(buffer.StartTime())
		if expireTime.After(startTime) {
			r.latestExpiredDataID = buffer.DataID()
			delete(r.uploadedBytes, buffer.DataID())
			ReleaseEvent(buffer.ReleaseBuffer())
			return true
		}
		return false
	})

	// detail event queue
	count += r.deleteEventsWithJudgement(r.detailEvents, func(element *list.Element) bool {
		detail, ok := element.Value.(SocketDataDetail)
		if !ok {
			return true
		}
		isDelete := r.latestExpiredDataID > 0 && detail.DataID() <= r.latestExpiredDataID ||
			(detail.Time() > 0 && expireTime.After(host.Time(detail.Time())))
		if isDelete {
			log.Debugf("delete expired detail event, data id: %d, buf: %p", detail.DataID(), r)
		}
		return isDelete
	})
	return count
}

func (r *Buffer) DataLength() int {
	if r == nil {
		return 0
	}
	r.eventLocker.RLock()
	defer r.eventLocker.RUnlock()
	if r.dataEvents == nil {
		return 0
	}
	return r.dataEvents.Len()
}

func (r *Buffer) deleteEventsWithJudgement(l *list.List, checker func(element *list.Element) bool) int {
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

func (r *Buffer) nextElement(e *list.Element) *list.Element {
	if e == nil {
		return nil
	}
	r.eventLocker.RLock()
	defer r.eventLocker.RUnlock()
	return e.Next()
}
