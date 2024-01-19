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
	"io"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var (
	ErrNotComplete = errors.New("socket: not complete event")
)

type SocketDataBuffer interface {
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
}

type SocketDataDetail interface {
	// DataID data id of the buffer
	DataID() uint64
}

type Buffer struct {
	dataEvents   *list.List
	detailEvents *list.List
	validated    bool // the events list is validated or not

	eventLocker sync.RWMutex

	head    *Position
	current *Position

	// record the latest expired data id in connection for expire the older socket detail
	// because the older socket detail may not be received in buffer
	latestExpiredDataID uint64
}

type SocketDataEventLimited struct {
	SocketDataBuffer
	From int
	Size int
}

func (s *SocketDataEventLimited) BufferData() []byte {
	return s.SocketDataBuffer.BufferData()[s.From:s.Size]
}

func (s *SocketDataEventLimited) BufferLen() int {
	return s.Size - s.From
}

func (s *SocketDataEventLimited) BufferStartPosition() int {
	return s.From
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

func (p *Position) DataID() uint64 {
	return p.element.Value.(SocketDataBuffer).DataID()
}

func (p *Position) Seq() int {
	return p.element.Value.(SocketDataBuffer).DataSequence()
}

func NewBuffer() *Buffer {
	return &Buffer{
		dataEvents:   list.New(),
		detailEvents: list.New(),
		validated:    false,
	}
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

func (r *Buffer) Position() *Position {
	return r.current.Clone()
}

func (r *Buffer) Clean() {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	r.dataEvents = list.New()
	r.detailEvents = list.New()
	r.head = nil
	r.current = nil
}

func (r *Buffer) Slice(validated bool, start, end *Position) *Buffer {
	dataEvents := list.New()
	detailEvents := list.New()
	var firstDetailElement *list.Element
	for nextElement := start.element; nextElement != end.element; nextElement = nextElement.Next() {
		if nextElement == nil {
			break
		}
		// found first matches detail event
		if detailEvents.Len() == 0 || firstDetailElement == nil {
			for e := r.detailEvents.Front(); e != nil; e = e.Next() {
				if e.Value.(SocketDataDetail).DataID() >= nextElement.Value.(SocketDataBuffer).DataID() {
					detailEvents.PushBack(e.Value)
					firstDetailElement = e
					break
				}
			}
		}
		dataEvents.PushBack(nextElement.Value)
	}
	lastBuffer := end.element.Value.(SocketDataBuffer)
	dataEvents.PushBack(&SocketDataEventLimited{SocketDataBuffer: lastBuffer, Size: end.bufIndex})

	// if the first detail element been found, append the details until the last buffer data id
	if firstDetailElement == nil {
		for e := r.detailEvents.Front(); e != nil; e = e.Next() {
			if e.Value.(SocketDataDetail).DataID() == lastBuffer.DataID() {
				detailEvents.PushBack(e.Value)
				break
			}
		}
	} else if firstDetailElement != nil && firstDetailElement.Value.(SocketDataDetail).DataID() != lastBuffer.DataID() {
		for tmp := firstDetailElement.Next(); tmp != nil; tmp = tmp.Next() {
			if tmp.Value.(SocketDataDetail).DataID() > lastBuffer.DataID() {
				break
			}
			detailEvents.PushBack(tmp.Value)
		}
	}

	return &Buffer{
		dataEvents:   dataEvents,
		detailEvents: detailEvents,
		validated:    validated,
		head:         &Position{element: dataEvents.Front(), bufIndex: start.bufIndex},
		current:      &Position{element: dataEvents.Front(), bufIndex: start.bufIndex},
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

func (r *Buffer) Details() *list.List {
	return r.detailEvents
}

func (r *Buffer) DataSize() int64 {
	if r == nil {
		return 0
	}
	var result int64
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
	if r.dataEvents == nil || r.dataEvents.Len() == 0 {
		return nil
	}
	return r.dataEvents.Front().Value.(SocketDataBuffer)
}

func (r *Buffer) LastSocketBuffer() SocketDataBuffer {
	if r.dataEvents.Len() == 0 {
		return nil
	}
	return r.dataEvents.Back().Value.(SocketDataBuffer)
}

// DetectNotSendingLastPosition detect the buffer contains not sending data: the BPF limited socket data count
func (r *Buffer) DetectNotSendingLastPosition() *Position {
	if r.dataEvents.Len() == 0 {
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

func CombineSlices(validated bool, buffers ...*Buffer) *Buffer {
	if len(buffers) == 0 {
		return nil
	}
	if len(buffers) == 1 {
		return buffers[0]
	}
	dataEvents := list.New()
	detailEvents := list.New()
	for _, b := range buffers {
		if b == nil {
			continue
		}
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
		detailEvents.PushBackList(b.detailEvents)
	}

	return &Buffer{
		dataEvents:   dataEvents,
		detailEvents: detailEvents,
		validated:    validated,
		head:         &Position{element: dataEvents.Front(), bufIndex: 0},
		current:      &Position{element: dataEvents.Front(), bufIndex: 0},
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
	reduceLen := len(data)
	currentIndex := 0
	for reduceLen > 0 {
		readCount, err := r.Read(data[:reduceLen])
		if err != nil {
			return err
		}
		reduceLen -= readCount
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

// nolint
func (r *Buffer) RemoveReadElements() bool {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	// delete until the last data id
	if r.head.element != nil && r.current.element != nil {
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

// SkipCurrentElement skip current element in reader, if return true means have read finished
func (r *Buffer) SkipCurrentElement() bool {
	r.head.element = r.nextElement(r.current.element)
	r.current.bufIndex = 0

	return r.head.element == nil
}

func (r *Buffer) removeElement0(element *list.Element) *list.Element {
	if element == nil {
		return nil
	}
	result := element.Next()
	r.dataEvents.Remove(element)
	return result
}

func (r *Buffer) AppendDetailEvent(event SocketDataDetail) {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	if r.detailEvents.Len() == 0 {
		r.detailEvents.PushFront(event)
		return
	}
	if r.detailEvents.Back().Value.(SocketDataDetail).DataID() < event.DataID() {
		r.detailEvents.PushBack(event)
		return
	}
	beenAdded := false
	for element := r.detailEvents.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(SocketDataDetail)
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

	if r.dataEvents.Len() == 0 {
		r.dataEvents.PushFront(event)
		return
	}
	if r.dataEvents.Back().Value.(SocketDataBuffer).DataID() < event.DataID() {
		r.dataEvents.PushBack(event)
		return
	}
	beenAdded := false
	for element := r.dataEvents.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(SocketDataBuffer)
		if existEvent.DataID() > event.DataID() {
			// data id needs order
			beenAdded = true
		} else if existEvent.DataID() == event.DataID() && existEvent.DataSequence() > event.DataSequence() {
			// following the sequence order
			beenAdded = true
		}
		if beenAdded {
			r.dataEvents.InsertBefore(event, element)
			break
		}
	}
	if !beenAdded {
		r.dataEvents.PushBack(event)
	}
}

func (r *Buffer) DeleteExpireEvents(expireDuration time.Duration) int {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	expireTime := time.Now().Add(-expireDuration)
	// data event queue
	count := r.deleteEventsWithJudgement(r.dataEvents, func(element *list.Element) bool {
		buffer := element.Value.(SocketDataBuffer)
		startTime := host.Time(buffer.StartTime())
		if expireTime.After(startTime) {
			r.latestExpiredDataID = buffer.DataID()
			return true
		}
		return false
	})

	// detail event queue
	count += r.deleteEventsWithJudgement(r.detailEvents, func(element *list.Element) bool {
		return r.latestExpiredDataID > 0 && element.Value.(SocketDataDetail).DataID() <= r.latestExpiredDataID
	})
	return count
}

func (r *Buffer) DataLength() int {
	if r.dataEvents == nil {
		return 0
	}
	return r.dataEvents.Len()
}

func (r *Buffer) DetailLength() int {
	if r.detailEvents == nil {
		return 0
	}
	return r.detailEvents.Len()
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
