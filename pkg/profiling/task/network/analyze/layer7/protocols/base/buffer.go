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

package base

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var (
	ErrNotComplete = errors.New("socket: not complete event")
)

type Buffer struct {
	events    *list.List
	validated bool // the events list is validated or not

	eventLocker sync.RWMutex

	head    *BufferPosition
	current *BufferPosition
}

type BufferPosition struct {
	// element of the event list
	element *list.Element
	// bufIndex the buffer index of the element
	bufIndex int
}

func (p *BufferPosition) String() string {
	buffer := p.element.Value.(SocketDataBuffer)
	return fmt.Sprintf("data id: %d, sequence: %d, buffer index: %d",
		buffer.DataID(), buffer.DataSequence(), p.bufIndex)
}

func newBuffer() *Buffer {
	return &Buffer{
		events:    list.New(),
		validated: false,
	}
}

func (r *Buffer) Position() *BufferPosition {
	return r.current.Clone()
}

func (r *Buffer) Slice(validated bool, start, end *BufferPosition) *Buffer {
	events := list.New()
	for nextElement := start.element; nextElement != end.element; nextElement = nextElement.Next() {
		events.PushBack(nextElement.Value)
	}
	events.PushBack(&SocketDataEventLimited{end.element.Value.(SocketDataBuffer), 0, end.bufIndex})

	return &Buffer{
		events:    events,
		validated: validated,
		head:      &BufferPosition{element: events.Front(), bufIndex: start.bufIndex},
		current:   &BufferPosition{element: events.Front(), bufIndex: start.bufIndex},
	}
}

func (r *Buffer) Len() int {
	if r.head == nil {
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

func (r *Buffer) FirstSocketBuffer() SocketDataBuffer {
	if r.events.Len() == 0 {
		return nil
	}
	return r.events.Front().Value.(SocketDataBuffer)
}

func (r *Buffer) LastSocketBuffer() SocketDataBuffer {
	if r.events.Len() == 0 {
		return nil
	}
	return r.events.Back().Value.(SocketDataBuffer)
}

// DetectNotSendingLastPosition detect the buffer contains not sending data: the BPF limited socket data count
func (r *Buffer) DetectNotSendingLastPosition() *BufferPosition {
	if r.events.Len() == 0 {
		return nil
	}

	for e := r.events.Front(); e != nil; e = e.Next() {
		buf := e.Value.(SocketDataBuffer)
		// the buffer is sent finished but still have reduced data not send
		if buf.IsFinished() && buf.HaveReduceDataAfterChunk() {
			return &BufferPosition{element: e, bufIndex: buf.BufferLen()}
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
	events := list.New()
	for _, b := range buffers {
		if b.head.bufIndex > 0 {
			headBuffer := b.events.Front().Value.(SocketDataBuffer)
			events.PushBack(&SocketDataEventLimited{headBuffer, b.head.bufIndex, headBuffer.BufferLen()})
			for next := b.events.Front().Next(); next != nil; next = next.Next() {
				events.PushBack(next.Value)
			}
		} else {
			events.PushBackList(b.events)
		}
	}
	return &Buffer{
		events:    events,
		validated: validated,
		head:      &BufferPosition{element: events.Front(), bufIndex: 0},
		current:   &BufferPosition{element: events.Front(), bufIndex: 0},
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

func (r *Buffer) OffsetPosition(offset int) *BufferPosition {
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
	return &BufferPosition{element: curEle, bufIndex: curIndex}
}

func (r *Buffer) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.current == nil || r.current.element == nil {
		return 0, io.EOF
	}
	element, n := r.readFromCurrent(p)
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

func (r *Buffer) readFromCurrent(p []byte) (element *list.Element, n int) {
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

func (r *Buffer) resetForLoopReading() {
	r.head = nil
	r.current = nil
}

func (r *Buffer) prepareForReading() bool {
	if r.events.Len() == 0 {
		return false
	}
	if r.head == nil || r.head.element == nil {
		// read in the first element
		r.eventLocker.RLock()
		defer r.eventLocker.RUnlock()
		r.head = &BufferPosition{element: r.events.Front(), bufIndex: 0}
		r.current = r.head.Clone()
	} else {
		// make sure we can read from head
		r.current = r.head.Clone()
	}

	return true
}

func (r *Buffer) removeReadElements() bool {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	// delete until to current position
	next := r.head.element
	for ; next != nil && next != r.current.element; next = r.removeElement0(next) {
	}
	if next != nil && next.Value.(SocketDataBuffer).BufferLen() == r.current.bufIndex {
		// the last event already read finished, then delete it
		r.head.element = r.removeElement0(next)
		r.head.bufIndex = 0
	} else if next != nil {
		// keep using the latest element
		r.head.element = next
	} else {
		return true
	}
	return false
}

// skipCurrentElement skip current element in reader, if return true means have read finished
func (r *Buffer) skipCurrentElement() bool {
	r.head.element = r.nextElement(r.current.element)
	r.current.bufIndex = 0

	return r.head.element == nil
}

func (r *Buffer) removeElement0(element *list.Element) *list.Element {
	if element == nil {
		return nil
	}
	result := element.Next()
	r.events.Remove(element)
	return result
}

// appendEvent insert the event to the event list following the order
func (r *Buffer) appendEvent(event *SocketDataUploadEvent) {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	if r.events.Len() == 0 {
		r.events.PushFront(event)
		return
	}
	if r.events.Back().Value.(SocketDataBuffer).DataID() < event.DataID() {
		r.events.PushBack(event)
		return
	}
	beenAdded := false
	for element := r.events.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(SocketDataBuffer)
		if existEvent.DataID() > event.DataID() {
			// data id needs order
			beenAdded = true
		} else if existEvent.DataID() == event.DataID() && existEvent.DataSequence() > event.DataSequence() {
			// following the sequence order
			beenAdded = true
		}
		if beenAdded {
			r.events.InsertBefore(event, element)
			break
		}
	}
	if !beenAdded {
		r.events.PushBack(event)
	}
}

func (r *Buffer) deleteExpireEvents(expireDuration time.Duration) int {
	r.eventLocker.Lock()
	defer r.eventLocker.Unlock()

	expireTime := time.Now().Add(-expireDuration)
	count := 0
	for e := r.events.Front(); e != nil; {
		startTime := host.Time(e.Value.(SocketDataBuffer).StartTime())
		if expireTime.After(startTime) {
			count++
			cur := e
			e = e.Next()
			r.events.Remove(cur)
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

func (p *BufferPosition) Clone() *BufferPosition {
	return &BufferPosition{element: p.element, bufIndex: p.bufIndex}
}
