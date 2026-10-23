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
	"container/list"
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// MetadataCopier is implemented by socket data events that can produce a copy of themselves without the
// data buffer: the copy keeps every metadata field (data id, times, sizes, direction, ...) so it can
// still serve as a kernel log detail, while the 20KB buffer of the original is released.
type MetadataCopier interface {
	CopyMetadata() SocketDataBuffer
}

// SetPosition moves the reading position (the head is unchanged)
func (r *Buffer) SetPosition(pos *Position) {
	if pos != nil {
		r.current = pos.Clone()
	}
}

// BodyConsumer consumes the body of a message whose length is known (Content-Length) as its socket
// data arrives, so the events are released immediately instead of being held until the whole message
// is complete. The consumed events are kept as metadata-only copies (see MetadataCopier) for the kernel
// log details and the sizes.
type BodyConsumer struct {
	Remaining int64 // body bytes still to consume (Content-Length mode)
	events    []SocketDataBuffer
	uploaded  map[uint64]int64 // uploaded bytes per data id, to account truncated socket calls
	virtual   int64            // body bytes the kernel transferred but BPF did not upload

	// direction of the message the body belongs to; data of the other direction can never be part of
	// the body, so reaching it means an event of this direction was lost and the body is given up
	direction enums.SocketDataDirection
	// aborted is set when the body was given up (the data of the body cannot be followed anymore)
	aborted bool

	// chunked transfer encoding: the framing is parsed as the bytes arrive
	chunked        bool
	chunkState     chunkState
	chunkRemaining int64  // data bytes left in the current chunk
	chunkLine      []byte // the chunk-size or trailer line being read
	chunkCRLF      int    // CRLF bytes consumed after the chunk data
	dataBytes      int64  // chunk data bytes consumed (the reported body size)
	done           bool
}

type chunkState int

const (
	chunkSizeLine chunkState = iota // reading the chunk-size line
	chunkData                       // reading chunk data
	chunkDataCRLF                   // reading the CRLF after the chunk data
	chunkTrailers                   // reading the trailer lines after the last chunk
)

// maxChunkLineLength bounds a chunk-size / trailer line; longer lines are not valid chunked framing
const maxChunkLineLength = 4096

// NewChunkedBodyConsumer starts consuming a body with chunked transfer encoding; the body is complete
// after the last chunk and the trailers. The reported size is the number of chunk data bytes.
func NewChunkedBodyConsumer(before *Buffer) *BodyConsumer {
	c := NewBodyConsumer(0, before)
	c.chunked = true
	return c
}

// NewBodyConsumer starts consuming a body of `length` bytes. `before` are the events that carried the
// bytes of the same message before the body (the headers): their uploaded bytes count towards the
// truncation accounting of the socket calls they belong to.
func NewBodyConsumer(length int64, before *Buffer) *BodyConsumer {
	c := &BodyConsumer{Remaining: length, uploaded: make(map[uint64]int64)}
	if before != nil {
		for _, e := range before.TotalBuffer() {
			c.uploaded[e.DataID()] += int64(e.BufferLen())
			c.direction = e.Direction()
		}
	}
	return c
}

// uploadedBytesOf returns the bytes BPF uploaded for the whole socket call the event belongs to. The
// buffer counts them while the events are appended, which is exact even when the message starts in a
// later chunk of the call; the consumer's own accounting is only the fallback.
func (c *BodyConsumer) uploadedBytesOf(r *Buffer, ev SocketDataBuffer) int64 {
	if v := r.UploadedBytes(ev.DataID()); v > c.uploaded[ev.DataID()] {
		return v
	}
	return c.uploaded[ev.DataID()]
}

// abort gives the body up: the bytes that were never seen are reported as transferred but not
// uploaded, so the message is still reported with the size its framing announced
func (c *BodyConsumer) abort() {
	c.aborted = true
	if c.Remaining > 0 {
		c.virtual += c.Remaining
		c.Remaining = 0
	}
	c.done = true
}

// isOtherDirection reports whether the event cannot belong to the body because it is data of the
// opposite direction of the connection
func (c *BodyConsumer) isOtherDirection(ev SocketDataBuffer) bool {
	return c.direction != 0 && ev.Direction() != 0 && ev.Direction() != c.direction
}

// Consume reads from the buffer's current position until the body is complete or the buffer runs out
// of data. Fully consumed events are removed from the buffer (and their pooled buffer released); the
// head and the current position end up at the first unconsumed byte. It returns true when the body is
// complete.
func (c *BodyConsumer) Consume(r *Buffer) bool {
	if c.chunked {
		return c.consumeChunked(r)
	}
	for c.Remaining > 0 {
		if r.current == nil || r.current.element == nil {
			return false
		}
		element := r.current.element
		ev, ok := element.Value.(SocketDataBuffer)
		if !ok || ev == nil {
			return false
		}
		if c.isOtherDirection(ev) {
			// an event of this message was lost: the next data on the connection belongs to the other
			// direction, consuming it as body would desynchronize the parser for the whole connection
			log.Debugf("give up the pending body, the next event belongs to the other direction, data id: %d", ev.DataID())
			c.abort()
			return true
		}
		from := r.current.bufIndex
		avail := int64(ev.BufferLen() - from)
		if avail < 0 {
			avail = 0
		}
		take := avail
		if take > c.Remaining {
			take = c.Remaining
		}
		to := from + int(take)
		c.Remaining -= take
		c.uploaded[ev.DataID()] += take
		c.keep(ev, from, to)
		if to < ev.BufferLen() {
			// the body ends inside this event, the rest belongs to the next message
			r.current.bufIndex = to
			r.head = r.current.Clone()
			return c.Remaining <= 0
		}
		// the event is fully consumed: account a truncated socket call, then release the event
		if ev.IsFinished() && ev.HaveReduceDataAfterChunk() {
			if missing := int64(ev.TotalSize()) - c.uploadedBytesOf(r, ev); missing > 0 {
				if missing > c.Remaining {
					missing = c.Remaining
				}
				c.Remaining -= missing
				c.virtual += missing
			}
		}
		r.eventLocker.Lock()
		next := r.removeElement0(element)
		r.head = &Position{element: next, bufIndex: 0}
		r.current = r.head.Clone()
		r.eventLocker.Unlock()
	}
	return true
}

// consumeChunked parses the chunked framing from the current position, releasing fully consumed
// events; it returns true when the last chunk and the trailers were consumed
func (c *BodyConsumer) consumeChunked(r *Buffer) bool {
	for !c.done {
		if r.current == nil || r.current.element == nil {
			return false
		}
		element := r.current.element
		ev, ok := element.Value.(SocketDataBuffer)
		if !ok || ev == nil {
			return false
		}
		if c.isOtherDirection(ev) {
			log.Debugf("give up the pending chunked body, the next event belongs to the other direction, data id: %d", ev.DataID())
			c.abort()
			return true
		}
		from := r.current.bufIndex
		to := c.parseChunked(ev.BufferData(), from)
		c.uploaded[ev.DataID()] += int64(to - from)
		c.keep(ev, from, to)
		if to < ev.BufferLen() {
			r.current.bufIndex = to
			r.head = r.current.Clone()
			return c.done
		}
		// the event is fully consumed: a truncated socket call loses bytes of the framing or data
		if ev.IsFinished() && ev.HaveReduceDataAfterChunk() {
			if missing := int64(ev.TotalSize()) - c.uploadedBytesOf(r, ev); missing > 0 {
				if c.chunkState == chunkData && missing < c.chunkRemaining {
					c.chunkRemaining -= missing
					c.virtual += missing
				} else {
					// the framing after the lost bytes cannot be parsed: end the body at the lost bytes
					c.virtual += missing
					c.done = true
				}
			}
		}
		r.eventLocker.Lock()
		next := r.removeElement0(element)
		r.head = &Position{element: next, bufIndex: 0}
		r.current = r.head.Clone()
		r.eventLocker.Unlock()
	}
	return true
}

// parseChunked walks the chunked framing in data[from:] and returns the index up to which the data was
// consumed (len(data) unless the body ended inside it)
func (c *BodyConsumer) parseChunked(data []byte, from int) int {
	i := from
	for i < len(data) && !c.done {
		switch c.chunkState {
		case chunkSizeLine, chunkTrailers:
			j := indexByteFrom(data, i, '\n')
			if j < 0 {
				c.chunkLine = append(c.chunkLine, data[i:]...)
				i = len(data)
				if len(c.chunkLine) > maxChunkLineLength {
					c.done = true // not chunked framing after all, give up on the body
				}
				continue
			}
			line := append(c.chunkLine, data[i:j]...)
			c.chunkLine = c.chunkLine[:0]
			i = j + 1
			line = bytes.TrimRight(line, "\r")
			if c.chunkState == chunkTrailers {
				if len(line) == 0 {
					c.done = true // the empty line after the trailers ends the body
				}
				continue
			}
			if k := bytes.IndexByte(line, ';'); k >= 0 { // chunk extensions
				line = line[:k]
			}
			size, err := strconv.ParseInt(strings.TrimSpace(string(line)), 16, 64)
			if err != nil || size < 0 {
				c.done = true // invalid framing, give up on the body
				continue
			}
			if size == 0 {
				c.chunkState = chunkTrailers
			} else {
				c.chunkRemaining = size
				c.chunkState = chunkData
			}
		case chunkData:
			take := int64(len(data) - i)
			if take > c.chunkRemaining {
				take = c.chunkRemaining
			}
			c.dataBytes += take
			c.chunkRemaining -= take
			i += int(take)
			if c.chunkRemaining == 0 {
				c.chunkState = chunkDataCRLF
				c.chunkCRLF = 0
			}
		case chunkDataCRLF:
			// the CRLF after the chunk data (a bare LF is tolerated)
			if data[i] == '\n' || c.chunkCRLF == 1 {
				c.chunkState = chunkSizeLine
			}
			c.chunkCRLF++
			i++
		}
	}
	return i
}

func indexByteFrom(data []byte, from int, b byte) int {
	if k := bytes.IndexByte(data[from:], b); k >= 0 {
		return from + k
	}
	return -1
}

func (c *BodyConsumer) keep(ev SocketDataBuffer, from, to int) {
	if to <= from {
		return
	}
	var meta SocketDataBuffer = ev
	if copier, ok := ev.(MetadataCopier); ok {
		meta = copier.CopyMetadata()
	}
	if from > 0 || to < ev.BufferLen() {
		meta = &SocketDataEventLimited{SocketDataBuffer: meta, From: from, Size: to}
	}
	c.events = append(c.events, meta)
}

// Body builds the body buffer of the consumed message: a slice-like buffer over the metadata copies
// whose details resolve from `original` (the connection buffer), with the real body size.
func (c *BodyConsumer) Body(original *Buffer) *Buffer {
	if len(c.events) == 0 {
		// nothing of the body was uploaded (it fell entirely into the truncated part of a socket call):
		// a buffer without events would make LastSocketBuffer()/FirstSocketBuffer() nil for the callers
		return nil
	}
	dataEvents := list.New()
	for _, e := range c.events {
		dataEvents.PushBack(e)
	}
	b := &Buffer{
		dataEvents:     dataEvents,
		detailEvents:   emptyList,
		validated:      true,
		originalBuffer: original,
		virtualBytes:   c.virtual,
	}
	if c.chunked {
		// the kept ranges include the chunk framing: report the data bytes (plus the lost ones)
		b.sizeOverride = c.dataBytes + c.virtual
	}
	b.head = &Position{element: dataEvents.Front(), bufIndex: 0}
	b.current = b.head.Clone()
	b.endPosition = &Position{element: dataEvents.Back(), bufIndex: dataEvents.Back().Value.(SocketDataBuffer).BufferLen()}
	return b
}
