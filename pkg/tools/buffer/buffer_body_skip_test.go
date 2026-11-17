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
	"fmt"
	"strings"
	"testing"
)

// bodySkippedEvent is an HTTP/1 body call decoded without its bytes: it keeps its length
type bodySkippedEvent struct {
	testEvent
	size int
}

func (e *bodySkippedEvent) BufferData() []byte       { return nil }
func (e *bodySkippedEvent) BufferLen() int           { return e.size }
func (e *bodySkippedEvent) TotalSize() uint64        { return uint64(e.size) }
func (e *bodySkippedEvent) PayloadSkipped() bool     { return true }
func (e *bodySkippedEvent) BodyPayloadSkipped() bool { return true }

func TestReadOfABodySkippedCall(t *testing.T) {
	b := skipTestBuffer(false,
		&testEvent{dataID: 1, data: []byte("0123456789")},
		&bodySkippedEvent{testEvent: testEvent{dataID: 2}, size: 100})
	before := BodySkipConflicts()
	p := make([]byte, 16)
	if _, err := b.Peek(p); !errors.Is(err, ErrPayloadSkipped) {
		t.Fatalf("peek across: %v", err)
	}
	if BodySkipConflicts() != before {
		t.Fatalf("a peek counted as a conflict")
	}
	if n, err := b.Read(p); n != 10 || err != nil {
		t.Fatalf("read the copied call: %d %v", n, err)
	}
	if _, err := b.Read(p); !errors.Is(err, ErrPayloadSkipped) {
		t.Fatalf("read into the skipped call: %v", err)
	}
	if BodySkipConflicts() != before+1 {
		t.Fatalf("conflict not counted")
	}
	// standing inside the skipped call
	b.current.element, b.current.bufIndex = b.current.element.Next(), 40
	if _, err := b.Peek(p); !errors.Is(err, ErrPayloadSkipped) {
		t.Fatalf("peek inside: %v", err)
	}
	if _, err := b.Read(p); !errors.Is(err, ErrPayloadSkipped) || BodySkipConflicts() != before+2 {
		t.Fatalf("read inside: %v", err)
	}
}

// bodyConsumerState is what a user of the consumer observes
func bodyConsumerState(c *BodyConsumer, b *Buffer, done bool) string {
	body := c.Body(b)
	var ids []string
	for _, e := range body.TotalBuffer() {
		ids = append(ids, fmt.Sprintf("%d:%d-%d", e.DataID(), e.BufferStartPosition(), e.BufferStartPosition()+e.BufferLen()))
	}
	head := "end"
	if b.head != nil && b.head.element != nil {
		head = fmt.Sprintf("%d@%d", b.head.element.Value.(SocketDataBuffer).DataID(), b.head.bufIndex)
	}
	return fmt.Sprintf("done=%t remaining=%d size=%d len=%d events=%v head=%s left=%d", done, c.Remaining,
		body.DataSize(), body.Len(), ids, head, b.DataLength())
}

// TestBodyConsumerCountsBodySkippedCalls: a body of copied calls and the same body with calls decoded
// without their bytes are consumed alike, wherever the body ends
func TestBodyConsumerCountsBodySkippedCalls(t *testing.T) {
	sizes := []int{100, 200, 300, 50}
	build := func(skip bool) *Buffer {
		var events []SocketDataBuffer
		for i, size := range sizes {
			id := uint64(i + 1)
			if skip && i > 0 && i < 3 {
				events = append(events, &bodySkippedEvent{testEvent: testEvent{dataID: id}, size: size})
				continue
			}
			data := make([]byte, size)
			for j := range data {
				data[j] = 'a' + byte(j%26)
			}
			events = append(events, &testEvent{dataID: id, data: data})
		}
		return skipTestBuffer(false, events...)
	}
	before := BodySkipConflicts()
	for _, length := range []int64{100, 150, 300, 450, 600, 620, 650, 700} {
		var states [2]string
		for i, skip := range []bool{false, true} {
			b := build(skip)
			c := NewBodyConsumer(length, nil)
			done := c.Consume(b)
			states[i] = bodyConsumerState(c, b, done)
		}
		if states[0] != states[1] {
			t.Fatalf("length %d:\ncopied  %s\nskipped %s", length, states[0], states[1])
		}
	}
	if BodySkipConflicts() != before {
		t.Fatalf("conflicts counted")
	}
}

func TestChunkedBodyGivesUpAtABodySkippedCall(t *testing.T) {
	b := skipTestBuffer(false,
		&testEvent{dataID: 1, data: []byte("5\r\nhello\r\n")},
		&bodySkippedEvent{testEvent: testEvent{dataID: 2}, size: 100})
	before := BodySkipConflicts()
	c := NewChunkedBodyConsumer(nil)
	if !c.Consume(b) || BodySkipConflicts() != before+1 {
		t.Fatalf("the chunked body did not give up")
	}
}

// bpfSkippedEvent is a socket call BPF uploaded without its content (skip_http1_body_payload_bpf): it has
// no bytes at all, only its size
type bpfSkippedEvent struct {
	testEvent
	size int
}

func (e *bpfSkippedEvent) BufferData() []byte   { return nil }
func (e *bpfSkippedEvent) BufferLen() int       { return 0 }
func (e *bpfSkippedEvent) TotalSize() uint64    { return uint64(e.size) }
func (e *bpfSkippedEvent) PayloadSkipped() bool { return true }

// TestBodyConsumerCountsBPFSkippedCalls: a body of copied calls and the same body with calls BPF uploaded
// without their content are consumed alike, the skipped calls kept as calls of the body (their kernel log
// details), when the body ends where BPF framed it (behind a skipped call, or inside a copied one)
func TestBodyConsumerCountsBPFSkippedCalls(t *testing.T) {
	sizes := []int{100, 200, 300, 50}
	build := func(skip bool) *Buffer {
		var events []SocketDataBuffer
		for i, size := range sizes {
			id := uint64(i + 1)
			if skip && i > 0 && i < 3 {
				events = append(events, &bpfSkippedEvent{testEvent: testEvent{dataID: id}, size: size})
				continue
			}
			data := make([]byte, size)
			for j := range data {
				data[j] = 'a' + byte(j%26)
			}
			events = append(events, &testEvent{dataID: id, data: data})
		}
		return skipTestBuffer(false, events...)
	}
	state := func(c *BodyConsumer, b *Buffer, done bool) string {
		body := c.Body(b)
		var ids []uint64
		for _, e := range body.TotalBuffer() {
			ids = append(ids, e.DataID())
		}
		head := "end"
		if b.head != nil && b.head.element != nil {
			head = fmt.Sprintf("%d@%d", b.head.element.Value.(SocketDataBuffer).DataID(), b.head.bufIndex)
		}
		return fmt.Sprintf("done=%t remaining=%d size=%d events=%v head=%s left=%d", done, c.Remaining,
			body.DataSize(), ids, head, b.DataLength())
	}
	before := BodySkipConflicts()
	for _, length := range []int64{50, 100, 300, 600, 620, 650, 700} {
		var states [2]string
		for i, skip := range []bool{false, true} {
			b := build(skip)
			c := NewBodyConsumer(length, nil)
			done := c.Consume(b)
			states[i] = state(c, b, done)
		}
		if states[0] != states[1] {
			t.Fatalf("length %d:\ncopied  %s\nskipped %s", length, states[0], states[1])
		}
	}
	// a body that ends inside a skipped call was framed otherwise than BPF framed it: given up, the call left
	// for the next message
	b := build(true)
	c := NewBodyConsumer(200, nil)
	if !c.Consume(b) || c.Remaining != 0 || c.Body(b).DataSize() != 200 {
		t.Fatalf("not given up: %s", state(c, b, true))
	}
	if b.head == nil || b.head.element.Value.(SocketDataBuffer).DataID() != 2 {
		t.Fatalf("the skipped call is not left: %s", state(c, b, true))
	}
	// a chunked body is never skipped by BPF: given up as well
	b = build(true)
	c = NewChunkedBodyConsumer(nil)
	b.current.element = b.current.element.Next()
	if !c.Consume(b) {
		t.Fatalf("the chunked body is not given up")
	}
	if BodySkipConflicts() != before {
		t.Fatalf("conflicts counted")
	}
}

// TestChunkedBodyCountsBPFSkippedChunkData: a chunked body whose chunk data calls BPF uploaded without their
// content is consumed as the same body with every call copied: the same size, the same calls
func TestChunkedBodyCountsBPFSkippedChunkData(t *testing.T) {
	// "a\r\n" + 10 bytes of data in two calls (4 + 6) + "\r\n" "3;x=y\r\n" + "abc" + "\r\n0\r\nT: 1\r\n\r\n"
	calls := []string{"a\r\n", "0123", "456789", "\r\n3;x=y\r\n", "abc", "\r\n0\r\nT: 1\r\n\r\n"}
	skippable := map[int]bool{1: true, 2: true, 4: true}
	state := func(skip bool) string {
		var events []SocketDataBuffer
		for i, c := range calls {
			id := uint64(i + 1)
			if skip && skippable[i] {
				events = append(events, &bpfSkippedEvent{testEvent: testEvent{dataID: id}, size: len(c)})
				continue
			}
			events = append(events, &testEvent{dataID: id, data: []byte(c)})
		}
		b := skipTestBuffer(false, events...)
		c := NewChunkedBodyConsumer(nil)
		done := c.Consume(b)
		body := c.Body(b)
		var ids []uint64
		for _, e := range body.TotalBuffer() {
			ids = append(ids, e.DataID())
		}
		return fmt.Sprintf("done=%t aborted=%t size=%d events=%v left=%d", done, c.aborted, body.DataSize(), ids, b.DataLength())
	}
	copied, skipped := state(false), state(true)
	if copied != skipped || !strings.Contains(copied, "size=13") {
		t.Fatalf("\ncopied  %s\nskipped %s", copied, skipped)
	}
}
