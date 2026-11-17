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
	"strings"
	"testing"
)

// buildFrames puts one event per frame into a connection buffer and returns the buffer together with
// a slice per frame, the way the HTTP/2 reader produces them: a DATA frame is a slice of the
// connection buffer and the body is the concatenation of the slices.
func buildFrames(frames []string) (conn *Buffer, slices []*Buffer) {
	conn = NewBuffer()
	for i, f := range frames {
		conn.AppendDataEvent(&testEvent{dataID: uint64(i + 1), data: []byte(f)})
	}
	conn.PrepareForReading()
	for range frames {
		start := conn.Position()
		if err := conn.ReadUntilBufferFull(make([]byte, len(frames[0]))); err != nil {
			break
		}
		slices = append(slices, conn.Slice(true, start, conn.Position()))
	}
	return conn, slices
}

func readAll(b *Buffer, n int) string {
	if !b.PrepareForReading() {
		return ""
	}
	out := make([]byte, n)
	if err := b.ReadUntilBufferFull(out); err != nil {
		return "ERR:" + err.Error()
	}
	return string(out)
}

// TestAppendSlicesAppendsInPlace: appending one slice at a time, the way a body is assembled frame by
// frame, must give the same content, size and virtual bytes as combining them all at once. The
// incremental path appends onto the buffer it built before instead of copying the whole body again.
func TestAppendSlicesAppendsInPlace(t *testing.T) {
	frames := []string{"aaaa", "bbbb", "cccc", "dddd", "eeee"}
	want := strings.Join(frames, "")

	connA, slicesA := buildFrames(frames)
	var incremental *Buffer
	for i, s := range slicesA {
		before := incremental
		incremental = AppendSlices(true, connA, incremental, s)
		if i > 0 && incremental != before {
			t.Fatalf("frame %d rebuilt the body instead of appending to it", i)
		}
	}

	connB, slicesB := buildFrames(frames)
	atOnce := CombineSlices(true, connB, slicesB...)

	if got := readAll(incremental, len(want)); got != want {
		t.Fatalf("incremental content: got %q want %q", got, want)
	}
	if got := readAll(atOnce, len(want)); got != want {
		t.Fatalf("at once content: got %q want %q", got, want)
	}
	if incremental.DataSize() != atOnce.DataSize() {
		t.Fatalf("size: incremental %d, at once %d", incremental.DataSize(), atOnce.DataSize())
	}
	if incremental.dataEvents.Len() != atOnce.dataEvents.Len() {
		t.Fatalf("elements: incremental %d, at once %d", incremental.dataEvents.Len(), atOnce.dataEvents.Len())
	}
}

// TestCombineSlicesKeepsVirtualBytes: the bytes BPF did not upload are carried by the slice and must
// accumulate on the combined buffer, so a truncated frame still reports the real body size
func TestAppendSlicesKeepsVirtualBytes(t *testing.T) {
	frames := []string{"aaaa", "bbbb", "cccc"}
	conn, slices := buildFrames(frames)
	var body *Buffer
	for _, s := range slices {
		s.AddVirtualBytes(10)
		body = AppendSlices(true, conn, body, s)
	}
	if body.virtualBytes != 30 {
		t.Fatalf("virtual bytes: got %d want 30", body.virtualBytes)
	}
	if size := body.DataSize(); size != int64(len(frames)*4+30) {
		t.Fatalf("size: got %d want %d", size, len(frames)*4+30)
	}
}

// TestAppendSlicesAfterCleanRebuilds: Clean empties the buffer without clearing the stream's
// reference to it, so the next frame must not append onto an empty list with a nil head
func TestAppendSlicesAfterCleanRebuilds(t *testing.T) {
	frames := []string{"aaaa", "bbbb"}
	conn, slices := buildFrames(frames)
	body := AppendSlices(true, conn, nil, slices[0])
	body.Clean()
	body = AppendSlices(true, conn, body, slices[1])
	if got := readAll(body, 4); got != "bbbb" {
		t.Fatalf("after clean: got %q want %q", got, "bbbb")
	}
}

// TestCombineSlicesLeavesItsBuffersAlone: combining the buffers of a stream into the stream's log, as
// the HTTP/2 analyzer does with the header, body and response buffers, must not change any of them. The header
// buffer of an HTTP/2 stream is itself a combination (CombineSlices of the header block); when the
// combination appended onto it in place, its size became the size of the whole stream.
func TestCombineSlicesLeavesItsBuffersAlone(t *testing.T) {
	frames := []string{"head", "body", "resp", "rbdy"}
	conn, slices := buildFrames(frames)
	header := CombineSlices(true, conn, nil, slices[0])
	body := AppendSlices(true, conn, nil, slices[1])
	respHeader := CombineSlices(true, conn, nil, slices[2])
	respBody := AppendSlices(true, conn, nil, slices[3])
	respBody.AddVirtualBytes(100)
	sizes := []int64{header.DataSize(), body.DataSize(), respHeader.DataSize(), respBody.DataSize()}
	total := CombineSlices(true, nil, header, body, respHeader, respBody)
	if got := total.DataSize(); got != 16+100 {
		t.Fatalf("the combination is %d bytes, expected %d", got, 16+100)
	}
	if total == header || total == body {
		t.Fatalf("the combination must be a new buffer")
	}
	for i, b := range []*Buffer{header, body, respHeader, respBody} {
		if b.DataSize() != sizes[i] {
			t.Fatalf("buffer %d changed from %d to %d bytes", i, sizes[i], b.DataSize())
		}
	}
}
