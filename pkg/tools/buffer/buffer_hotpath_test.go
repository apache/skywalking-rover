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
	"reflect"
	"testing"
)

// partiallyRead returns a buffer of the frames whose head sits `offset` bytes into the first event, the
// way RemoveReadElements leaves it after a message that ended inside an event
func partiallyRead(frames []string, offset int) *Buffer {
	b := NewBuffer()
	for i, f := range frames {
		b.AppendDataEvent(&testEvent{dataID: uint64(i + 1), data: []byte(f)})
	}
	b.PrepareForReading()
	if err := b.ReadUntilBufferFull(make([]byte, offset)); err != nil {
		panic(err)
	}
	b.RemoveReadElements(false)
	return b
}

// TestCombinedSocketBuffersMatchesCombineSlices: the events must be exactly those of the combined
// buffer, in order, with the same wrapper of a partially read head, for every shape of input
func TestCombinedSocketBuffersMatchesCombineSlices(t *testing.T) {
	_, slices := buildFrames([]string{"aaaa", "bbbb", "cccc", "dddd"})
	notPrepared := NewBuffer()
	notPrepared.AppendDataEvent(&testEvent{dataID: 9, data: []byte("zz")})
	consumer := NewBodyConsumer(6, nil)
	bodySource := partiallyRead([]string{"xxxxyy", "yyyy"}, 2)
	consumer.Consume(bodySource)

	cases := map[string][]*Buffer{
		"none":               {},
		"all nil":            {nil, nil, nil, nil},
		"single":             {partiallyRead([]string{"abcd", "efgh"}, 1)},
		"single nil":         {nil},
		"slices":             slices,
		"slices with nils":   {slices[0], nil, slices[1], nil},
		"partially read":     {partiallyRead([]string{"abcd", "efgh"}, 3), nil, slices[2], partiallyRead([]string{"ijkl"}, 2)},
		"not prepared":       {notPrepared, slices[3]},
		"only not prepared":  {notPrepared, nil},
		"body consumer body": {slices[0], consumer.Body(bodySource), nil, slices[1]},
	}
	for name, buffers := range cases {
		want := CombineSlices(true, nil, buffers...).TotalBuffer()
		got := CombinedSocketBuffers(buffers...)
		if (want == nil) != (got == nil) || !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: got %v want %v", name, got, want)
		}
		for i := range want {
			if _, limited := want[i].(*SocketDataEventLimited); !limited && want[i] != got[i] {
				t.Fatalf("%s: event %d is not the same event", name, i)
			}
		}
	}
}

// TestCurrentSocketBufferMatchesSlice: the event a Slice at the reading position starts with, unwrapped
func TestCurrentSocketBufferMatchesSlice(t *testing.T) {
	if (*Buffer)(nil).CurrentSocketBuffer() != nil || NewBuffer().CurrentSocketBuffer() != nil {
		t.Fatal("no event expected")
	}
	for _, offset := range []int{0, 2} {
		b := partiallyRead([]string{"abcd", "efgh"}, offset)
		b.PrepareForReading()
		pos := b.Position()
		first := b.Slice(true, pos, pos).FirstSocketBuffer().(*SocketDataEventLimited)
		if got := b.CurrentSocketBuffer(); got != first.SocketDataBuffer {
			t.Fatalf("offset %d: got %v, the slice starts with %v", offset, got, first.SocketDataBuffer)
		}
	}
}

// TestPositionsAreNotShared: the head and the reading position are updated in place now, so a
// position handed out before must not move with them
func TestPositionsAreNotShared(t *testing.T) {
	b := NewBuffer()
	b.AppendDataEvent(&testEvent{dataID: 1, data: []byte("abcd")})
	b.AppendDataEvent(&testEvent{dataID: 2, data: []byte("efgh")})
	b.PrepareForReading()
	start := b.Position()
	peek := make([]byte, 6)
	if n, err := b.Peek(peek); err != nil || n != 6 || string(peek) != "abcdef" {
		t.Fatalf("peek: %d %v %q", n, err, peek)
	}
	if got := b.Position(); got.element != start.element || got.bufIndex != 0 {
		t.Fatal("peek did not restore the position")
	}
	if err := b.ReadUntilBufferFull(make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	if start.DataID() != 1 || start.Offset() != 0 {
		t.Fatal("the handed out position moved with the reader")
	}
	b.PrepareForReading()
	if b.head == b.current || b.Position().Offset() != 0 || b.Position().DataID() != 1 {
		t.Fatal("PrepareForReading did not start over from the head")
	}
	if err := b.ReadUntilBufferFull(make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	if b.head.bufIndex != 0 || b.head.DataID() != 1 {
		t.Fatal("reading moved the head")
	}
}

// TestUploadCounterMatchesMap: the counter answers what the map it replaces answered
func TestUploadCounterMatchesMap(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for round := 0; round < 200; round++ {
		var c uploadCounter
		m := make(map[uint64]int64)
		ids := 1 + rnd.Intn(12)
		for i := 0; i < 50; i++ {
			id, n := uint64(rnd.Intn(ids)), int64(rnd.Intn(100))
			c.add(id, n)
			m[id] += n
			probe := uint64(rnd.Intn(ids + 2))
			if c.get(probe) != m[probe] {
				t.Fatalf("round %d: id %d got %d want %d", round, probe, c.get(probe), m[probe])
			}
		}
	}
}

func TestPooledBufferRoundTrip(t *testing.T) {
	for _, size := range []int{0, 100, 2048, 3000, 8192, MaxEventBufferSize, MaxEventBufferSize + 1} {
		b := TakeBuffer(size)
		want := size
		if want > MaxEventBufferSize {
			want = MaxEventBufferSize
		}
		if len(b) != want || cap(b) != bufferClasses[bufferClassOf(want)] {
			t.Fatalf("size %d: len %d cap %d", size, len(b), cap(b))
		}
		ReleaseBufferOnly(b)
	}
}
