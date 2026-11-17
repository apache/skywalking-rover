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
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

// backSearchInsert is where AppendDataEvent put an event before the finger: behind the last element, searched
// from the back, that the event sorts at or after; -1 for the front
func backSearchInsert(list []SocketDataBuffer, event SocketDataBuffer) int {
	for i := len(list) - 1; i >= 0; i-- {
		if eventAfter(event, list[i]) {
			return i
		}
	}
	return -1
}

// TestFingerInsertLikeBackSearch: the events go where the search from the back put them, for batches delivered
// out of order (several CPUs), ties of data id, sequence and time, and reads and removals in between
func TestFingerInsertLikeBackSearch(t *testing.T) {
	defer withEventSlab(maxEventSlab)()
	rng := rand.New(rand.NewSource(7))
	for round := 0; round < 300; round++ {
		b := NewBuffer()
		var ref []SocketDataBuffer
		next := uint64(1)
		for step := 0; step < 60; step++ {
			switch op := rng.Intn(10); {
			case op < 7:
				// a batch of a CPU: ascending ids from a point behind the newest
				from := next - uint64(rng.Intn(int(next)))
				if from == 0 {
					from = 1
				}
				id := from
				for k := rng.Intn(12) + 1; k > 0; k-- {
					ev := &testEvent{dataID: id, seq: rng.Intn(2), start: uint64(rng.Intn(3)), data: []byte{byte(id), 1}}
					at := backSearchInsert(ref, ev)
					ref = append(ref[:at+1], append([]SocketDataBuffer{ev}, ref[at+1:]...)...)
					b.AppendDataEvent(ev)
					id += uint64(rng.Intn(3))
				}
				if id >= next {
					next = id + 1
				}
			case op < 9 && len(ref) > 0:
				// the analysis reads the head and drops it
				if !b.PrepareForReading() {
					t.Fatal("no data")
				}
				b.RemoveCurrentElement()
				ref = ref[1:]
			default:
				if rng.Intn(3) == 0 {
					taken := b.TakeDataEvents()
					if !reflect.DeepEqual(taken, ref) && (len(taken) != 0 || len(ref) != 0) {
						t.Fatalf("round %d: taken %v", round, taken)
					}
					ref = nil
				}
			}
			got := b.TotalBuffer()
			if len(got) != len(ref) {
				t.Fatalf("round %d step %d: %d events, %d expected", round, step, len(got), len(ref))
			}
			for i := range got {
				if got[i] != ref[i] {
					t.Fatalf("round %d step %d: event %d is %+v, expected %+v", round, step, i, got[i], ref[i])
				}
			}
		}
	}
}

// TestAppendSliceOfLikeAppendSlices: appending a frame through AppendSliceOf gives the body AppendSlices gives
// it with the slice of the frame: the same values in the same wrappers, the same size, virtual bytes and end
func TestAppendSliceOfLikeAppendSlices(t *testing.T) { //nolint:funlen // one randomized equivalence check read top to bottom
	rng := rand.New(rand.NewSource(3))
	for round := 0; round < 2000; round++ {
		src := NewBuffer()
		n := rng.Intn(6) + 2
		for i := 0; i < n; i++ {
			src.AppendDataEvent(&testEvent{dataID: uint64(i + 1), data: []byte(fmt.Sprintf("event-%d-%s", i, string(make([]byte, rng.Intn(8)))))})
		}
		src.PrepareForReading()
		elems := []*eventElement{}
		for e := src.dataEvents.Front(); e != nil; e = e.Next() {
			elems = append(elems, e)
		}
		pos := func(i int) *Position {
			e := elems[i]
			return &Position{element: e, bufIndex: rng.Intn(e.Value.(SocketDataBuffer).BufferLen() + 1)}
		}
		// a body of two frames already (a combined buffer), built the same way twice
		body := func() *Buffer {
			first := src.Slice(true, &Position{element: elems[0]}, &Position{element: elems[0], bufIndex: 2})
			second := src.Slice(true, &Position{element: elems[0], bufIndex: 2}, &Position{element: elems[1], bufIndex: 1})
			return CombineSlices(true, src, first, second)
		}
		i := rng.Intn(n)
		j := i + rng.Intn(n-i)
		start, end := pos(i), pos(j)
		if i == j && start.bufIndex > end.bufIndex {
			start.bufIndex, end.bufIndex = end.bufIndex, start.bufIndex
		}
		virtual := int64(rng.Intn(3)) * 100
		if rng.Intn(10) == 0 && i != j {
			// the start element left the list
			src.lock()
			src.dataEvents.Remove(elems[i])
			src.unlock()
		}
		want := body()
		slice := src.Slice(true, start, end)
		if slice != nil && virtual > 0 {
			slice.AddVirtualBytes(virtual)
		}
		want = AppendSlices(true, src, want, slice)
		got := body()
		if !AppendSliceOf(true, got, src, start, end, virtual) {
			t.Fatalf("round %d: not appended", round)
		}
		if !reflect.DeepEqual(want.TotalBuffer(), got.TotalBuffer()) || want.virtualBytes != got.virtualBytes ||
			want.DataSize() != got.DataSize() || want.endPosition != got.endPosition || want.validated != got.validated ||
			!reflect.DeepEqual(want.head, got.head) || !reflect.DeepEqual(want.current, got.current) {
			t.Fatalf("round %d (%d-%d, %d-%d, virtual %d): %v / %v, expected %v / %v", round, i, j, start.bufIndex,
				end.bufIndex, virtual, got.TotalBuffer(), got.DataSize(), want.TotalBuffer(), want.DataSize())
		}
		for k := range want.TotalBuffer() {
			if reflect.TypeOf(want.TotalBuffer()[k]) != reflect.TypeOf(got.TotalBuffer()[k]) {
				t.Fatalf("round %d: value %d is a %T, expected a %T", round, k, got.TotalBuffer()[k], want.TotalBuffer()[k])
			}
		}
	}
	// onto a slice, the first frame of a body: the combination of the two
	for round := 0; round < 2000; round++ {
		src := NewBuffer()
		n := rng.Intn(6) + 2
		for i := 0; i < n; i++ {
			src.AppendDataEvent(&testEvent{dataID: uint64(i + 1), data: []byte(fmt.Sprintf("frame-%d-%s", i, string(make([]byte, rng.Intn(8)))))})
		}
		src.PrepareForReading()
		elems := []*eventElement{}
		for e := src.dataEvents.Front(); e != nil; e = e.Next() {
			elems = append(elems, e)
		}
		first := src.Slice(true, &Position{element: elems[0], bufIndex: rng.Intn(3)}, &Position{element: elems[0], bufIndex: 3})
		first.AddVirtualBytes(int64(rng.Intn(2)) * 7)
		i := rng.Intn(n)
		j := i + rng.Intn(n-i)
		start := &Position{element: elems[i], bufIndex: rng.Intn(elems[i].Value.(SocketDataBuffer).BufferLen() + 1)}
		end := &Position{element: elems[j], bufIndex: rng.Intn(elems[j].Value.(SocketDataBuffer).BufferLen() + 1)}
		if i == j && start.bufIndex > end.bufIndex {
			start.bufIndex, end.bufIndex = end.bufIndex, start.bufIndex
		}
		virtual := int64(rng.Intn(3)) * 100
		slice := src.Slice(true, start, end)
		if virtual > 0 {
			slice.AddVirtualBytes(virtual)
		}
		original := NewBuffer()
		want := AppendSlices(true, original, first, slice)
		got := CombineSliceOf(true, original, first, src, start, end, virtual)
		if got == nil {
			t.Fatalf("round %d: not combined", round)
		}
		if !reflect.DeepEqual(want.TotalBuffer(), got.TotalBuffer()) || want.virtualBytes != got.virtualBytes ||
			want.DataSize() != got.DataSize() || want.endPosition != got.endPosition || want.validated != got.validated ||
			want.originalBuffer != got.originalBuffer || want.combined != got.combined || want.detailEvents != got.detailEvents ||
			got.head.element != got.dataEvents.Front() || got.current.element != got.dataEvents.Front() ||
			want.head.element != want.dataEvents.Front() || want.current.element != want.dataEvents.Front() ||
			got.head.bufIndex != want.head.bufIndex || got.current.bufIndex != want.current.bufIndex {
			t.Fatalf("round %d (%d-%d): %v / %d, expected %v / %d", round, i, j, got.TotalBuffer(), got.DataSize(),
				want.TotalBuffer(), want.DataSize())
		}
		for k := range want.TotalBuffer() {
			if reflect.TypeOf(want.TotalBuffer()[k]) != reflect.TypeOf(got.TotalBuffer()[k]) {
				t.Fatalf("round %d: value %d is a %T, expected a %T", round, k, got.TotalBuffer()[k], want.TotalBuffer()[k])
			}
		}
	}
	if AppendSliceOf(true, nil, NewBuffer(), nil, nil, 0) || AppendSliceOf(true, NewBuffer(), NewBuffer(), nil, nil, 0) {
		t.Fatal("appended onto a buffer AppendSlices does not append onto in place")
	}
}

// TestSeekInsertLikeBackSearch: in deep lists, where the place of an event is far from the finger and the marks
// find it (seek), the events still go where the search from the back put them: per-CPU batches over long spans,
// ties, reads from the front, removals in the middle and from the back (ReleaseEventsFrom), whole takes
func TestSeekInsertLikeBackSearch(t *testing.T) { //nolint:funlen // one randomized equivalence check read top to bottom
	defer withEventSlab(maxEventSlab)()
	rng := rand.New(rand.NewSource(11))
	marked := 0
	for round := 0; round < 40; round++ {
		b := NewBuffer()
		var ref []SocketDataBuffer
		next := uint64(1)
		for step := 0; step < 400; step++ {
			switch op := rng.Intn(20); {
			case op < 14:
				// a batch of a CPU over a long span behind the newest
				from := next - uint64(rng.Intn(int(next)))
				if from == 0 {
					from = 1
				}
				id, span := from, int(next-from)
				for k := rng.Intn(40) + 1; k > 0; k-- {
					ev := &testEvent{dataID: id, seq: rng.Intn(2), start: uint64(rng.Intn(3)), data: []byte{byte(id), 1}}
					at := backSearchInsert(ref, ev)
					ref = append(ref[:at+1], append([]SocketDataBuffer{ev}, ref[at+1:]...)...)
					b.AppendDataEvent(ev)
					id += uint64(rng.Intn(span/20 + 2))
				}
				if id >= next {
					next = id + 1
				}
			case op < 17 && len(ref) > 0:
				// reads from the front
				for k := rng.Intn(20) + 1; k > 0 && len(ref) > 0; k-- {
					b.removeElement0(b.dataEvents.Front())
					ref = ref[1:]
				}
			case op < 18 && len(ref) > 0:
				// an element in the middle leaves
				i := rng.Intn(len(ref))
				e := b.dataEvents.Front()
				for k := 0; k < i; k++ {
					e = e.Next()
				}
				b.removeElement0(e)
				ref = append(ref[:i], ref[i+1:]...)
			case op < 19 && len(ref) > 0:
				// the back from a data id goes
				from := ref[rng.Intn(len(ref))].DataID()
				b.ReleaseEventsFrom(from)
				for len(ref) > 0 && ref[len(ref)-1].DataID() >= from {
					ref = ref[:len(ref)-1]
				}
			default:
				if rng.Intn(4) == 0 {
					b.TakeDataEvents()
					ref = nil
				}
			}
			got := b.TotalBuffer()
			if len(got) != len(ref) {
				t.Fatalf("round %d step %d: %d events, %d expected", round, step, len(got), len(ref))
			}
			for i := range got {
				if got[i] != ref[i] {
					t.Fatalf("round %d step %d: event %d is %+v, expected %+v", round, step, i, got[i], ref[i])
				}
			}
			// the marks are elements of the list in list order (or left it)
			marked = max(marked, len(b.marks))
			var prev *eventElement
			for _, m := range b.marks {
				if m.list != b.dataEvents {
					continue
				}
				if prev != nil {
					for e := prev; e != m; e = e.Next() {
						if e == nil {
							t.Fatalf("round %d step %d: marks out of list order", round, step)
						}
					}
				}
				prev = m
			}
		}
	}
	if marked < 10 {
		t.Fatalf("the searches planted %d marks at most: the test does not reach seek", marked)
	}
}
