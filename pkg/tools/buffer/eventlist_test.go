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
	"fmt"
	"math/rand"
	"testing"
)

func eventListValues(l *eventList) []int {
	var out []int
	for e := l.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value.(int))
	}
	// the backward walk must see the same list
	i := len(out) - 1
	for e := l.Back(); e != nil; e = e.Prev() {
		if i < 0 || e.Value.(int) != out[i] {
			panic("backward walk differs from the forward walk")
		}
		i--
	}
	return out
}

func stdListValues(l *list.List) []int {
	var out []int
	for e := l.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value.(int))
	}
	return out
}

// TestEventListMatchesContainerList runs the same random operations on an eventList and a container/list
// and compares them after each one, including what a removed (stale) element reads
func TestEventListMatchesContainerList(t *testing.T) {
	for _, slab := range []int{1, 4, maxEventSlab} {
		t.Run(fmt.Sprintf("slab-%d", slab), func(t *testing.T) {
			defer withEventSlab(slab)()
			eventListMatchesContainerList(t)
		})
	}
}

// withEventSlab sets the slab size and returns the restore
func withEventSlab(n int) func() {
	before := int(eventSlab.Load())
	SetEventListSlab(n)
	return func() { SetEventListSlab(before) }
}

func eventListMatchesContainerList(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for round := 0; round < 50; round++ {
		ours, std := newEventList(), list.New()
		var oursElems []*eventElement
		var stdElems []*list.Element
		var removedOurs []*eventElement
		var removedStd []*list.Element
		for op := 0; op < 400; op++ {
			v := op
			switch k := rnd.Intn(10); {
			case k < 4 || len(oursElems) == 0:
				oursElems = append(oursElems, ours.PushBack(v))
				stdElems = append(stdElems, std.PushBack(v))
			case k < 5:
				oursElems = append(oursElems, ours.PushFront(v))
				stdElems = append(stdElems, std.PushFront(v))
			case k < 7:
				i := rnd.Intn(len(oursElems))
				a, b := ours.InsertAfter(v, oursElems[i]), std.InsertAfter(v, stdElems[i])
				if (a == nil) != (b == nil) {
					t.Fatalf("InsertAfter on a removed mark: ours %v, std %v", a, b)
				}
				if a != nil {
					oursElems = append(oursElems, a)
					stdElems = append(stdElems, b)
				}
			case k < 9:
				i := rnd.Intn(len(oursElems))
				if ours.Remove(oursElems[i]) != std.Remove(stdElems[i]) {
					t.Fatalf("Remove returned different values")
				}
				removedOurs = append(removedOurs, oursElems[i])
				removedStd = append(removedStd, stdElems[i])
			default:
				if rnd.Intn(4) == 0 {
					// a replaced list detaches its elements as Remove does (renew)
					for e := std.Front(); e != nil; {
						next := e.Next()
						std.Remove(e)
						e = next
					}
					ours, std = ours.renew(), list.New()
				}
			}
			if got, want := eventListValues(ours), stdListValues(std); fmt.Sprint(got) != fmt.Sprint(want) || ours.Len() != std.Len() {
				t.Fatalf("round %d op %d: ours %v (len %d), std %v (len %d)", round, op, got, ours.Len(), want, std.Len())
			}
			for i := range removedOurs {
				o, s := removedOurs[i], removedStd[i]
				if o.Value != s.Value || (o.Next() == nil) != (s.Next() == nil) || (o.Prev() == nil) != (s.Prev() == nil) {
					t.Fatalf("a removed element reads differently: %v/%v next %v/%v", o.Value, s.Value, o.Next(), s.Next())
				}
			}
		}
	}
}

func appendIDs(b *Buffer, ids ...uint64) {
	for _, id := range ids {
		b.AppendDataEvent(&testEvent{dataID: id, data: []byte{byte(id)}})
	}
}

// TestBufferOutOfOrderInsert: late events go to their data id, across slab boundaries
func TestBufferOutOfOrderInsert(t *testing.T) {
	defer withEventSlab(maxEventSlab)()
	b := NewBuffer()
	appendIDs(b, 5, 1, 3, 2, 9, 4, 8, 6, 7)
	for id := uint64(100); id > 10; id-- {
		appendIDs(b, id)
	}
	ids := dataIDs(b)
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("not sorted at %d: %v", i, ids)
		}
	}
	if len(ids) != 99 {
		t.Fatalf("expected 99 events, got %d", len(ids))
	}
}

// TestBufferRemoveInTheMiddle: removing an element in the middle (through a position that points at
// it) keeps the neighbors linked, and the removed element reads detached with its event
func TestBufferRemoveInTheMiddle(t *testing.T) {
	defer withEventSlab(maxEventSlab)()
	b := NewBuffer()
	appendIDs(b, 1, 2, 3, 4, 5)
	mid := b.dataEvents.Front().Next().Next()
	b.eventLocker.Lock()
	next := b.removeElement0(mid)
	b.eventLocker.Unlock()
	if next == nil || next.Value.(SocketDataBuffer).DataID() != 4 {
		t.Fatalf("the element after the removed one should be 4")
	}
	if fmt.Sprint(dataIDs(b)) != "[1 2 4 5]" {
		t.Fatalf("left %v", dataIDs(b))
	}
	if !b.isDetached(mid) || mid.Value.(SocketDataBuffer).DataID() != 3 {
		t.Fatalf("the removed element must be detached and keep its event")
	}
	// removing it again is a no-op
	b.eventLocker.Lock()
	again := b.removeElement0(mid)
	b.eventLocker.Unlock()
	if again != nil || b.DataLength() != 4 {
		t.Fatalf("a second removal must not change the list")
	}
	// a slice that starts at the removed element restarts from the first linked element
	end := &Position{element: b.dataEvents.Back(), bufIndex: 1}
	s := b.Slice(true, &Position{element: mid}, end)
	if s == nil || len(s.TotalBuffer()) != 4 {
		t.Fatalf("slice from a removed start: %v", s)
	}
}

// TestBufferWraparound: a long lived buffer appends, reads and removes many more events than one slab
// holds, so its elements come from many slabs while earlier ones are released
func TestBufferWraparound(t *testing.T) {
	defer withEventSlab(maxEventSlab)()
	b := NewViewBuffer(NewBuffer())
	p := make([]byte, 1)
	next := uint64(1)
	for round := 0; round < 50; round++ {
		n := 1 + round%(maxEventSlab+3)
		var ids []uint64
		for i := 0; i < n; i++ {
			ids = append(ids, next)
			next++
		}
		if len(ids) > 2 {
			ids[0], ids[1] = ids[1], ids[0] // one late event per round
		}
		appendIDs(b, ids...)
		if !b.PrepareForReading() {
			t.Fatalf("round %d: nothing to read", round)
		}
		var read []byte
		for {
			if _, err := b.Read(p); err != nil {
				break
			}
			read = append(read, p[0])
		}
		if len(read) != n {
			t.Fatalf("round %d: read %d of %d", round, len(read), n)
		}
		for i := 1; i < len(read); i++ {
			if read[i] != read[i-1]+1 {
				t.Fatalf("round %d: out of order %v", round, read)
			}
		}
		if !b.RemoveReadElements(false) && b.DataLength() != 0 {
			t.Fatalf("round %d: %d events left", round, b.DataLength())
		}
		b.ResetForLoopReading()
	}
}

// TestTakeDataEventsKeepsStalePositions: an element of a taken list keeps its event, so a position that
// outlives the take still reads it, but it is detached like a removed element: it links to no neighbor, so
// it keeps no other slab alive, and the new list starts empty in slabs of its own
func TestTakeDataEventsKeepsStalePositions(t *testing.T) {
	defer withEventSlab(maxEventSlab)()
	b := NewBuffer()
	appendIDs(b, 1, 2, 3)
	first := b.dataEvents.Front()
	position := &Position{element: first}
	taken := b.TakeDataEvents()
	if len(taken) != 3 || b.DataLength() != 0 {
		t.Fatalf("took %d, left %d", len(taken), b.DataLength())
	}
	if first.Next() != nil || first.Prev() != nil || first.next != nil || first.prev != nil || first.list != nil {
		t.Fatalf("an element of the taken list is still linked")
	}
	if position.DataID() != 1 || !b.isDetached(first) {
		t.Fatalf("a stale position must still read its event and find its element detached")
	}
	if b.dataEvents.spare != nil {
		t.Fatalf("the new list took over the spare elements of the slab of the taken one")
	}
	appendIDs(b, 4, 5)
	if fmt.Sprint(dataIDs(b)) != "[4 5]" {
		t.Fatalf("after take: %v", dataIDs(b))
	}
	if first.Next() != nil {
		t.Fatalf("a stale element links into the new list")
	}
}

// TestEventListRenewSlab: a list renewed every round takes a first slab as big as the list it replaces, not the
// largest slab the list had grown to, so a round of a few events does not allocate (and drop) a full slab
func TestEventListRenewSlab(t *testing.T) {
	old := eventSlab.Load()
	SetEventListSlab(maxEventSlab)
	defer eventSlab.Store(old)

	for _, c := range []struct{ n, want int }{{0, 4}, {1, 4}, {4, 4}, {5, 8}, {9, 16}, {17, 32}, {32, 32}, {500, 32}} {
		if got := renewSlab(c.n); got != c.want {
			t.Fatalf("renewSlab(%d) = %d, want %d", c.n, got, c.want)
		}
	}

	l := newEventList()
	// grow the slab size to the largest
	for i := 0; i < 200; i++ {
		l.PushBack(i)
	}
	if l.nextSlab != maxEventSlab {
		t.Fatalf("slab size after 200 pushes: %d", l.nextSlab)
	}
	for round := 0; round < 3; round++ {
		l = l.renew()
		if l.nextSlab != minEventSlab && round > 0 {
			t.Fatalf("round %d: first slab %d after a renewed list of 3", round, l.nextSlab)
		}
		for i := 0; i < 3; i++ {
			l.PushBack(i)
		}
		if got := len(l.spare) + l.Len(); round > 0 && got > minEventSlab {
			t.Fatalf("round %d: %d elements allocated for 3 events", round, got)
		}
		if vals := eventListValues(l); len(vals) != 3 || vals[2] != 2 {
			t.Fatalf("round %d: values %v", round, vals)
		}
	}
	// a busy round still gets slabs that grow
	l = l.renew()
	for i := 0; i < 100; i++ {
		l.PushBack(i)
	}
	if l.Len() != 100 || l.nextSlab != maxEventSlab {
		t.Fatalf("busy round: len %d, slab %d", l.Len(), l.nextSlab)
	}
	l = l.renew()
	if l.nextSlab != maxEventSlab {
		t.Fatalf("after a busy round: first slab %d", l.nextSlab)
	}
}
