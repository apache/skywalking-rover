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
	"sync/atomic"
)

// eventList is the list of the data events of a Buffer: container/list with the same semantics, element
// for element, except for where its elements come from.
//
// container/list allocates one element per insertion, and every socket data event is inserted at least
// twice (the connection buffer, then the per direction view of the HTTP/2 analyzer), which made the
// element the most allocated object of the agent. eventList carves its elements out of slabs instead:
// one allocation serves up to maxEventSlab insertions.
//
// Only the lists the events are appended to one by one (AppendDataEvent) take slabs, and only when
// SetEventListSlab allows it: an element removed from such a list keeps its event (see below), and a slab
// is kept alive by any of its elements, so an event that embeds its data array (the rover events) would
// keep 20KB alive per removed sibling. The default, 1, allocates every such element on its own, as
// container/list does. A list built at once (a slice, a combination, a body) is never removed from
// element by element and always takes its elements in one allocation (reserve).
//
// An element is never reused, not even after it is removed: a Position (the end position of a slice, a
// position handed to the protocol analyzer) can outlive the removal of its element and still read the
// event through it, and must find the element detached (Next and Prev nil) rather than linked into the
// list again. So a removed element stays what container/list leaves behind: its Value, no neighbors, no
// list. The cost of the slab is only that a slab is kept alive by any of its elements still referenced,
// with the (small, metadata) event values of its removed elements; maxEventSlab bounds that.
//
// That bound only holds while a removed element links to nothing: an element that still pointed at its
// neighbors would keep their slabs alive, and theirs, the whole history of the connection behind one
// position. So a list that is replaced (renew) detaches its elements like Remove does, and a slab is never
// shared by two lists: the spare elements of a replaced list are dropped with it, not handed on.
type eventList struct {
	root eventElement // sentinel list element, only &root, root.prev, and root.next are used
	len  int

	// spare are elements not handed out yet, taken from the front
	spare []eventElement
	// nextSlab is the size of the next slab: slabs grow from minEventSlab to maxEventSlab, so a short
	// list (a slice of a message) does not take a full slab
	nextSlab int
}

const (
	minEventSlab = 4
	maxEventSlab = 32
)

// eventSlab is the largest slab an appended-to list takes, see eventList; 1 disables the slabs
var eventSlab atomic.Int32

func init() {
	eventSlab.Store(1)
}

// SetEventListSlab sets how many elements of the data event list of a buffer one allocation serves at
// most (capped at 32): for socket data events that hold their data in a pooled buffer, so an event kept
// alive after its release is only its metadata. 1, the default, allocates every element on its own.
func SetEventListSlab(n int) {
	if n < 1 {
		n = 1
	}
	if n > maxEventSlab {
		n = maxEventSlab
	}
	eventSlab.Store(int32(n))
}

// eventElement is an element of an eventList, container/list.Element for the data events
type eventElement struct {
	next, prev *eventElement
	list       *eventList
	Value      interface{}

	// keyID is the data id of the event, kept in the element by AppendDataEvent (0: not kept, read from the
	// event), so the search for the place of an out of order event compares the elements it walks over without
	// loading their events, but for the ones of the same data id
	keyID uint64
}

// eventKey is the order of the data events of a buffer: by data id, then sequence, then start time
type eventKey struct {
	id    uint64
	start uint64
	seq   int
}

func keyOf(event SocketDataBuffer) eventKey {
	return eventKey{id: event.DataID(), seq: event.DataSequence(), start: event.StartTime()}
}

// before tells whether the event of key a sorts before the event of key b
func (a *eventKey) before(b *eventKey) bool {
	if a.id != b.id {
		return a.id < b.id
	}
	if a.seq != b.seq {
		return a.seq < b.seq
	}
	return a.start < b.start
}

// setKey keeps the data id of the element's event in the element
func (e *eventElement) setKey(k *eventKey) {
	e.keyID = k.id
}

// atOrBefore tells whether the element's event sorts at or before the key: eventAfter(event of the key, element's)
func (e *eventElement) atOrBefore(k *eventKey) bool {
	if e.keyID != 0 && e.keyID != k.id {
		return e.keyID < k.id
	}
	ev := e.Value.(SocketDataBuffer)
	if id := ev.DataID(); id != k.id {
		return id < k.id
	}
	if seq := ev.DataSequence(); seq != k.seq {
		return seq < k.seq
	}
	return ev.StartTime() <= k.start
}

// Next returns the next list element or nil.
func (e *eventElement) Next() *eventElement {
	if p := e.next; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

// Prev returns the previous list element or nil.
func (e *eventElement) Prev() *eventElement {
	if p := e.prev; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

func newEventList() *eventList {
	return new(eventList).init()
}

// lazyInit lazily initializes a zero eventList value.
func (l *eventList) lazyInit() {
	if l.root.next == nil {
		l.init()
	}
}

func (l *eventList) init() *eventList {
	l.root.next = &l.root
	l.root.prev = &l.root
	l.len = 0
	return l
}

// renew returns a new empty list to replace l (TakeDataEvents, Clean). Every element of l is detached as
// Remove detaches it (its Value stays, its neighbors and its list go), so a position that outlives the
// replacement finds its element removed, and an element still referenced keeps only its own slab alive,
// not the slabs of the elements it was linked to. The new list does not take the spare elements of l: they
// are in a slab of l, which would then be shared by the elements of both lists.
//
// Its first slab is as big as l was (renewSlab): a list renewed every analysis round (the connection buffer of
// the HTTP/2 analyzer, TakeDataEvents) holds the few events of one round, and a first slab of the size l had
// grown to (the largest, after a few rounds) left most of its elements unused, round after round.
func (l *eventList) renew() *eventList {
	size := l.len
	for e := l.root.next; e != nil && e != &l.root; {
		next := e.next
		e.next, e.prev, e.list = nil, nil, nil
		e = next
	}
	l.init()
	n := newEventList()
	n.nextSlab = renewSlab(size)
	l.spare = nil
	return n
}

// renewSlab is the first slab size of the list that replaces one of n elements: n rounded up to a power of two,
// within minEventSlab and maxEventSlab
func renewSlab(n int) int {
	size := minEventSlab
	for size < n && size < maxEventSlab {
		size *= 2
	}
	return size
}

// reserve makes the next n insertions take their elements from one allocation, for a list whose final
// size is known (a slice or a combination of slices). A list that already has elements and grows again
// (AppendSlices) takes at least the next slab, as the insertions one by one would.
func (l *eventList) reserve(n int) {
	if n <= len(l.spare) {
		return
	}
	if l.len > 0 {
		// the next slab size of a combined list, which the slab setting does not limit (see eventList)
		grow := max(l.nextSlab, minEventSlab)
		if n < grow {
			n = grow
		}
		l.nextSlab = min(grow*2, maxEventSlab)
	}
	l.spare = make([]eventElement, n)
}

func (l *eventList) newElement(v interface{}) *eventElement {
	if len(l.spare) == 0 {
		limit := int(eventSlab.Load())
		if limit <= 1 {
			return &eventElement{Value: v}
		}
		size := l.nextSlab
		if size < minEventSlab {
			size = minEventSlab
		}
		if size > limit {
			size = limit
		}
		l.spare = make([]eventElement, size)
		l.nextSlab = min(size*2, limit)
	}
	e := &l.spare[0]
	// the element leaves the spare slice: clearing the slot is not needed, it was never used
	l.spare = l.spare[1:]
	e.Value = v
	return e
}

// Len returns the number of elements of list l.
func (l *eventList) Len() int { return l.len }

// Front returns the first element of list l or nil if the list is empty.
func (l *eventList) Front() *eventElement {
	if l.len == 0 {
		return nil
	}
	return l.root.next
}

// Back returns the last element of list l or nil if the list is empty.
func (l *eventList) Back() *eventElement {
	if l.len == 0 {
		return nil
	}
	return l.root.prev
}

// insert inserts e after at, increments l.len, and returns e.
func (l *eventList) insert(e, at *eventElement) *eventElement {
	e.prev = at
	e.next = at.next
	e.prev.next = e
	e.next.prev = e
	e.list = l
	l.len++
	return e
}

func (l *eventList) insertValue(v interface{}, at *eventElement) *eventElement {
	return l.insert(l.newElement(v), at)
}

// remove removes e from its list, decrements l.len
func (l *eventList) remove(e *eventElement) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // avoid memory leaks
	e.prev = nil // avoid memory leaks
	e.list = nil
	l.len--
}

// Remove removes e from l if e is an element of list l. It returns the element value e.Value.
// The element must not be nil.
func (l *eventList) Remove(e *eventElement) interface{} {
	if e.list == l {
		l.remove(e)
	}
	return e.Value
}

// PushFront inserts a new element e with value v at the front of list l and returns e.
func (l *eventList) PushFront(v interface{}) *eventElement {
	l.lazyInit()
	return l.insertValue(v, &l.root)
}

// PushBack inserts a new element e with value v at the back of list l and returns e.
func (l *eventList) PushBack(v interface{}) *eventElement {
	l.lazyInit()
	return l.insertValue(v, l.root.prev)
}

// InsertAfter inserts a new element e with value v immediately after mark and returns e.
// If mark is not an element of l, the list is not modified.
func (l *eventList) InsertAfter(v interface{}, mark *eventElement) *eventElement {
	if mark.list != l {
		return nil
	}
	return l.insertValue(v, mark)
}
