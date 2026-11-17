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

package protocols

import (
	"math"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

// http2LinkMemory is how many linked data ids a connection remembers to answer whether the previous data id of
// an arriving event has arrived: an older one is taken as arrived (http2Links.floor)
const http2LinkMemory = 256

// http2Links tells which socket events of a connection the parser may read: an event is linked once every
// event BPF uploaded before it has arrived.
//
// The data id of a socket call is taken when the call enters, its previous data id when it returns: the data
// id of the call of the connection that was uploaded last (socket_data_last_id_map). So the previous data ids
// chain the uploads in the order the calls returned, not in the order of their data ids: when a read and a
// write of the connection run at once, the one that entered later can return first, and with the per-CPU
// batches of the compact records the reader can receive the uploads in any order. A rule on the data ids
// (the previous data id is at most the largest one parsed) then lets the parser read an event while an
// earlier call of its own direction is still on its way, and skip that call as late when it arrives; or wait
// for a call that is already there behind the one waiting for it, until the gap wait gives up.
//
// Following the chain instead is exact: an event whose previous event has arrived and is linked is linked,
// and since the calls of one direction run one after the other, a linked event comes after every call of its
// direction that entered before it. The parser reads only linked events, and when it gives an event up
// (http2GapWaitDuration) it links it by force, which links what waits behind it.
type http2Links struct {
	started bool
	// floor: a previous data id at or below it is taken as linked: the ids linked and forgotten (recent
	// keeps http2LinkMemory of them), and, once the start window is over, the ones before the first event the
	// analysis saw
	floor uint64
	// startFloor is the previous data id of the first event the analysis saw, startAt when it arrived. The
	// uploads up to it were made before that event, but it is not the first one made only because it was the
	// first one delivered: the first calls of a new connection run on several CPUs, and an upload of one may
	// still be in a ring that was not woken up or in a per-CPU batch that was not kicked. Taking them as linked
	// at once let the parser read the first event and skip the earlier ones as late when they came (for the
	// direction that started with them: the preface, the SETTINGS and the first header blocks, so its framing
	// and its HPACK table were lost). So they are waited for like any missing upload for the start window
	// (http2ArrivalWait), and only what did not come by then is taken as from before the analysis (a
	// connection captured mid stream), see missingSinceStart.
	startFloor uint64
	startAt    int64
	startOver  bool
	// recent are the linked data ids remembered, ring the order they leave recent in
	recent http2LinkSet
	ring   [http2LinkMemory]uint64
	ringAt int
	// last is the data id linked last: the next upload of the connection names it as its previous one, unless
	// the uploads arrive out of order, so it is linked without looking anything up
	last uint64
	// waiting are the arrived events not linked yet, by data id, and byPrev the id waiting for a data id: the
	// first one, the next ones of the same data id (a duplicated previous id, rare) in byPrevMore. A slice per
	// waiting event was an allocation per event of a connection whose uploads arrive out of order.
	waiting    map[uint64]http2LinkWait
	byPrev     map[uint64]uint64
	byPrevMore map[uint64][]uint64
	// lastPrune is when the waiting events were last looked at for events that left the buffers unparsed
	lastPrune time.Time
	// through is the linkClock time up to which every event read from the rings had reached the connection
	// buffers when the current analysis pass took the events (passStart): the waits count up to it only
	through int64
	// behind is through when the pass started with a backlog between the reader and the partitions, math.MaxInt64
	// without one (0 before the first pass), see deliveryBehind
	behind int64
	// staleRoots are the events pruneStale linked by force while the upload they wait for had not arrived (the
	// roots of the waiting chains), by data id, with that upload and their arrival: the parser takes one like an
	// event it gives up at its head when it reaches it (a gap, see takeStaleRoot), and does not continue a frame
	// into it (continuable), so a frame of the call before the hole is never completed with its bytes
	staleRoots map[uint64]http2LinkWait
}

type http2LinkWait struct {
	prev uint64
	// arrived is when the analysis took the event over (monotonic nanoseconds of the process)
	arrived int64
}

// linkClock is the clock of http2LinkWait.arrived: the delivery clock of the event queues (btf/delivery.go), which
// does not run while a reader is blocked on a full partition
func linkClock() int64 {
	return btf.DeliveryNow()
}

// http2DeliveryStallLimit bounds how far the waits may lag behind the clock because the pipeline between the
// reader and the partitions holds events (http2DeliveredThrough): a partition that never drains (stuck) must not
// stop every give up for ever
const http2DeliveryStallLimit = 30 * time.Second

// http2DeliveredThrough is the time of linkClock up to which every event the reader has read has reached its
// connection buffer (btf.DeliveredThrough), not further back than http2DeliveryStallLimit
var http2DeliveredThrough = func() int64 {
	through := btf.DeliveredThrough()
	if floor := linkClock() - int64(http2DeliveryStallLimit); through < floor {
		through = floor
	}
	return through
}

// passStart is called by the analysis of the connection before it takes the events of the connection buffer: the
// waits of the pass are measured up to what had reached the connection buffers then, so an event the reader has
// read but a partition has not consumed (a backlog of the analysis) is waited for, never given up
func (l *http2Links) passStart() {
	now, through := linkClock(), http2DeliveredThrough()
	if through >= now {
		// nothing read waits to reach the buffers
		l.through, l.behind = now, math.MaxInt64
		return
	}
	l.through, l.behind = through, through
}

// deliveryBehind is how far every event read had reached the buffers when the pass started, when events read
// before that were still on their way (a backlog), math.MaxInt64 otherwise: a wait that starts at or after it
// may be for one of them
func (l *http2Links) deliveryBehind() int64 {
	if l.behind == 0 {
		return math.MaxInt64
	}
	return l.behind
}

// current is the time the waits of the pass are measured up to (see passStart)
func (l *http2Links) current() int64 {
	if l.through > 0 {
		return l.through
	}
	return linkClock()
}

// arrive takes an event the connection received: linked at once when its previous event is, otherwise it
// waits for it. The chunks of one call arrive under one data id and are taken once.
func (l *http2Links) arrive(dataID, prevDataID uint64) {
	if !l.started {
		l.started = true
		l.recent.reset()
		l.waiting = make(map[uint64]http2LinkWait)
		l.byPrev = make(map[uint64]uint64)
		l.byPrevMore = nil
		// the events before the first one may still come: they are waited for during the start window
		l.floor = 0
		l.startFloor, l.startAt, l.startOver = prevDataID, linkClock(), prevDataID == 0
	}
	if l.recent.has(dataID) {
		return
	}
	if prevDataID != 0 && prevDataID == l.last {
		// the chain in order: the previous upload is the one linked last, so the event is linked. It is not
		// waiting either: an event waits only while its previous one is not linked.
		l.link(dataID)
		return
	}
	if len(l.waiting) > 0 {
		if _, ok := l.waiting[dataID]; ok {
			return
		}
	}
	if l.isLinked(prevDataID) {
		l.link(dataID)
		return
	}
	l.waiting[dataID] = http2LinkWait{prev: prevDataID, arrived: linkClock()}
	if _, taken := l.byPrev[prevDataID]; taken {
		if l.byPrevMore == nil {
			l.byPrevMore = make(map[uint64][]uint64)
		}
		l.byPrevMore[prevDataID] = append(l.byPrevMore[prevDataID], dataID)
	} else {
		l.byPrev[prevDataID] = dataID
	}
}

// isLinked tells whether a previous data id is linked: remembered, or older than what is remembered, or made
// before the first event the analysis saw and not delivered within the start window
func (l *http2Links) isLinked(dataID uint64) bool {
	if dataID == 0 || dataID <= l.floor {
		return true
	}
	if l.recent.has(dataID) {
		return true
	}
	if dataID <= l.startFloor && !l.startOver && time.Duration(l.current()-l.startAt) >= http2ArrivalWait() {
		// the start window is over: an upload made before the first event that has not come by now was made
		// before the analysis
		l.startOver = true
		l.floor = max(l.floor, l.startFloor)
		return true
	}
	return false
}

// missingSinceStart tells whether the event of the data id, which waits, waits for an upload made before the
// first event the analysis saw (at or below startFloor): when it has not come within the start window it was
// made before the analysis, which went past nothing then. It follows the waiting events back to the upload that
// has not arrived (a bounded walk: it is only asked when the parser gives an event up).
func (l *http2Links) missingSinceStart(dataID uint64) bool {
	if l.startFloor == 0 {
		return false
	}
	id := dataID
	for i := 0; i < 4096; i++ {
		w, ok := l.waiting[id]
		if !ok {
			return id != 0 && id <= l.startFloor && !l.recent.has(id)
		}
		id = w.prev
	}
	return false
}

// linked tells whether the parser may read the arrived event of the data id: every event uploaded before it
// has arrived (or was given up)
func (l *http2Links) linked(dataID uint64) bool {
	if !l.started || len(l.waiting) == 0 {
		return true
	}
	_, waiting := l.waiting[dataID]
	return !waiting
}

// continuable tells whether a frame may continue into the arrived event of the data id from the call before it
// in its direction: it is linked, and not linked by the prune past an upload that has not arrived
func (l *http2Links) continuable(dataID uint64) bool {
	if !l.linked(dataID) {
		return false
	}
	if len(l.staleRoots) > 0 {
		if _, stale := l.staleRoots[dataID]; stale {
			return false
		}
	}
	return true
}

// waitedSince tells how long the event of the data id has been waiting since it arrived, 0 when it is linked
// (a root the prune linked has waited since its arrival)
func (l *http2Links) waitedSince(dataID uint64) time.Duration {
	if len(l.staleRoots) > 0 {
		if w, ok := l.staleRoots[dataID]; ok {
			return max(time.Duration(l.current()-w.arrived), 0)
		}
	}
	if len(l.waiting) == 0 {
		return 0
	}
	w, ok := l.waiting[dataID]
	if !ok {
		return 0
	}
	return max(time.Duration(l.current()-w.arrived), 0)
}

// takeStaleRoot tells whether the event of the data id was linked by the prune while the upload it waited for
// (prev) had not arrived, and forgets it: the parser reached it
func (l *http2Links) takeStaleRoot(dataID uint64) (prev uint64, ok bool) {
	if len(l.staleRoots) == 0 {
		return 0, false
	}
	w, ok := l.staleRoots[dataID]
	if ok {
		delete(l.staleRoots, dataID)
	}
	return w.prev, ok
}

// force links a waiting event the parser gives up waiting for, and what waits behind it
func (l *http2Links) force(dataID uint64) {
	w, ok := l.waiting[dataID]
	if !ok {
		return
	}
	delete(l.waiting, dataID)
	// it no longer waits for its previous upload, which may never come: the entry that names it there goes too
	l.unwait(w.prev, dataID)
	l.link(dataID)
}

// unwait forgets that the event of the data id waits for the upload of prev (byPrev, byPrevMore)
func (l *http2Links) unwait(prev, dataID uint64) {
	more := l.byPrevMore[prev]
	if first, ok := l.byPrev[prev]; ok && first == dataID {
		if len(more) == 0 {
			delete(l.byPrev, prev)
			return
		}
		// the next waiter of the same previous upload takes its place
		l.byPrev[prev] = more[0]
		more = more[1:]
	} else {
		for i, id := range more {
			if id == dataID {
				more = append(more[:i:i], more[i+1:]...)
				break
			}
		}
	}
	if len(more) == 0 {
		delete(l.byPrevMore, prev)
	} else {
		l.byPrevMore[prev] = more
	}
}

// link marks the data id linked and links the events waiting for it, and theirs
func (l *http2Links) link(dataID uint64) {
	stack := [8]uint64{}
	pending := append(stack[:0], dataID)
	for len(pending) > 0 {
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		l.remember(id)
		if len(l.byPrev) == 0 {
			continue
		}
		first, ok := l.byPrev[id]
		if !ok {
			continue
		}
		delete(l.byPrev, id)
		var more []uint64
		if len(l.byPrevMore) > 0 {
			if more = l.byPrevMore[id]; more != nil {
				delete(l.byPrevMore, id)
			}
		}
		// the waiters in the order they arrived
		for i := -1; i < len(more); i++ {
			w := first
			if i >= 0 {
				w = more[i]
			}
			// a waiter forced in the meantime is linked already
			if _, still := l.waiting[w]; still {
				delete(l.waiting, w)
				pending = append(pending, w)
			}
		}
	}
}

func (l *http2Links) remember(dataID uint64) {
	if old := l.ring[l.ringAt]; old != 0 {
		l.recent.remove(old)
		if old > l.floor {
			l.floor = old
		}
	}
	l.ring[l.ringAt] = dataID
	l.ringAt = (l.ringAt + 1) % http2LinkMemory
	l.recent.add(dataID)
	l.last = dataID
}

// pruneStale links by force the events that have waited twice the gap wait since they arrived for an upload that
// has not arrived (the roots of the waiting chains; what waits behind a root is linked with it): the parser gives
// an event up at its head after the gap wait, so a root waiting that long left the buffers without being parsed
// (it expired, or a gap released it), and the events behind it must not wait for it. A root that is still in the
// buffers is remembered (staleRoots), so the parser takes it as the gap it is when it reaches it. It looks at
// most once per gap wait.
func (l *http2Links) pruneStale(wait time.Duration) {
	if len(l.waiting) == 0 && (len(l.byPrev) > 0 || len(l.byPrevMore) > 0) {
		// a backstop: nothing waits, so nothing waits for any upload
		clear(l.byPrev)
		l.byPrevMore = nil
	}
	if (len(l.waiting) == 0 && len(l.staleRoots) == 0) || time.Since(l.lastPrune) < wait {
		return
	}
	l.lastPrune = time.Now()
	now := l.current()
	for id, w := range l.staleRoots {
		// an event still in the buffers is parsed or expired by then (maxBufferExpireDuration)
		if time.Duration(now-w.arrived) >= maxBufferExpireDuration+2*wait {
			delete(l.staleRoots, id)
		}
	}
	var stale []uint64
	for id, w := range l.waiting {
		if time.Duration(now-w.arrived) < 2*wait {
			continue
		}
		if _, behind := l.waiting[w.prev]; behind {
			// linked with the root it waits behind
			continue
		}
		stale = append(stale, id)
	}
	for _, id := range stale {
		w, ok := l.waiting[id]
		if !ok {
			continue
		}
		if !l.missingSinceStart(id) {
			if l.staleRoots == nil {
				l.staleRoots = make(map[uint64]http2LinkWait)
			}
			l.staleRoots[id] = w
		}
		l.force(id)
	}
}

// release gives the waiting count of a connection that goes away back to the gauge
func (l *http2Links) release() {
	l.waiting = nil
	l.byPrev = nil
	l.byPrevMore = nil
	l.recent.reset()
	l.last = 0
	l.started = false
	l.staleRoots = nil
}

// http2LinkSetSize is the slots of an http2LinkSet: twice what it holds at most (the ring), so a probe stays short
const http2LinkSetSize = 2 * http2LinkMemory

// http2LinkSet is the set of the remembered data ids: an open addressed hash set of a fixed size with linear
// probing, the set a map of the ids was, without the hashing and the buckets of a map. It holds at most what the
// ring holds. Data id 0 is the empty slot, so it is kept on its own: the ring takes 0 for an empty place and
// never forgets it, the set never does either.
type http2LinkSet struct {
	slots [http2LinkSetSize]uint64
	zero  bool
}

func (s *http2LinkSet) reset() {
	*s = http2LinkSet{}
}

// len is the count of the ids the set holds
func (s *http2LinkSet) len() int {
	n := 0
	if s.zero {
		n++
	}
	for _, id := range s.slots {
		if id != 0 {
			n++
		}
	}
	return n
}

func http2LinkSlot(id uint64) int {
	// Fibonacci hashing: the data ids are consecutive numbers, which this spreads over the slots
	return int((id * 0x9E3779B97F4A7C15) >> (64 - 9))
}

func (s *http2LinkSet) has(id uint64) bool {
	if id == 0 {
		return s.zero
	}
	for i := http2LinkSlot(id); ; i = (i + 1) & (http2LinkSetSize - 1) {
		switch s.slots[i] {
		case id:
			return true
		case 0:
			return false
		}
	}
}

func (s *http2LinkSet) add(id uint64) {
	if id == 0 {
		s.zero = true
		return
	}
	i := http2LinkSlot(id)
	for s.slots[i] != 0 {
		if s.slots[i] == id {
			return
		}
		i = (i + 1) & (http2LinkSetSize - 1)
	}
	s.slots[i] = id
}

// remove deletes the id with the backward shift of linear probing, so no slot is left a tombstone
func (s *http2LinkSet) remove(id uint64) {
	if id == 0 {
		// the ring never forgets 0 (it is its empty place)
		return
	}
	i := http2LinkSlot(id)
	for s.slots[i] != id {
		if s.slots[i] == 0 {
			return
		}
		i = (i + 1) & (http2LinkSetSize - 1)
	}
	for {
		s.slots[i] = 0
		j := i
		for {
			j = (j + 1) & (http2LinkSetSize - 1)
			if s.slots[j] == 0 {
				return
			}
			home := http2LinkSlot(s.slots[j])
			// the entry at j may move into the hole at i when its home is not cyclically in (i, j]
			if (j > i && (home <= i || home > j)) || (j < i && home <= i && home > j) {
				s.slots[i] = s.slots[j]
				i = j
				break
			}
		}
	}
}
