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
	"math/rand"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// TestHTTP2LinksFollowTheExits: the uploads of a read X (id 10) and a write W (id 11) that ran at once, W
// returning first, and the read Y after them: W names 9, X names W, Y names X. Whatever the order they
// arrive in, an event is linked only once the uploads before it in the order of the exits have arrived, and
// the events waiting behind a late one are linked when it comes.
func TestHTTP2LinksFollowTheExits(t *testing.T) {
	type ev struct{ id, prev uint64 }
	x, w, y := ev{10, 11}, ev{11, 9}, ev{12, 10}
	orders := [][]ev{{w, x, y}, {w, y, x}, {y, w, x}, {y, x, w}, {x, y, w}, {x, w, y}}
	for _, order := range orders {
		var l http2Links
		l.arrive(8, 0)
		l.arrive(9, 8)
		seen := map[uint64]bool{}
		for _, e := range order {
			l.arrive(e.id, e.prev)
			seen[e.id] = true
			// an event is linked exactly when its chain back to 9 has arrived
			for _, c := range []ev{w, x, y} {
				want := seen[c.id]
				for p := c.prev; want && p != 9; {
					want = seen[p]
					switch p {
					case w.id:
						p = w.prev
					case x.id:
						p = x.prev
					default:
						p = 9
					}
				}
				if got := seen[c.id] && l.linked(c.id); got != want {
					t.Fatalf("order %v: after %d arrived, %d linked=%t, want %t", order, e.id, c.id, got, want)
				}
			}
		}
		if len(l.waiting) != 0 || len(l.byPrev) != 0 || len(l.byPrevMore) != 0 {
			t.Fatalf("order %v: %d still waiting", order, len(l.waiting))
		}
	}
}

// TestHTTP2LinksRacingExits: two calls that returned at once both name the same previous call (they read
// socket_data_last_id_map before either wrote it): both are linked by it, and the next names one of them
func TestHTTP2LinksRacingExits(t *testing.T) {
	var l http2Links
	l.arrive(5, 0)
	l.arrive(8, 7) // waits for 7
	l.arrive(7, 5)
	l.arrive(6, 5)
	for _, id := range []uint64{5, 6, 7, 8} {
		if !l.linked(id) {
			t.Fatalf("%d is not linked", id)
		}
	}
}

// TestHTTP2LinksForceAndForget: an event given up is linked by force with what waits behind it, an event
// waiting long without reaching the parser is linked by the prune, and the linked ids are forgotten beyond
// http2LinkMemory without making a forgotten one look missing
func TestHTTP2LinksForceAndForget(t *testing.T) {
	var l http2Links
	l.arrive(1, 0)
	l.arrive(3, 2) // 2 is lost
	l.arrive(4, 3)
	if l.linked(3) || l.linked(4) {
		t.Fatal("linked behind a missing upload")
	}
	l.force(3)
	if !l.linked(3) || !l.linked(4) {
		t.Fatal("not linked after the give up")
	}
	if len(l.byPrev) != 0 || len(l.byPrevMore) != 0 {
		t.Fatalf("the forced event still waits for its lost upload: %v %v", l.byPrev, l.byPrevMore)
	}
	// two events waiting for the same lost upload (a duplicated previous id): forcing one keeps the other waiting
	// for it, forcing that one too forgets the upload
	l.arrive(31, 30)
	l.arrive(32, 30)
	l.force(31)
	if l.linked(32) || l.byPrev[30] != 32 || len(l.byPrevMore) != 0 {
		t.Fatalf("after forcing the first waiter: 32 linked %t, %v %v", l.linked(32), l.byPrev, l.byPrevMore)
	}
	l.force(32)
	if len(l.byPrev) != 0 || len(l.byPrevMore) != 0 {
		t.Fatalf("both waiters forced: %v %v", l.byPrev, l.byPrevMore)
	}
	l.arrive(6, 5) // 5 is lost, 6 never reaches the parser's head
	w := l.waiting[6]
	w.arrived -= int64(time.Second)
	l.waiting[6] = w
	l.pruneStale(100 * time.Millisecond)
	if !l.linked(6) {
		t.Fatal("not linked by the prune")
	}
	for id := uint64(7); id < 7+2*http2LinkMemory; id++ {
		l.arrive(id, id-1)
	}
	if l.recent.len() != http2LinkMemory {
		t.Fatalf("%d linked ids remembered", l.recent.len())
	}
	// a late event naming a forgotten id is linked, one naming an id never seen above the floor waits
	l.arrive(1000, 10)
	l.arrive(1002, 1001)
	if !l.linked(1000) || l.linked(1002) {
		t.Fatalf("1000 linked=%t, 1002 linked=%t", l.linked(1000), l.linked(1002))
	}
}

// TestHTTP2LinkSetLikeAMap: the open addressed set answers what a map of the ids answers, through adds and
// removals in any order (the backward shift of a removal keeps every probe chain whole)
func TestHTTP2LinkSetLikeAMap(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var set http2LinkSet
	ref := map[uint64]bool{}
	var held []uint64
	for i := 0; i < 200000; i++ {
		switch {
		case len(held) < http2LinkMemory && rng.Intn(3) != 0:
			// consecutive ids, as the data ids of a connection, and a few far ones
			id := uint64(rng.Intn(4096))
			if rng.Intn(50) == 0 {
				id = rng.Uint64()
			}
			set.add(id)
			if !ref[id] {
				held = append(held, id)
			}
			ref[id] = true
		case len(held) > 0:
			k := rng.Intn(len(held))
			id := held[k]
			held = append(held[:k], held[k+1:]...)
			set.remove(id)
			delete(ref, id)
			if id == 0 {
				// 0 is never forgotten
				ref[0] = true
				held = append(held, 0)
			}
		}
		probe := uint64(rng.Intn(4096))
		if set.has(probe) != ref[probe] {
			t.Fatalf("step %d: has(%d)=%t, the map says %t", i, probe, set.has(probe), ref[probe])
		}
	}
	for id := range ref {
		if !set.has(id) {
			t.Fatalf("%d lost", id)
		}
	}
	if set.len() != len(ref) {
		t.Fatalf("%d ids, the map has %d", set.len(), len(ref))
	}
}

// TestHTTP2LinksStartWaitsForEarlierUploads: the first event the analysis sees is not linked by its previous
// data id alone: an earlier upload of a new connection can be delivered after it (another CPU's ring, a batch
// not kicked yet), so it waits for it during the start window. What does not come within the window was made
// before the analysis: then the ids up to the first one's previous data id are taken as linked.
func TestHTTP2LinksStartWaitsForEarlierUploads(t *testing.T) {
	defer func(old time.Duration) { http2ArrivalWaitDuration = old }(http2ArrivalWaitDuration)
	http2ArrivalWaitDuration = 100 * time.Millisecond

	// a new connection: 3 is delivered before 1 and 2
	var l http2Links
	l.arrive(3, 2)
	if l.linked(3) {
		t.Fatal("the first event delivered is linked before the uploads made before it")
	}
	l.arrive(2, 1)
	if l.linked(2) || l.linked(3) {
		t.Fatal("linked behind the missing first upload")
	}
	l.arrive(1, 0)
	for _, id := range []uint64{1, 2, 3} {
		if !l.linked(id) {
			t.Fatalf("%d is not linked once the first upload came", id)
		}
	}
	if l.missingSinceStart(3) {
		t.Fatal("nothing is missing")
	}

	// a connection captured mid stream: 7 names 6, which was before the analysis and never comes
	var m http2Links
	m.arrive(7, 6)
	if m.linked(7) || !m.missingSinceStart(7) {
		t.Fatalf("7 linked=%t, missing since the start=%t", m.linked(7), m.missingSinceStart(7))
	}
	m.arrive(8, 7)
	if m.linked(8) || !m.missingSinceStart(8) {
		t.Fatalf("8 linked=%t, missing since the start=%t", m.linked(8), m.missingSinceStart(8))
	}
	// the parser gives 7 up at its head: what waits behind it is linked
	m.force(7)
	if !m.linked(8) {
		t.Fatal("8 is not linked with 7")
	}
	// another call made before the analysis (racing the one 7 named) is waited for in the window ...
	m.arrive(10, 5)
	if m.linked(10) || !m.missingSinceStart(10) {
		t.Fatalf("10 linked=%t, missing since the start=%t", m.linked(10), m.missingSinceStart(10))
	}
	// ... and taken as before the analysis once the window is over
	time.Sleep(150 * time.Millisecond)
	m.arrive(11, 4)
	if !m.linked(11) {
		t.Fatal("an upload before the first one is still waited for after the start window")
	}
	// an id above the first one's previous data id is never taken as from before the analysis
	m.arrive(13, 12)
	if m.linked(13) || m.missingSinceStart(13) {
		t.Fatalf("13 linked=%t, missing since the start=%t", m.linked(13), m.missingSinceStart(13))
	}
}

// TestHTTP2StartReorderNotLate: the second socket call of a new connection is delivered before the first one
// (the preface, the SETTINGS and the first request): the parser must wait for the first one instead of reading
// the second one and skipping the first one as late, which lost the framing and the HPACK table of the direction
func TestHTTP2StartReorderNotLate(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.settings()
	client.headers(1, false, append(requestFields("/first"), hf("x-session", "shared-session-abcdefghij"))...)
	first := client.take()
	// the second request refers to the dynamic table entries the first one made
	client.headers(3, true, append(requestFields("/second"), hf("x-session", "shared-session-abcdefghij"))...)
	second := client.take()

	now := bpfNow()
	c.feedWithID(enums.SocketDataDirectionIngress, second, 0, 2, 1, now)
	c.analyze()
	if m := c.metrics(); m.LateSkips != 0 || m.DecodeErrors != 0 || m.FramingErrors != 0 || len(c.blocks[enums.SocketDataDirectionIngress]) != 0 {
		t.Fatalf("parsed ahead of the first call: late=%d decode=%d framing=%d blocks=%d", m.LateSkips, m.DecodeErrors,
			m.FramingErrors, len(c.blocks[enums.SocketDataDirectionIngress]))
	}
	c.feedWithID(enums.SocketDataDirectionIngress, first, 0, 1, 0, now)
	c.analyze()
	m := c.metrics()
	if m.LateSkips != 0 || m.DecodeErrors != 0 || m.FramingErrors != 0 || m.Gaps != 0 || m.headerDesync[enums.SocketDataDirectionIngress] {
		t.Fatalf("late=%d decode=%d framing=%d gaps=%d desync=%t", m.LateSkips, m.DecodeErrors, m.FramingErrors, m.Gaps,
			m.headerDesync[enums.SocketDataDirectionIngress])
	}
	blocks := c.blocks[enums.SocketDataDirectionIngress]
	if len(blocks) != 2 || blocks[0][":path"] != "/first" || blocks[1][":path"] != "/second" ||
		blocks[1]["x-session"] != "shared-session-abcdefghij" {
		t.Fatalf("the header blocks: %v", blocks)
	}
	server.settings()
	c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 3, 2, now)
	c.analyze()
	if m.LateSkips != 0 || m.Gaps != 0 {
		t.Fatalf("late=%d gaps=%d", m.LateSkips, m.Gaps)
	}
}

// TestHTTP2StartMidStreamNotAGap: a connection captured mid stream starts with an event whose previous upload
// was before the analysis: it is waited for during the start window, then given up without counting a gap (the
// parser went past nothing), so a later decode error keeps the per-block behaviour of a mid stream capture
func TestHTTP2StartMidStreamNotAGap(t *testing.T) {
	defer func(old time.Duration) { http2ArrivalWaitDuration = old }(http2ArrivalWaitDuration)
	http2ArrivalWaitDuration = 50 * time.Millisecond
	defer SetHTTP2GapWaitDuration(SetHTTP2GapWaitDuration(50 * time.Millisecond))

	c := newHTTP2TestConn(t)
	client := newHTTP2Peer()
	client.headers(5, true, requestFields("/mid")...)
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 41, 40, bpfNow())
	c.analyze()
	if len(c.blocks[enums.SocketDataDirectionIngress]) != 0 {
		t.Fatal("parsed before the start window ended")
	}
	// the window ends on the delivery clock: analyzed again until it did, however slow the box is
	for deadline := time.Now().Add(10 * time.Second); len(c.blocks[enums.SocketDataDirectionIngress]) == 0 &&
		time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		c.analyze()
	}
	m := c.metrics()
	if blocks := c.blocks[enums.SocketDataDirectionIngress]; len(blocks) != 1 || blocks[0][":path"] != "/mid" {
		t.Fatalf("the header blocks: %v", blocks)
	}
	if m.Gaps != 0 {
		t.Fatalf("gaps=%d", m.Gaps)
	}
}

// TestHTTP2LinksPruneOnlyRoots: the prune links by force the event at the root of a waiting chain (it waits for an
// upload that has not arrived), what waits behind it is linked with it; the root is remembered so the parser takes
// it as a gap, and no frame continues into it
func TestHTTP2LinksPruneOnlyRoots(t *testing.T) {
	var l http2Links
	l.arrive(1, 0)
	l.arrive(3, 2) // 2 is lost
	l.arrive(4, 3)
	for _, id := range []uint64{3, 4} {
		w := l.waiting[id]
		w.arrived -= int64(time.Second)
		l.waiting[id] = w
	}
	l.pruneStale(100 * time.Millisecond)
	if !l.linked(3) || !l.linked(4) {
		t.Fatal("not linked by the prune")
	}
	if l.continuable(3) || !l.continuable(4) {
		t.Fatalf("continuable: 3 %t, 4 %t", l.continuable(3), l.continuable(4))
	}
	if l.waitedSince(3) < time.Second {
		t.Fatalf("the root waited %s", l.waitedSince(3))
	}
	if prev, ok := l.takeStaleRoot(4); ok {
		t.Fatalf("4 waited behind the root, taken with %d", prev)
	}
	if prev, ok := l.takeStaleRoot(3); !ok || prev != 2 {
		t.Fatalf("the root: %d %t", prev, ok)
	}
	if !l.continuable(3) {
		t.Fatal("still not continuable once taken")
	}
}

// TestHTTP2PrunedHoleInHeaderBlockDesyncs: the CONTINUATION frame of a header block is lost and the event after it
// is linked by the prune (it waited longer than twice the gap wait without reaching the head): when the parser
// reaches it, the hole is a gap in the middle of the header block, so the direction is marked header-desynced and
// the block is not decoded from the fragments around the hole
func TestHTTP2PrunedHoleInHeaderBlockDesyncs(t *testing.T) {
	c := newHTTP2TestConn(t)
	client := newHTTP2Peer()
	client.preface()
	client.settings()
	block := client.encode(append(requestFields("/split"), hf("x-session", "shared-session-abcdefghij"))...)
	third := len(block) / 3
	if err := client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:third], EndHeaders: false}); err != nil {
		t.Fatal(err)
	}
	first := client.take()
	if err := client.framer.WriteContinuation(1, false, block[third:2*third]); err != nil {
		t.Fatal(err)
	}
	_ = client.take() // id 2: lost
	if err := client.framer.WriteContinuation(1, true, block[2*third:]); err != nil {
		t.Fatal(err)
	}
	last := client.take()

	now := bpfNow()
	c.feedWithID(enums.SocketDataDirectionIngress, first, 0, 1, 0, now)
	c.feedWithID(enums.SocketDataDirectionIngress, last, 0, 3, 2, now)
	c.analyze()
	m := c.metrics()
	if len(m.pendingHeaders) != 1 || m.links.linked(3) {
		t.Fatalf("pending %d, 3 linked %t", len(m.pendingHeaders), m.links.linked(3))
	}
	// 3 has waited long: the prune links it (the parser still waits at it, its kernel time is recent)
	w := m.links.waiting[3]
	w.arrived -= int64(time.Minute)
	m.links.waiting[3] = w
	m.links.lastPrune = time.Time{}
	c.analyze()
	if !m.links.linked(3) {
		t.Fatal("not linked by the prune")
	}
	c.analyze()
	if !m.headerDesync[enums.SocketDataDirectionIngress] || m.Gaps != 1 {
		t.Fatalf("desync %t, gaps %d", m.headerDesync[enums.SocketDataDirectionIngress], m.Gaps)
	}
	if len(c.blocks[enums.SocketDataDirectionIngress]) != 0 || len(c.analyzer.streams) != 0 {
		t.Fatalf("decoded across the hole: %v", c.blocks[enums.SocketDataDirectionIngress])
	}
}
