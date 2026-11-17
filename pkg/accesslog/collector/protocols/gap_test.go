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
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

const (
	gapTestBody     = 256 << 10 // request body
	gapTestRead     = 8 << 10   // bytes the server reads per socket call
	gapTestRespBody = 1 << 10
)

// countingHTTP1 counts the complete messages: the request body fully uploaded (no byte made up for an
// event that never arrived) and the path the one its connection sent
type countingHTTP1 struct {
	complete atomic.Int64
	broken   atomic.Int64
}

func (a *countingHTTP1) HandleHTTPData(m *HTTP1Metrics, _ *PartitionConnection, req *reader.Request, resp *reader.Response) error {
	uploaded := 0
	if body := req.BodyBuffer(); body != nil {
		for _, e := range body.TotalBuffer() {
			uploaded += e.BufferLen()
		}
	}
	if uploaded == gapTestBody && strings.HasPrefix(req.Original().URL.Path, fmt.Sprintf("/c%d/", m.ConnectionID)) &&
		resp.Original().StatusCode == 200 {
		a.complete.Add(1)
	} else {
		a.broken.Add(1)
	}
	return nil
}

func (a *countingHTTP1) OnProtocolBreak(*HTTP1Metrics, *PartitionConnection) {}

// gapTestConn produces the socket calls the server side of a keep-alive connection sees: a 256KB request
// read 8KB at a time, then a 1KB response written at once
type gapTestConn struct {
	id       uint64
	dataID   uint64
	pending  [][]byte
	ingress  int // count of the pending calls that are read
	messages int
}

func (c *gapTestConn) next() (data []byte, direction enums.SocketDataDirection, start bool) {
	if len(c.pending) == 0 {
		c.messages++
		req := []byte(fmt.Sprintf("POST /c%d/m%d HTTP/1.1\r\nHost: stress-server\r\nContent-Length: %d\r\n\r\n",
			c.id, c.messages, gapTestBody) + strings.Repeat("a", gapTestBody))
		for off := 0; off < len(req); off += gapTestRead {
			c.pending = append(c.pending, req[off:min(off+gapTestRead, len(req))])
		}
		c.ingress = len(c.pending)
		c.pending = append(c.pending, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", gapTestRespBody)+
			strings.Repeat("b", gapTestRespBody)))
		start = true
	}
	data = c.pending[0]
	c.pending = c.pending[1:]
	direction = enums.SocketDataDirectionIngress
	if c.ingress <= 0 {
		direction = enums.SocketDataDirectionEgress
	}
	c.ingress--
	c.dataID++
	return data, direction, start
}

// gapEvent is a socket data event whose data the memory protection does not account for apart from the event: what
// the simulation models is an event that holds its call's data in itself (the budget counts events)
type gapEvent struct {
	*aclevents.SocketDataUploadEvent
}

// ReleaseBuffer gives back no pooled buffer: the data is the event's own
func (e *gapEvent) ReleaseBuffer() []byte {
	e.Buffer = nil
	return nil
}

func (c *gapTestConn) event(data []byte, direction enums.SocketDataDirection) *gapEvent {
	ev := &aclevents.SocketDataUploadEvent{
		Protocol0: enums.ConnectionProtocolHTTP, Direction0: direction, Finished: 1, DataLen: uint16(len(data)),
		StartTime0: bpfNow(), EndTime0: bpfNow(), ConnectionID: c.id, RandomID: c.id * 31,
		DataID0: c.dataID, PrevDataID0: c.dataID - 1, TotalSize0: uint64(len(data)),
	}
	ev.Buffer = append([]byte(nil), data...)
	return &gapEvent{ev}
}

type gapSimulation struct {
	t         *testing.T
	partition *PartitionContext
	analyzer  *countingHTTP1
	conns     []*gapTestConn
	budget    int64
	random    *rand.Rand
	cursor    int
	started   int64 // requests whose first call was produced
	maxInUse  int64
}

func newGapSimulation(t *testing.T, connections int, budgetEvents int64) *gapSimulation {
	purgeGapMarksOlderThan(t)
	analyzer := &countingHTTP1{}
	s := &gapSimulation{t: t, analyzer: analyzer,
		partition: newTestPartition([]Protocol{NewHTTP1Analyzer(nil, analyzer)}), random: rand.New(rand.NewSource(7))}
	for i := 0; i < connections; i++ {
		s.conns = append(s.conns, &gapTestConn{id: uint64(i + 1)})
	}
	// the rover event embeds its array: the budget counts events
	s.budget = budgetEvents * (21760 + 64)
	buffer.SetMemoryBudget(s.budget)
	return s
}

// read hands one socket call of the next connection to the partition the way the reader does: refused
// by the memory protection (and noted), or admitted and appended
func (s *gapSimulation) read(conn *gapTestConn) {
	data, direction, start := conn.next()
	if start {
		s.started++
	}
	if !buffer.AcquireEvent() {
		NoteProtectionDrop(conn.id, conn.id*31, enums.ConnectionProtocolHTTP, false, conn.dataID, 0, IsHTTP1RequestLine(data))
		return
	}
	ev := conn.event(data, direction)
	connection := s.partition.GetConnectionContext(ev.ConnectionID, ev.RandomID, ev.Protocol0, ev.DataID0)
	s.partition.AppendAndMaybeAnalyze(connection, ev)
	if inflight := buffer.InflightBytes(); inflight > s.maxInUse {
		s.maxInUse = inflight
	}
}

// tick reads `events` socket calls of connections picked at random (every connection has a message in
// flight, at its own pace), then analyzes connections in turn until they released `capacity` events (or
// every connection was analyzed): the analysis is slower than the load when capacity < events
func (s *gapSimulation) tick(events, capacity int) {
	for i := 0; i < events; i++ {
		s.read(s.conns[s.random.Intn(len(s.conns))])
	}
	start := eventsInUse()
	for visited := 0; visited < len(s.conns) && start-eventsInUse() < int64(capacity); visited++ {
		conn := s.conns[s.cursor%len(s.conns)]
		s.cursor++
		if connection, ok := s.partition.connections.Get(common.NewConnectionKey(conn.id, conn.id*31)); ok {
			s.partition.processConnectionEvents(connection)
		}
	}
}

func (s *gapSimulation) close() {
	s.partition.connections.IterCb(func(_ common.ConnectionKey, con *PartitionConnection) {
		con.ReleasePendingData()
	})
}

func eventsInUse() int64 {
	inUse, _, _, _ := buffer.MemoryStats()
	return inUse
}

// runGapOverload: 100 connections each send 256KB requests in 8KB reads, 2000 calls per round while the
// analysis gets through 750 (37.5% of the load), against a budget of 1500 events. Then the load drops below
// the budget.
func runGapOverload(t *testing.T) (overload, recovery float64, s *gapSimulation) {
	before := eventsInUse()
	s = newGapSimulation(t, 100, 1500)
	defer buffer.SetMemoryBudget(0)
	const overloadTicks, offered, capacity = 80, 2000, 750
	for i := 0; i < overloadTicks; i++ {
		s.tick(offered, capacity)
	}
	overloadStarted, overloadComplete := s.started, s.analyzer.complete.Load()
	// the load drops to 1000 calls per pass: everything fits, give it a few passes to settle
	for i := 0; i < 20; i++ {
		s.tick(500, 1<<30)
	}
	recoveryStarted, recoveryComplete := s.started, s.analyzer.complete.Load()
	for i := 0; i < 30; i++ {
		s.tick(500, 1<<30)
	}
	overload = float64(overloadComplete) / float64(overloadStarted)
	recovery = float64(s.analyzer.complete.Load()-recoveryComplete) / float64(s.started-recoveryStarted)
	if s.maxInUse > s.budget+(21760+64) {
		t.Fatalf("in-flight memory %d went past the budget %d", s.maxInUse, s.budget)
	}
	s.close()
	if after := eventsInUse(); after != before {
		t.Fatalf("events in use %d after the run, %d before: the accounting is off", after, before)
	}
	return overload, recovery, s
}

func TestGapHandlingKeepsCompleteMessagesUnderOverload(t *testing.T) {
	discardedBefore, resyncsBefore := gapDiscardedEvents.Load(), gapResyncsTotal.Load()
	overload, recovery, s := runGapOverload(t)
	// the analysis gets through 37.5% of the calls, so 37.5% of the messages is the most there is
	t.Logf("with the gap handling: %.1f%% of the messages complete under overload (the analysis keeps up with "+
		"%.1f%% of the load), %.1f%% after the load dropped, %d broken, %d events discarded, %d resyncs",
		overload*100, 750.0/2000*100, recovery*100, s.analyzer.broken.Load(),
		gapDiscardedEvents.Load()-discardedBefore, gapResyncsTotal.Load()-resyncsBefore)
	if overload < 0.03 {
		t.Fatalf("only %.1f%% of the messages completed under overload", overload*100)
	}
	if recovery < 0.99 {
		t.Fatalf("only %.1f%% of the messages completed after the load dropped", recovery*100)
	}
	if s.analyzer.broken.Load() != 0 {
		t.Fatalf("%d messages were reported with missing bytes", s.analyzer.broken.Load())
	}
	if gapConnectionsActive.Load() != 0 || gapMarksPending.Load() != 0 {
		t.Fatalf("gap state left behind: %d connections, %d marks", gapConnectionsActive.Load(), gapMarksPending.Load())
	}
}

// TestGapHandlingBaselineLivelock is the same run without the gap handling: the leftovers of the cut
// messages hold the budget until the expiry (which a run this short never reaches), so almost nothing
// completes and nothing recovers
func TestGapHandlingBaselineLivelock(t *testing.T) {
	gapHandling = false
	defer func() { gapHandling = true }()
	overload, recovery, s := runGapOverload(t)
	t.Logf("without the gap handling: %.1f%% of the messages complete under overload (%d of %d), %.1f%% after the "+
		"load dropped", overload*100, s.analyzer.complete.Load(), s.started, recovery*100)
	if overload > 0.10 {
		t.Fatalf("the baseline completed %.1f%%: the simulation no longer shows the livelock", overload*100)
	}
}

// TestGapHandlingInactiveProtectionUnchanged: without a drop the event path and the analysis are the
// ones without the gap handling, every message completes
func TestGapHandlingInactiveProtectionUnchanged(t *testing.T) {
	before := eventsInUse()
	s := newGapSimulation(t, 50, 0)
	buffer.SetMemoryBudget(0)
	connectionsBefore := gapConnectionsTotal.Load()
	for i := 0; i < 40; i++ {
		s.tick(1000, 1<<30)
	}
	if gapConnectionsTotal.Load() != connectionsBefore || gapConnectionsActive.Load() != 0 {
		t.Fatal("the gap handling acted without a drop")
	}
	// the messages still in flight at the end are the only ones not complete
	if done := s.analyzer.complete.Load(); done < s.started-int64(len(s.conns)) || s.analyzer.broken.Load() != 0 {
		t.Fatalf("%d of %d messages complete, %d broken", done, s.started, s.analyzer.broken.Load())
	}
	s.close()
	if after := eventsInUse(); after != before {
		t.Fatalf("events in use %d after the run, %d before", after, before)
	}
}

// TestGapResyncAfterDroppedBodyEvent follows one connection: a body event dropped, the rest of the
// message dropped at once, the next request complete
func TestGapResyncAfterDroppedBodyEvent(t *testing.T) {
	before := eventsInUse()
	s := newGapSimulation(t, 1, 0)
	buffer.SetMemoryBudget(0)
	conn := s.conns[0]
	feed := func(drop bool) {
		data, direction, _ := conn.next()
		if drop {
			NoteProtectionDrop(conn.id, conn.id*31, enums.ConnectionProtocolHTTP, false, conn.dataID, 0, IsHTTP1RequestLine(data))
			return
		}
		if !buffer.AcquireEvent() {
			t.Fatal("the protection is off")
		}
		ev := conn.event(data, direction)
		s.partition.AppendAndMaybeAnalyze(s.partition.GetConnectionContext(ev.ConnectionID, ev.RandomID, ev.Protocol0, ev.DataID0), ev)
	}
	calls := gapTestBody/gapTestRead + 2 // the headers push the request into one more read, then the response
	for i := 0; i < calls; i++ {
		feed(i == 10)
		if i == 5 {
			s.partition.processEvents(false)
		}
	}
	s.partition.processEvents(false)
	connection := s.partition.GetConnectionContext(conn.id, conn.id*31, enums.ConnectionProtocolHTTP, 1)
	if connection.gap.Load() == nil || connection.PendingDataLength() != 0 {
		t.Fatalf("the cut message must be dropped while waiting for the next request, pending %d", connection.PendingDataLength())
	}
	for i := 0; i < calls; i++ {
		feed(false)
	}
	s.partition.processEvents(false)
	if s.analyzer.complete.Load() != 1 || s.analyzer.broken.Load() != 0 {
		t.Fatalf("complete %d, broken %d: the request after the gap must complete", s.analyzer.complete.Load(), s.analyzer.broken.Load())
	}
	if connection.gap.Load() != nil || connection.PendingDataLength() != 0 {
		t.Fatal("the connection must be resynchronised and empty")
	}
	s.close()
	if after := eventsInUse(); after != before {
		t.Fatalf("events in use %d after the run, %d before", after, before)
	}
}

// TestGapHandlingConcurrent drives the reader, the partition and the analysis on their own goroutines,
// with the early expiry running, for the race detector and the accounting
func TestGapHandlingConcurrent(t *testing.T) {
	before := eventsInUse()
	s := newGapSimulation(t, 64, 400)
	defer buffer.SetMemoryBudget(0)
	type admitted struct {
		ev *gapEvent
	}
	ch := make(chan admitted, 256)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // the partition goroutine
		defer wg.Done()
		for a := range ch {
			connection := s.partition.GetConnectionContext(a.ev.ConnectionID, a.ev.RandomID, a.ev.Protocol0, a.ev.DataID0)
			s.partition.AppendAndMaybeAnalyze(connection, a.ev)
		}
	}()
	var analysis sync.WaitGroup
	analysis.Add(1)
	go func() { // the analysis
		defer analysis.Done()
		for {
			select {
			case <-done:
				return
			default:
				s.partition.processEvents(false)
			}
		}
	}()
	for i := 0; i < 60000; i++ {
		conn := s.conns[i%len(s.conns)]
		data, direction, _ := conn.next()
		if !buffer.AcquireEvent() {
			NoteProtectionDrop(conn.id, conn.id*31, enums.ConnectionProtocolHTTP, false, conn.dataID, 0, IsHTTP1RequestLine(data))
			continue
		}
		ch <- admitted{ev: conn.event(data, direction)}
	}
	close(ch)
	wg.Wait()
	close(done)
	analysis.Wait()
	s.partition.processEvents(false)
	t.Logf("concurrent: %d of %d messages complete, %d broken", s.analyzer.complete.Load(), s.conns[0].messages*len(s.conns),
		s.analyzer.broken.Load())
	if s.analyzer.complete.Load() == 0 {
		t.Fatal("nothing completed")
	}
	s.close()
	if after := eventsInUse(); after != before {
		t.Fatalf("events in use %d after the run, %d before", after, before)
	}
	purgeGapMarksOlderThan(t)
}

// purgeGapMarksOlderThan clears the drops noted for connections that never sent again, so the other
// tests start without them
func purgeGapMarksOlderThan(t *testing.T) {
	t.Helper()
	purgeGapMarks(-time.Hour)
}

// TestGapLateEventBeforeResyncDiscarded: a request start from before the gap that arrives after the
// resynchronisation released its body must not be read together with the resync request (it would
// take the request's bytes as its body and pair with its response)
func TestGapLateEventBeforeResyncDiscarded(t *testing.T) {
	purgeGapMarksOlderThan(t)
	before := eventsInUse()
	analyzer := &recordingHTTP1{}
	p := newTestPartition([]Protocol{NewHTTP1Analyzer(nil, analyzer)})
	const id = 77
	feed := func(dataID uint64, direction enums.SocketDataDirection, data string) {
		if !buffer.AcquireEvent() {
			t.Fatal("the protection is off")
		}
		ev := &aclevents.SocketDataUploadEvent{
			Protocol0: enums.ConnectionProtocolHTTP, Direction0: direction, Finished: 1, DataLen: uint16(len(data)),
			StartTime0: bpfNow(), EndTime0: bpfNow(), ConnectionID: id, RandomID: id,
			DataID0: dataID, PrevDataID0: dataID - 1, TotalSize0: uint64(len(data)),
		}
		ev.Buffer = buffer.TakeBuffer(len(data))
		copy(ev.Buffer, data)
		p.AppendAndMaybeAnalyze(p.GetConnectionContext(id, id, enums.ConnectionProtocolHTTP, dataID), ev)
	}
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	feed(9, in, strings.Repeat("x", 50)) // the body of POST /x, whose headers (8) are late
	NoteProtectionDrop(id, id, enums.ConnectionProtocolHTTP, false, 10, 0, false)
	feed(30, in, "POST /r HTTP/1.1\r\nHost: s\r\nContent-Length: 10\r\n\r\n0123456789")
	feed(31, out, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	p.processEvents(false) // resynchronises at 30, releases 9
	feed(8, in, "POST /x HTTP/1.1\r\nHost: s\r\nContent-Length: 50\r\n\r\n")
	feed(40, in, "GET /next HTTP/1.1\r\nHost: s\r\n\r\n")
	feed(41, out, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	p.processEvents(false)
	want := []string{"POST /r -> 201 req=10 resp=0", "GET /next -> 200 req=0 resp=0"}
	if fmt.Sprint(analyzer.handled) != fmt.Sprint(want) {
		t.Fatalf("logs %v, want %v: the late POST /x must not take the following request as its body", analyzer.handled, want)
	}
	connection := p.GetConnectionContext(id, id, enums.ConnectionProtocolHTTP, 1)
	connection.ReleasePendingData()
	if after := eventsInUse(); after != before {
		t.Fatalf("events in use %d, %d before", after, before)
	}
}
