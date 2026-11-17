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
	"bytes"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

// Gap handling: what the analysis does with a connection the memory protection dropped an event of.
//
// A message that lost an event can never complete, but the analysis keeps every event it cannot parse
// yet (an event may only be late, the queue is not ordered), and the HTTP/2 parser waits for a missing
// call before it goes on. Under a sustained overload the leftovers of the cut messages hold the memory
// budget until the one minute expiry, so the protection drops nearly every new event, which cuts even
// more messages: the agent keeps only the messages that fit between two expiry runs.
//
// So the reader tells the queue which connection lost an event (NoteProtectionDrop, from the samples the
// protection refused), and the queue releases what can no longer complete right away:
//
// the buffered events of the cut message are released, the following events of the connection are
// dropped until the next socket call that starts a request, and the parser restarts there, after the
// whole messages before the gap were analyzed. The events that arrive late from before that point are
// dropped too (gapFloor): what they belonged to is gone, and read now they would be taken as part of the
// messages after it. Only HTTP/1 is followed: HTTP/2 has no message start to resume at.
//
// Nothing of this happens when nothing is dropped: the event path then loads two counters.

var (
	// gapHandling turns the gap handling on; the tests turn it off for the behavior without it
	gapHandling = true

	gapMarks = struct {
		sync.Mutex
		http1 map[common.ConnectionKey]*gapMark
	}{http1: make(map[common.ConnectionKey]*gapMark)}
	// gapMarksPending counts the drops not taken by their connection yet: while it is 0 (and the
	// connection has no gap state) nothing else is looked at
	gapMarksPending atomic.Int64
	// gapConnectionsActive counts the HTTP/1 connections waiting for a request start
	gapConnectionsActive atomic.Int64

	// maxGapMarks bounds the noted drops of connections that sent nothing since
	maxGapMarks = 1 << 16
	// gapMaxDropDuration: a connection that saw no request start for this long after a drop resumes the
	// analysis as without the gap handling
	gapMaxDropDuration = time.Minute

	gapConnectionsTotal atomic.Int64
	gapDiscardedEvents  atomic.Int64
	gapResyncsTotal     atomic.Int64
	gapLostMessages     atomic.Int64
)

// gapPos is the position of an event in its connection: the socket call and the chunk of it
type gapPos struct {
	dataID uint64
	seq    uint16
}

func (p gapPos) before(other gapPos) bool {
	return p.dataID < other.dataID || (p.dataID == other.dataID && p.seq < other.seq)
}

// gapMark is what the reader noted of the HTTP/1 drops of a connection: the first and the last dropped
// event, and whether the first one started a request (then the messages before it are whole)
type gapMark struct {
	first       gapPos
	firstStarts bool
	lastDataID  uint64
	at          time.Time
}

// NoteProtectionDrop is told about a socket data event the memory protection refused, on the goroutine
// that reads the events; startsRequest tells whether its payload starts an HTTP/1 request
// (IsHTTP1RequestLine on the first chunk of a socket call). TLS events share the data id of their socket
// call and cannot be ordered by it: they are not followed.
func NoteProtectionDrop(connectionID, randomID uint64, protocol enums.ConnectionProtocol, ssl bool,
	dataID uint64, sequence uint16, startsRequest bool) {
	if !gapHandling || ssl || protocol != enums.ConnectionProtocolHTTP {
		return
	}
	key := common.NewConnectionKey(connectionID, randomID)
	now := time.Now()
	gapMarks.Lock()
	defer gapMarks.Unlock()
	pos := gapPos{dataID: dataID, seq: sequence}
	if m := gapMarks.http1[key]; m != nil {
		m.at = now
		if pos.before(m.first) {
			m.first, m.firstStarts = pos, startsRequest
		}
		if dataID > m.lastDataID {
			m.lastDataID = dataID
		}
		return
	}
	if len(gapMarks.http1) < maxGapMarks {
		gapMarks.http1[key] = &gapMark{first: pos, firstStarts: startsRequest, lastDataID: dataID, at: now}
		gapMarksPending.Add(1)
	}
}

func takeGapMark(connectionID, randomID uint64) *gapMark {
	key := common.NewConnectionKey(connectionID, randomID)
	gapMarks.Lock()
	defer gapMarks.Unlock()
	m := gapMarks.http1[key]
	if m != nil {
		delete(gapMarks.http1, key)
		gapMarksPending.Add(-1)
	}
	return m
}

// purgeGapMarks forgets the drops noted for connections that sent nothing for a minute
func purgeGapMarks(maxAge time.Duration) {
	if gapMarksPending.Load() == 0 {
		return
	}
	deadline := time.Now().Add(-maxAge)
	gapMarks.Lock()
	defer gapMarks.Unlock()
	for key, m := range gapMarks.http1 {
		if m.at.Before(deadline) {
			delete(gapMarks.http1, key)
			gapMarksPending.Add(-1)
		}
	}
}

// forgetGapMarks drops the noted drops of the connection when it is removed
func forgetGapMarks(connectionID, randomID uint64) {
	if gapMarksPending.Load() > 0 {
		takeGapMark(connectionID, randomID)
	}
}

type gapState int

const (
	// gapDropping: the events after the gap are dropped until a request start
	gapDropping gapState = iota
	// gapResync: a request start arrived, it and the events after it are kept aside (stash) until the
	// analysis resynchronises
	gapResync
	// gapResetting: the analysis is resynchronising, the new events are still kept aside
	gapResetting
)

// connGap is the HTTP/1 gap state of a connection. The partition goroutine moves it on every event of
// the connection, the analyzer goroutine when it resynchronises; mu guards it.
type connGap struct {
	mu          sync.Mutex
	state       gapState
	first       gapPos
	firstStarts bool
	pruned      bool // the events of the cut message were released (pruneAfterGap)
	lastDataID  uint64
	since       time.Time
	resyncID    uint64
	stash       []buffer.SocketDataBuffer
	// recut is set when an event at or after the resync request was dropped while resynchronising
	recut bool
	// closed is set when the state was removed from the connection: an event that waited for mu looks again
	closed bool
}

// filterGap decides an event of a connection that lost an event to the memory protection; it returns
// true when the event was taken (dropped, or kept aside until the resynchronisation) and must not be
// appended to the connection buffer
func (p *PartitionContext) filterGap(connection *PartitionConnection, data buffer.SocketDataBuffer) bool {
	if data.Protocol() != enums.ConnectionProtocolHTTP {
		return false
	}
	if f := connection.gapFloor.Load(); f != 0 && data.DataID() < f {
		// sent before a resynchronisation point of the connection, late: what it belonged to was released
		discardGapEvent(data)
		return true
	}
	if gapMarksPending.Load() == 0 && connection.gap.Load() == nil {
		return false
	}
	if ssl, ok := data.(interface{ GetSSL() uint8 }); ok && ssl.GetSSL() != 0 {
		return false
	}
	var mark *gapMark
	if gapMarksPending.Load() > 0 {
		mark = takeGapMark(connection.connectionID, connection.randomID)
	}
	for {
		g := connection.gap.Load()
		if g == nil {
			if mark == nil {
				return false
			}
			g = &connGap{state: gapDropping, first: mark.first, firstStarts: mark.firstStarts, lastDataID: mark.lastDataID,
				since: time.Now()}
			if !connection.gap.CompareAndSwap(nil, g) {
				continue
			}
			gapConnectionsActive.Add(1)
			gapConnectionsTotal.Add(1)
			mark = nil
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			continue
		}
		taken := g.filter(connection, data, mark)
		g.mu.Unlock()
		return taken
	}
}

// filter is filterGap with the state locked
func (g *connGap) filter(connection *PartitionConnection, data buffer.SocketDataBuffer, mark *gapMark) bool {
	if mark != nil {
		g.merge(mark)
	}
	if (gapPos{dataID: data.DataID(), seq: uint16(data.DataSequence())}).before(g.first) {
		return false // sent before the gap (late from another CPU): it may still complete a message
	}
	if g.state == gapDropping {
		if (data.DataID() > g.lastDataID && isHTTP1RequestStart(data)) || time.Since(g.since) > gapMaxDropDuration {
			g.state, g.resyncID = gapResync, data.DataID()
		} else {
			discardGapEvent(data)
			return true
		}
	}
	if data.DataID() < g.resyncID {
		discardGapEvent(data) // between the gap and the resync request: the rest of a cut message
		return true
	}
	g.stash = append(g.stash, data)
	connection.markDataAppended()
	return true
}

// merge adds drops noted after the state was created
func (g *connGap) merge(mark *gapMark) {
	if mark.first.before(g.first) {
		g.first, g.firstStarts, g.pruned = mark.first, mark.firstStarts, false
	}
	if mark.lastDataID > g.lastDataID {
		g.lastDataID = mark.lastDataID
	}
	if g.state == gapDropping || mark.lastDataID < g.resyncID {
		return
	}
	// the message started by the resync request lost an event too
	if g.state == gapResetting {
		g.recut = true // the analyzer goes back to dropping once it appended what it took
		return
	}
	for _, e := range g.stash {
		discardGapEvent(e)
	}
	g.stash, g.state, g.since = nil, gapDropping, time.Now()
}

// pruneAfterGap releases, once per gap and before the connection is analyzed, the buffered events of
// the message the gap cut: from its request start (the last one before the gap, or the dropped event
// itself when it started a request) to the end, all of the buffer when the message started before
// what the buffer holds. The whole messages before stay and are analyzed.
func (p *PartitionContext) pruneAfterGap(connection *PartitionConnection) {
	g := connection.gap.Load()
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.pruned || g.state != gapDropping {
		g.mu.Unlock()
		return
	}
	g.pruned = true
	first, starts := g.first, g.firstStarts
	g.mu.Unlock()
	buf := connection.Buffer(enums.ConnectionProtocolHTTP)
	if buf == nil {
		return
	}
	boundary := first.dataID
	if !starts {
		limit := first.dataID
		if first.seq > 0 {
			limit++ // the first chunk of the same socket call may start the request
		}
		if start := buf.LastDataEventBefore(limit, isHTTP1RequestStart); start != nil {
			boundary = start.DataID()
		} else {
			// the cut message started before what the buffer holds: all of it belongs to that message
			boundary = 0
			if m, ok := connection.Metrics(enums.ConnectionProtocolHTTP).(*HTTP1Metrics); ok && m.resetAfterGap() {
				gapLostMessages.Add(1)
			}
		}
	}
	gapDiscardedEvents.Add(int64(buf.ReleaseEventsFrom(boundary)))
}

// resetAfterGap resynchronises the analysis of a connection whose resync request arrived, after the
// events before the gap were analyzed: what is left before the request is released, the half parsed
// messages are forgotten, and the request with the events after it is handed to the buffer. It returns
// true when the connection has to be analyzed again.
func (p *PartitionContext) resetAfterGap(connection *PartitionConnection) bool {
	g := connection.gap.Load()
	if g == nil {
		return false
	}
	g.mu.Lock()
	if g.state != gapResync {
		g.mu.Unlock()
		return false
	}
	g.state = gapResetting
	stash, resyncID := g.stash, g.resyncID
	g.stash = nil
	raiseGapFloor(connection, resyncID)
	g.mu.Unlock()

	if buf := connection.Buffer(enums.ConnectionProtocolHTTP); buf != nil {
		gapDiscardedEvents.Add(int64(buf.ReleaseEventsBefore(resyncID)))
	}
	if m, ok := connection.Metrics(enums.ConnectionProtocolHTTP).(*HTTP1Metrics); ok && m.resetAfterGap() {
		gapLostMessages.Add(1)
	}
	for {
		for _, e := range stash {
			connection.AppendData(e)
		}
		g.mu.Lock()
		if len(g.stash) > 0 {
			stash, g.stash = g.stash, nil
			g.mu.Unlock()
			continue
		}
		gapResyncsTotal.Add(1)
		if g.recut {
			g.state, g.first, g.firstStarts = gapDropping, gapPos{dataID: resyncID}, true
			g.recut, g.pruned, g.since = false, false, time.Now()
		} else {
			g.closed = true
			connection.gap.Store(nil)
			gapConnectionsActive.Add(-1)
		}
		g.mu.Unlock()
		return true
	}
}

func raiseGapFloor(connection *PartitionConnection, floor uint64) {
	if floor > connection.gapFloor.Load() {
		connection.gapFloor.Store(floor)
	}
}

// releaseGap gives back what the gap state of a removed connection holds
func (c *PartitionConnection) releaseGap() {
	forgetGapMarks(c.connectionID, c.randomID)
	g := c.gap.Load()
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	for _, e := range g.stash {
		discardGapEvent(e)
	}
	g.stash, g.closed = nil, true
	c.gap.Store(nil)
	gapConnectionsActive.Add(-1)
}

// gapStashLength is the count of events the gap state keeps aside
func (c *PartitionConnection) gapStashLength() int {
	g := c.gap.Load()
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.stash)
}

// resetAfterGap forgets the message being parsed and the requests waiting for their response: the
// events that would complete them were dropped. It reports whether a message was being parsed.
func (m *HTTP1Metrics) resetAfterGap() bool {
	lost := m.pendingBody != nil
	m.pendingBody = nil
	m.halfRequests.Init()
	return lost
}

func discardGapEvent(data buffer.SocketDataBuffer) {
	buffer.ReleaseEvent(data.ReleaseBuffer())
	gapDiscardedEvents.Add(1)
}

// http1RequestMethods are the request lines the resynchronisation starts at
var http1RequestMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("PATCH "), []byte("OPTIONS "), []byte("CONNECT "), []byte("TRACE ")}

// isHTTP1RequestStart reports whether the event is the first chunk of a socket call that starts with an
// HTTP/1 request line: a response is useless without its request, so the analysis resumes at a request
func isHTTP1RequestStart(data buffer.SocketDataBuffer) bool {
	return data.IsStart() && !buffer.IsPayloadSkipped(data) && IsHTTP1RequestLine(data.BufferData())
}

// IsHTTP1RequestLine reports whether the payload starts with an HTTP/1 request line
func IsHTTP1RequestLine(payload []byte) bool {
	for _, method := range http1RequestMethods {
		if bytes.HasPrefix(payload, method) {
			return true
		}
	}
	return false
}

// AnalyzeNewData runs one analysis pass over the connections that received data since the last one, as
// the event counter trigger does, for the callers that drive the analysis themselves (tests)
func (p *PartitionContext) AnalyzeNewData() {
	p.processEventsOfNewData()
}

func init() {
	telemetry.Register("rover_socket_data_gap_connections_total",
		"HTTP/1 connections that lost a socket data event to the memory protection, after which their "+
			"events are dropped until the next request start",
		telemetry.Counter, func() float64 { return float64(gapConnectionsTotal.Load()) })
	telemetry.Register("rover_socket_data_gap_connections",
		"HTTP/1 connections waiting for a request start after a dropped socket data event",
		telemetry.Gauge, func() float64 { return float64(gapConnectionsActive.Load()) })
	telemetry.Register("rover_socket_data_gap_discarded_events_total",
		"Socket data events released at once because an event of their message was dropped by the memory protection",
		telemetry.Counter, func() float64 { return float64(gapDiscardedEvents.Load()) })
	telemetry.Register("rover_socket_data_gap_resyncs_total",
		"HTTP/1 connections the analysis restarted at a request start after a dropped socket data event",
		telemetry.Counter, func() float64 { return float64(gapResyncsTotal.Load()) })
	telemetry.Register("rover_socket_data_gap_lost_messages_total",
		"HTTP/1 messages given up half parsed because events they needed were dropped",
		telemetry.Counter, func() float64 { return float64(gapLostMessages.Load()) })
}
