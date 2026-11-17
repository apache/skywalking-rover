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

// Package http1skip decides, while the perf reader decodes the socket data events, which calls of an
// HTTP/1 connection are decoded without their bytes (access_log.protocol_analyze.skip_http1_body_payload).
// The analyzer only counts the bytes of a Content-Length body, so a call that lies wholly inside one needs
// no data buffer: the event keeps its length and every other field, only the bytes are not copied.
package http1skip

import (
	"bytes"
	"net/http"
	"strconv"
	"time"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

const (
	// maxConnections bounds the connections the tracker follows, a new one beyond is not skipped
	maxConnections = 1 << 18
	// a connection without events for idleSweeps sweeps (of sweepPeriod) is forgotten once the analyzer
	// forgot it too
	sweepPeriod = 30 * time.Second
	idleSweeps  = 4
	// sweepCheckEvery is how many decisions pass between two looks at the clock
	sweepCheckEvery = 4096
	// peekSize is what the analyzer peeks to tell a message start (reader.IdentityMessageType)
	peekSize = 16
	// maxBoundaries bounds the message ends kept while the tracker waits for the analyzer
	maxBoundaries = 64
	// maxMessageAge: the calls of a message that runs longer are copied, the analyzer gives a body up
	// a minute after its head (in its own time, which lags behind)
	maxMessageAge = uint64(20 * time.Second)
	// maxGaps bounds the missing data ids kept of a connection, with more it is not skipped until a call
	// that overlapped no other one proves them all done (see clearGaps). A Go connection spends a data id on
	// a read that returns EAGAIN for nearly every read.
	maxGaps = 64
	// maxAwaited bounds the uploaded calls a connection waits for, see conn.awaited
	maxAwaited = 8
	// recentIDs is how many of the last decoded data ids a connection keeps, see conn.decoded
	recentIDs = 16
)

// Call is what the tracker reads of a socket data event before its bytes are copied
type Call struct {
	ConnectionID, RandomID uint64
	Protocol               enums.ConnectionProtocol
	SSL                    bool
	Direction              enums.SocketDataDirection
	DataID, PrevDataID     uint64
	// FirstDataID is the first data id of an event that stands for several socket calls (BPF coalesced the
	// skipped calls of a body, data ids FirstDataID to DataID), 0 for the event of one call
	FirstDataID       uint64
	Sequence          uint16
	Finished, Reduced bool
	// DataLen is the length of the bytes the event reports, TotalSize the size of the socket call
	DataLen   int
	TotalSize uint64
	// StartTime is the BPF time of the call
	StartTime uint64
	// InFlight is the count of the socket calls of the fd in flight when the call returned, itself included,
	// 0 when BPF does not know it: with 1, every call with a smaller data id had returned and uploaded what
	// it uploads before this call uploaded
	InFlight uint16
}

// firstID is the first data id the event stands for
func (c *Call) firstID() uint64 {
	if c.FirstDataID != 0 && c.FirstDataID < c.DataID {
		return c.FirstDataID
	}
	return c.DataID
}

// Tracker decides which socket calls are decoded without their bytes, on the reader goroutine only.
//
// A call without its bytes reads the same to the analyzer only while the analyzer counts it as a part of
// a Content-Length body: any other reader of the call (a peek for a message start, a head, a chunked
// body) would see the bytes missing. So the tracker frames the calls of a connection the way the analyzer
// does (the same head parser, the same body framing, in data id order) and skips a call only while it can
// prove the analyzer frames them alike: from a point where the analyzer held nothing (a connection it
// never saw, or one it reported clean, see ConnSync, at a message end of the tracker) every call since was
// framed by the tracker: a head it accepts, or a call of the body of such a message. Anything else (a call
// out of order or lost, a head it does not follow, bytes between messages) leaves the analyzer state open
// until it reports clean at a later message end; its calls are copied meanwhile.
//
// The analyzer reads the calls in data id order, which is not the order they upload in: BPF gives a call its
// data id when it enters and uploads it when it returns, so a call that entered before others (a blocking
// read posted before the writes of a body) can upload after them and sort in front of calls already
// skipped. So no call is skipped while a data id below the largest one decoded is missing (gaps, see
// hasHole): its call may still come. BPF spends a data id on a call that uploads nothing as well (a read
// that returns EAGAIN, an error, most of the reads of a Go connection that polls), which looks the same. A
// missing id is forgotten once its call is decoded, or once a call proves that it uploaded nothing: a call
// that returned while no other call of its fd was in flight (Call.InFlight 1) uploaded after every call
// with a smaller data id had returned, so those that uploaded are in the chain of the previous data ids
// in front of it. When every previous data id named so far was decoded (conn.awaited), the missing ids
// below such a call are calls that uploaded nothing (clearGaps).
//
// On top, as insurance, a skipped call neither starts nor ends with a start token (edgesTokenFree), no start
// token begins in the bytes the analyzer reads before it close enough to run into it (tailTokenFree), and
// the head of its message has none behind it, so the analyzer would not take it for a message start where
// it would most likely look if it were not in step.
type Tracker struct {
	// minSize is the smallest call skipped, smaller ones are as cheap to copy
	minSize int
	// LossEpoch changes whenever the reader lost events without telling which (btf.LossEpoch)
	LossEpoch func() uint64

	conns     map[connKey]*conn
	seq       uint64
	parser    reader.HeadParser
	decisions uint64
	gen       uint64
	lastSweep time.Time
}

// NewTracker creates a tracker; minSize is the smallest call it skips
func NewTracker(minSize int) *Tracker {
	return &Tracker{minSize: max(minSize, 1), LossEpoch: btf.LossEpoch, conns: make(map[connKey]*conn)}
}

type msgState uint8

const (
	stateIdle    msgState = iota // between messages
	stateBody                    // in a Content-Length body
	stateChunked                 // in a chunked body
)

// boundary is the end of a message while the tracker waits for the analyzer to be clean at one
type boundary struct {
	seq          uint64
	afterRequest bool
}

type conn struct {
	gen uint64
	// lastID is the data id of the last call, maxID the largest one
	lastID, maxID uint64
	// gaps are the data ids below maxID of calls not decoded yet: still to come, lost, or calls that
	// uploaded nothing. gapsLost: more were missing than gaps holds, or a data id came twice; the
	// connection is never skipped again.
	gaps     []uint64
	gapsLost bool
	// awaited are the previous data ids named by decoded calls whose call was not decoded yet: uploaded
	// calls still to come (in the per CPU buffer of another CPU) or lost. awaitedLost: more than maxAwaited,
	// or a chain the previous data ids cannot follow (a call without one in the middle of the connection);
	// the gaps are then only forgotten when their calls are decoded.
	awaited     []uint64
	awaitedLost bool
	// recent are the data ids of the last decoded calls (a ring), which tell a previous data id decoded
	// whatever the gaps know
	recent     [recentIDs]uint64
	recentNext int
	// tail is the last bytes the connection uploaded, in the order the tracker decoded them
	tail    [peekSize - 1]byte
	tailLen int
	// a call uploaded in several chunks: its data id and the sequence of the next chunk
	inCall  bool
	callID  uint64
	nextSeq uint16
	// dead: TLS or another protocol, never skipped
	dead  bool
	epoch uint64
	// unsyncedAt is the decode sequence of the last call the tracker could not frame (0 for none), and
	// boundaries the message ends since, one of which the analyzer has to report clean at
	unsyncedAt uint64
	boundaries []boundary

	// the message in progress
	state     msgState
	dir       enums.SocketDataDirection
	remaining int64
	framing   *buffer.ChunkedFraming
	request   bool
	method    string
	// insured: no start token behind the head, its body calls may be skipped
	insured bool
	started uint64
	// reqEnd is the decode sequence of the end of the request a response answers
	reqEnd uint64
	// lastSkipped is the data id of the last call skipped
	lastSkipped uint64
	// endWithCall: the message ends with the call whose later chunks are still to come
	endWithCall bool

	// the request that just ended, for the response that directly follows it
	lastReq    string
	lastReqDir enums.SocketDataDirection
	lastReqEnd uint64
}

// Decide returns the decode sequence of the event and whether it is decoded without its bytes. data is
// the bytes the event carries, still in the perf record.
func (t *Tracker) Decide(c *Call, data []byte) (seq uint64, skip bool) {
	t.seq++
	seq = t.seq
	k := connKey{id: c.ConnectionID, random: c.RandomID}
	cn := t.conns[k]
	if c.Protocol == enums.ConnectionProtocolUnknown {
		// not analyzed, only reported as a kernel log; the call is not in flight any more
		if cn != nil && c.Sequence == 0 {
			cn.noteIDs(c.firstID(), c.DataID)
		}
		return seq, false
	}
	t.maybeSweep()
	if cn == nil {
		if len(t.conns) >= maxConnections {
			return seq, false
		}
		cn = &conn{epoch: t.LossEpoch()}
		if lookup(k) != nil {
			cn.unsyncedAt = seq // the analyzer holds data of the connection the tracker never saw
		}
		t.conns[k] = cn
		trackedConnections.Add(1)
	}
	cn.gen = t.gen
	if cn.dead {
		return seq, false
	}
	if c.Protocol != enums.ConnectionProtocolHTTP || c.SSL {
		cn.dead = true
		cn.unsync(seq, reasonProtocol)
		return seq, false
	}
	follows := cn.follow(t, c, data, seq)
	cn.pushTail(data)
	if !follows {
		return seq, false
	}
	if !cn.synced(k, seq) {
		skipWaits.Add(1)
		return seq, false
	}
	cn.lastSkipped = c.DataID
	skippedEvents.Add(1)
	skippedBytes.Add(int64(len(data)))
	return seq, true
}

// NoteDropped tells the tracker that an event of the connection was lost before it was decoded
func (t *Tracker) NoteDropped(connectionID, randomID uint64) {
	if cn := t.conns[connKey{id: connectionID, random: randomID}]; cn != nil && !cn.dead {
		cn.unsync(t.seq+1, reasonLoss)
	}
}

// follow frames the call and tells whether it lies wholly inside a Content-Length body and may be skipped
//
//nolint:gocyclo // per-call framing state machine on the hot path, splitting it obscures the flow
func (cn *conn) follow(t *Tracker, c *Call, data []byte, seq uint64) bool {
	if epoch := t.LossEpoch(); epoch != cn.epoch {
		cn.epoch = epoch
		cn.unsync(seq, reasonLoss)
	}
	if c.Sequence != 0 {
		cn.followChunk(c, data, seq)
		return false
	}
	if c.DataID < cn.lastSkipped {
		// a call made before a skipped one comes after it: the calls overlapped (one entered before the
		// other uploaded), the only order the previous data id cannot prove. It may read the skipped one.
		overlaps.Add(1)
	}
	// the previous call uploaded on the connection is the last one decoded (none for the first one): no call
	// in between is missing or still to come, which the analyzer would read before this one
	chained := !cn.inCall && c.PrevDataID == cn.lastID && c.DataID > cn.maxID
	cn.noteChain(c)
	cn.lastID = c.DataID
	cn.noteIDs(c.firstID(), c.DataID)
	if c.InFlight == 1 {
		cn.clearGaps(c)
	}
	cn.inCall, cn.callID, cn.nextSeq = !c.Finished, c.DataID, 1
	lastReq, lastReqDir, lastReqEnd := cn.lastReq, cn.lastReqDir, cn.lastReqEnd
	cn.lastReq = ""
	if cn.state != stateIdle {
		switch {
		case !chained:
			cn.unsync(seq, reasonOrder)
		case c.Direction != cn.dir:
			cn.unsync(seq, reasonDirection)
		case c.StartTime > cn.started && c.StartTime-cn.started > maxMessageAge:
			cn.unsync(seq, reasonAge)
		case cn.state == stateChunked:
			cn.feedChunked(c, data, seq)
			return false
		default:
			skip := cn.followBody(c, data, seq, t.minSize)
			if skip && cn.hasHole() {
				holeWaits.Add(1)
				return false
			}
			return skip
		}
	} else if !chained {
		cn.unsync(seq, reasonOrder)
	}
	// between messages only a head the tracker follows keeps the analyzer in step
	head, ok := t.parser.Parse(data)
	if !ok {
		cn.unsync(seq, reasonUnframed)
		return false
	}
	cn.startMessage(c, data, head, chained, lastReq, lastReqDir, lastReqEnd, seq)
	return false
}

// followChunk frames a later chunk of a call
func (cn *conn) followChunk(c *Call, data []byte, seq uint64) {
	if !cn.inCall || c.DataID != cn.callID || c.Sequence != cn.nextSeq {
		cn.inCall = false
		cn.unsync(seq, reasonOrder)
		return
	}
	cn.nextSeq++
	cn.inCall = !c.Finished
	switch {
	case cn.state == stateChunked:
		cn.feedChunked(c, data, seq)
	case cn.state == stateIdle && cn.endWithCall && c.Finished:
		cn.closeMessage(seq)
	}
	// in a Content-Length body the call was accounted with its first chunk
}

// followBody accounts a call of a Content-Length body
func (cn *conn) followBody(c *Call, data []byte, seq uint64, minSize int) bool {
	if int64(c.TotalSize) > cn.remaining {
		// the body ends inside the call, the next message starts in it
		cn.unsync(seq, reasonOverrun)
		return false
	}
	cn.remaining -= int64(c.TotalSize)
	skip := cn.insured && c.Finished && !c.Reduced && c.DataLen == len(data) && uint64(len(data)) == c.TotalSize &&
		len(data) >= minSize && edgesTokenFree(data) && tailTokenFree(cn.tail[:cn.tailLen], data)
	if cn.remaining == 0 {
		cn.endMessage(c, seq)
	}
	return skip
}

// noteIDs records the data ids of a decoded event (its first chunk): one call, or a run of calls BPF
// coalesced (from first to last, the ids in between are calls of the run or calls that uploaded nothing)
func (cn *conn) noteIDs(first, last uint64) {
	if first < last {
		for i := 0; i < len(cn.gaps); {
			if g := cn.gaps[i]; g >= first && g < last {
				cn.gaps = append(cn.gaps[:i], cn.gaps[i+1:]...)
				continue
			}
			i++
		}
		if cn.maxID < first {
			// the ids up to the first are missing as usual, the ones of the run are not
			cn.noteID(first)
		}
		if cn.maxID < last-1 {
			cn.maxID = last - 1
		}
	}
	cn.noteID(last)
}

// noteChain follows the previous data ids of the decoded calls (conn.awaited): the call was uploaded, and
// the one its previous data id names was uploaded before it
func (cn *conn) noteChain(c *Call) {
	first := c.firstID()
	for i := 0; i < len(cn.awaited); {
		if a := cn.awaited[i]; a >= first && a <= c.DataID {
			if a != c.DataID {
				// a previous data id names a call inside a coalesced event: BPF never coalesces over the data id
				// of another upload, and a call names a held run by its last data id, so the chain is not
				// what it seems; nothing is proven from here on
				cn.awaitedLost = true
			}
			cn.awaited = append(cn.awaited[:i], cn.awaited[i+1:]...)
			continue
		}
		i++
	}
	switch {
	case cn.awaitedLost:
	case c.PrevDataID == 0:
		// only the first upload of a connection names none: a chain that starts again lost its start
		if cn.lastID != 0 {
			cn.awaitedLost = true
		}
	case c.PrevDataID == cn.lastID || cn.decoded(c.PrevDataID):
	case len(cn.awaited) == maxAwaited:
		cn.awaited, cn.awaitedLost = nil, true
	default:
		cn.awaited = append(cn.awaited, c.PrevDataID)
	}
	cn.recent[cn.recentNext] = c.DataID
	cn.recentNext = (cn.recentNext + 1) % recentIDs
}

// decoded tells whether the call of the data id was decoded, as far as the last decoded ids and the gaps
// tell
func (cn *conn) decoded(id uint64) bool {
	for _, r := range cn.recent {
		if r == id {
			return true
		}
	}
	if id > cn.maxID || cn.gapsLost {
		return false
	}
	for _, g := range cn.gaps {
		if g == id {
			return false
		}
	}
	return true
}

// clearGaps forgets the missing data ids below a call that returned while no other call of its fd was in
// flight, when every previous data id named so far was decoded: every call below it had returned before it
// uploaded, and every one of those that uploaded is in the chain in front of it, all decoded, so the
// missing ones uploaded nothing
func (cn *conn) clearGaps(c *Call) {
	if cn.awaitedLost || len(cn.awaited) > 0 || (len(cn.gaps) == 0 && !cn.gapsLost) {
		return
	}
	below := c.firstID()
	if cn.gapsLost {
		// which ids are missing is not known: only a call that is the newest one decoded proves them all
		if c.DataID == cn.maxID {
			cn.gaps, cn.gapsLost = nil, false
			gapClears.Add(1)
		}
		return
	}
	kept := cn.gaps[:0]
	for _, g := range cn.gaps {
		if g > below {
			kept = append(kept, g)
		}
	}
	if len(kept) != len(cn.gaps) {
		gapClears.Add(1)
	}
	cn.gaps = kept
}

// noteID records the data id of a decoded call (its first chunk)
func (cn *conn) noteID(id uint64) {
	if id > cn.maxID {
		if missing := id - cn.maxID - 1; missing > 0 && !cn.gapsLost {
			if missing > uint64(maxGaps-len(cn.gaps)) {
				cn.gaps, cn.gapsLost = nil, true
			} else {
				for g := cn.maxID + 1; g < id; g++ {
					cn.gaps = append(cn.gaps, g)
				}
			}
		}
		cn.maxID = id
		return
	}
	for i, g := range cn.gaps {
		if g == id {
			cn.gaps = append(cn.gaps[:i], cn.gaps[i+1:]...)
			return
		}
	}
	if !cn.gapsLost {
		// the id came twice: two calls that entered at once can take the same data id, the other one may
		// still come
		cn.gaps, cn.gapsLost = nil, true
	}
}

// hasHole tells whether a call with a smaller data id than a decoded one may still upload: the analyzer
// would read it in front of the calls decoded since
func (cn *conn) hasHole() bool {
	return cn.gapsLost || len(cn.gaps) > 0
}

// pushTail appends the bytes of a decoded call to the tail
func (cn *conn) pushTail(data []byte) {
	if len(data) >= len(cn.tail) {
		cn.tailLen = copy(cn.tail[:], data[len(data)-len(cn.tail):])
		return
	}
	keep := min(cn.tailLen, len(cn.tail)-len(data))
	copy(cn.tail[:keep], cn.tail[cn.tailLen-keep:cn.tailLen])
	cn.tailLen = keep + copy(cn.tail[keep:], data)
}

// feedChunked follows the chunked framing over the bytes of the call as the analyzer parses it
func (cn *conn) feedChunked(c *Call, data []byte, seq uint64) {
	if c.DataLen == 0 && c.TotalSize > 0 {
		// a call BPF uploaded without its content: chunk data the analyzer counts
		if !cn.framing.SkipData(int64(c.TotalSize)) {
			cn.unsync(seq, reasonOverrun)
		}
		return
	}
	consumed, done := cn.framing.Feed(data)
	switch {
	case done && consumed == len(data) && c.Finished && !c.Reduced:
		cn.endMessage(c, seq)
	case done:
		cn.unsync(seq, reasonOverrun) // the next message starts inside the call
	case c.Finished && c.Reduced:
		cn.unsync(seq, reasonOverrun) // bytes of the framing were not uploaded
	}
}

// startMessage frames the message the head starts
//
//nolint:gocyclo // message framing rules (methods, status codes, body kinds) checked in order
func (cn *conn) startMessage(c *Call, data []byte, head reader.Head, chained bool, lastReq string,
	lastReqDir enums.SocketDataDirection, lastReqEnd, seq uint64) {
	inCall := int64(c.TotalSize) - int64(head.Length) // body bytes in the call of the head
	length, ok := contentLength(head.Header)
	te := head.Header["Transfer-Encoding"]
	chunked := len(te) == 1 && te[0] == "chunked"
	if !ok || inCall < 0 || hasHeader(data[:head.Length], "Upgrade") ||
		(len(te) > 0 && (!chunked || head.Header["Content-Length"] != nil)) {
		cn.unsync(seq, reasonUnframed)
		return
	}
	noBody := false
	if head.Request {
		if head.Method == http.MethodConnect {
			cn.unsync(seq, reasonUnframed)
			return
		}
	} else {
		// a response only directly behind the request it answers, whose method tells whether it has a body
		code := head.StatusCode
		if !chained || lastReq == "" || lastReqDir == c.Direction || code == http.StatusSwitchingProtocols {
			cn.unsync(seq, reasonUnframed)
			return
		}
		noBody = lastReq == http.MethodHead || code/100 == 1 || code == http.StatusNoContent || code == http.StatusNotModified
	}
	cn.dir, cn.request, cn.method, cn.started, cn.reqEnd = c.Direction, head.Request, head.Method, c.StartTime, lastReqEnd
	cn.insured = tokenFree(data[head.Length:]) && tokenFree(data[max(0, len(data)-peekSize+1):])
	switch {
	case noBody:
		// the next message starts behind the head
		if inCall != 0 {
			cn.unsync(seq, reasonOverrun)
			return
		}
		cn.endMessage(c, seq)
	case chunked:
		cn.state, cn.framing = stateChunked, buffer.NewChunkedFraming()
		cn.feedChunked(c, data[head.Length:], seq)
	case length > 0:
		if inCall > length {
			cn.unsync(seq, reasonOverrun)
			return
		}
		cn.state, cn.remaining = stateBody, length-inCall
		if cn.remaining == 0 {
			cn.endMessage(c, seq)
		}
	default:
		// no framing: the analyzer reads the body to the end of the event, the next message starts with the
		// next call (a request without body, a response read to the close)
		if !c.Finished {
			cn.unsync(seq, reasonUnframed)
			return
		}
		cn.endMessage(c, seq)
	}
}

// endMessage ends the message with the call, or with its last chunk still to come
func (cn *conn) endMessage(c *Call, seq uint64) {
	cn.state, cn.framing = stateIdle, nil
	if c.Finished {
		cn.closeMessage(seq)
		return
	}
	cn.endWithCall = true
}

// closeMessage records the end of a message behind the call of seq
func (cn *conn) closeMessage(seq uint64) {
	cn.endWithCall = false
	if cn.request {
		cn.lastReq, cn.lastReqDir, cn.lastReqEnd = cn.method, cn.dir, seq
	}
	if cn.unsyncedAt != 0 {
		if len(cn.boundaries) == maxBoundaries {
			cn.boundaries = append(cn.boundaries[:0], cn.boundaries[1:]...)
		}
		cn.boundaries = append(cn.boundaries, boundary{seq: seq, afterRequest: cn.request})
	}
}

// unsync leaves the analyzer state open: the call of seq was not framed
func (cn *conn) unsync(seq uint64, reason giveUpReason) {
	if cn.state != stateIdle {
		giveUps[reason].Add(1)
	}
	unsyncedCalls.Add(1)
	cn.state, cn.framing, cn.endWithCall = stateIdle, nil, false
	cn.lastReq = ""
	cn.unsyncedAt = seq
	cn.boundaries = cn.boundaries[:0]
}

// synced tells whether the analyzer frames the calls as the tracker does: it reported clean at a message
// end the tracker framed every call behind
func (cn *conn) synced(k connKey, seq uint64) bool {
	if cn.unsyncedAt == 0 {
		return true
	}
	s := lookup(k)
	if s == nil {
		return false
	}
	clean := s.clean.Load()
	if clean < cn.unsyncedAt {
		return false
	}
	for _, b := range cn.boundaries {
		if b.seq != clean {
			continue
		}
		if !cn.request && cn.reqEnd <= clean {
			// the response answers a request the analyzer read before it was known to be in step: it may
			// not hold the request, and skip the response
			cn.unsync(seq, reasonUnframed)
			return false
		}
		cn.unsyncedAt, cn.boundaries = 0, nil
		return true
	}
	return false
}

// contentLength is the Content-Length of the head, 0 without one; false unless it is a single value of
// digits only (the analyzer would accept a sign)
func contentLength(header http.Header) (int64, bool) {
	values := header["Content-Length"]
	if len(values) == 0 {
		return 0, true
	}
	v := values[0]
	if len(values) > 1 || v == "" || len(v) > 18 {
		return 0, false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil
}

// hasHeader tells whether the head block has a header line of the name (ASCII case insensitive)
func hasHeader(block []byte, name string) bool {
	for len(block) > 0 {
		line := block
		if i := bytes.IndexByte(block, '\n'); i >= 0 {
			line, block = block[:i], block[i+1:]
		} else {
			block = nil
		}
		if len(line) > len(name) && line[len(name)] == ':' && equalFold(line[:len(name)], name) {
			return true
		}
	}
	return false
}

func equalFold(b []byte, s string) bool {
	for i := 0; i < len(b); i++ {
		x, y := b[i], s[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func (t *Tracker) maybeSweep() {
	t.decisions++
	if t.decisions%sweepCheckEvery != 0 {
		return
	}
	if now := time.Now(); now.Sub(t.lastSweep) >= sweepPeriod {
		t.sweep(now)
	}
}

// sweep forgets the connections idle for idleSweeps sweeps that the analyzer forgot as well
func (t *Tracker) sweep(now time.Time) {
	t.lastSweep = now
	t.gen++
	for k, cn := range t.conns {
		if t.gen-cn.gen >= idleSweeps && lookup(k) == nil {
			delete(t.conns, k)
			trackedConnections.Add(-1)
		}
	}
}
