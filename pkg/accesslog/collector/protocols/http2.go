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
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"

	"github.com/sirupsen/logrus"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// maxHTTP2StreamingTime is the max time of an HTTP/2 streaming, if the streaming is too long, then this streaming will split
var maxHTTP2StreamingTime = time.Minute * 3

// maxHTTP2StreamIdleTime is the max time a stream may stay open without completing, after that it is dropped
var maxHTTP2StreamIdleTime = time.Minute * 5

// http2GapWaitDuration is how long the parser waits for a socket event that is missing from the sequence
// (events of different CPUs can be delivered out of order) before it gives up and continues with a gap,
// which most likely desynchronizes the HPACK dynamic table of that direction
var http2GapWaitDuration = 3 * time.Second

// http2ArrivalWaitDuration is how long an event waits for a missing earlier upload since it reached the
// analysis, besides http2GapWaitDuration since the kernel made it, so a missing call is waited for also when the
// agent runs behind the kernel. Negative: the longest a call can reach the analysis after a call that returned
// after it (common.H2CDeliveryDelayBound: the kick period of the per-CPU batches, the flush period of a ring that
// is not woken up, the hand-over of a partial batch) with http2ArrivalMargin, and at least half of
// http2GapWaitDuration.
var http2ArrivalWaitDuration time.Duration = -1

// http2ArrivalMargin is what the arrival wait adds to the delivery delay bound: the scheduling of the reader and
// of the partitions
const http2ArrivalMargin = 500 * time.Millisecond

func http2ArrivalWait() time.Duration {
	if http2ArrivalWaitDuration >= 0 {
		return http2ArrivalWaitDuration
	}
	wait := http2GapWaitDuration / 2
	if bound := common.H2CDeliveryDelayBound(); bound > 0 && bound+http2ArrivalMargin > wait {
		wait = bound + http2ArrivalMargin
	}
	return wait
}

// SetHTTP2GapWaitDuration replaces http2GapWaitDuration and returns the value it had, for the tests that model
// the timing of the deliveries at a smaller scale
func SetHTTP2GapWaitDuration(d time.Duration) time.Duration {
	old := http2GapWaitDuration
	http2GapWaitDuration = d
	return old
}

const (
	// http2DefaultHeaderTableSize is the initial HPACK dynamic table size (RFC 7540 6.5.2)
	http2DefaultHeaderTableSize = 4096
	// http2MaxSaneControlFrameLength: control frames bigger than this mean the framing is out of sync
	http2MaxSaneControlFrameLength = 1 << 20
	// http2MaxFrameType is the highest frame type defined by RFC 7540 (CONTINUATION)
	http2MaxFrameType = 0x9
	// http2SettingHeaderTableSize is the SETTINGS_HEADER_TABLE_SIZE identifier
	http2SettingHeaderTableSize = 0x1
	// http2SettingMaxFrameSize is the SETTINGS_MAX_FRAME_SIZE identifier
	http2SettingMaxFrameSize = 0x5
	// http2MinMaxFrameSize / http2MaxMaxFrameSize bound SETTINGS_MAX_FRAME_SIZE (RFC 7540 6.5.2)
	http2MinMaxFrameSize = 1 << 14
	http2MaxMaxFrameSize = 1<<24 - 1
	// http2MaxAllowedHeaderTableSize bounds the HPACK dynamic table size a peer may switch to
	http2MaxAllowedHeaderTableSize = 16 << 20
)

var http2Log = logger.GetLogger("accesslog", "collector", "protocols", "http2")

type HTTP2StreamAnalyzer interface {
	HandleWholeStream(connection *PartitionConnection, stream *HTTP2Streaming) error
	OnProtocolBreak(connection *PartitionConnection, metrics *HTTP2Metrics)
}

// HTTP2DropEventListener is an optional interface of an HTTP2StreamAnalyzer. The parser drops a socket
// data event that cannot be parsed in order anymore (it arrived late, or its framing is broken); an
// analyzer that reports the kernel level detail from the data events themselves would lose the bytes of
// that socket call, so it is handed the event before it is released.
type HTTP2DropEventListener interface {
	OnDropEvent(connection *PartitionConnection, event buffer.SocketDataBuffer)
}

type HTTP2Protocol struct {
	ctx      *common.AccessLogContext
	analyzer HTTP2StreamAnalyzer
}

// followTruncation tells whether a DATA payload is followed past a socket call truncated by the upload
// limit (buffer.Buffer.SetFollowTruncation). It goes with skip_h2c_data_payload as the BPF side applied
// it: BPF then skips the calls that lie inside a payload, also behind a truncated call, and the parser
// must step over the bytes the truncated call did not upload to reach them. Off, the parser treats a
// truncated call as it always did.
func (r *HTTP2Protocol) followTruncation() bool {
	return r.ctx != nil && r.ctx.ConnectionMgr.SkipH2CDataPayload()
}

func NewHTTP2Analyzer(ctx *common.AccessLogContext, analyzer HTTP2StreamAnalyzer) *HTTP2Protocol {
	protocol := &HTTP2Protocol{ctx: ctx}
	if analyzer == nil {
		analyzer = nopHTTP2Analyzer{}
	}
	protocol.analyzer = analyzer
	return protocol
}

// nopHTTP2Analyzer is the analyzer of an HTTP2Protocol made without one: the streams are parsed and not reported
type nopHTTP2Analyzer struct{}

func (nopHTTP2Analyzer) HandleWholeStream(*PartitionConnection, *HTTP2Streaming) error { return nil }

func (nopHTTP2Analyzer) OnProtocolBreak(*PartitionConnection, *HTTP2Metrics) {}

// HTTP2Metrics keeps the per connection HTTP/2 parsing state.
//
// HTTP/2 has one independent HPACK compression context per direction (RFC 7540 4.3), and a frame
// never spans two socket calls of different directions, so the data events of the connection are
// re-partitioned per direction and each direction keeps its own HPACK decoder and read position.
type HTTP2Metrics struct {
	ConnectionID uint64
	RandomID     uint64
	Streams      map[uint32]*HTTP2Streaming

	// taken is the slice the events of the connection buffer are taken into every round, see Analyze
	taken []buffer.SocketDataBuffer

	// decoders / dirBuffers / lastConsumed are indexed by enums.SocketDataDirection (1: ingress, 2: egress)
	decoders     [3]*hpack.Decoder
	dirBuffers   [3]*buffer.Buffer
	lastConsumed [3]http2ConsumedPosition
	// headerBlocks collect the fields of the header block being decoded, they are the emit target of
	// the decoder of the same direction
	headerBlocks [3]HTTP2Headers
	// headerDesync is set for a direction once its HPACK decoder has failed: the dynamic table (RFC 7540
	// 4.3) is indexed, so a block that was never fed to the decoder (a lost HEADERS/CONTINUATION event, or
	// a connection captured mid stream) leaves every later block of that direction undecodable. There is
	// no resync: once set, the direction's header blocks are dropped without decoding instead of failing
	// one by one, and the connection is counted in rover_http2_connections_header_desync_total.
	headerDesync [3]bool
	// headerFrameWait is set for a direction while its parser waits for the rest of a HEADERS or CONTINUATION
	// frame: a missing call given up then may be the rest of that header block (see markSkippedHeaderBlocks)
	headerFrameWait [3]bool
	// dropScan is where the walk of the last socket event the parser dropped in a direction ended, so the next
	// chunk of the same call goes on from there (see droppedHeaderBytes)
	dropScan [3]http2DropScan
	// pendingHeaders holds the header block fragments of a HEADERS frame waiting for CONTINUATION frames
	pendingHeaders map[uint32]*http2PendingHeaders
	// streamAges and pendingAges link the open streams and the pending header blocks in the order they
	// were created, which is the order they expire in: dropIdleStreams only looks at the expired head
	// instead of every entry on every analysis (with many open streams that scan was most of the CPU)
	streamAges, pendingAges http2AgeList
	// maxFrameSize is the SETTINGS_MAX_FRAME_SIZE the peer announced for the frames of a direction
	// (0 when it has not been observed), a frame bigger than that means the framing is out of sync
	maxFrameSize [3]uint32
	// requestDirection is the direction the requests flow in, learned from the client preface or
	// the first request / response header block, 0 when still unknown
	requestDirection enums.SocketDataDirection

	// lastDataID is the largest data id of a socket event that was (at least partially) parsed, in any
	// direction
	lastDataID uint64
	// links tells which arrived events may be read: every event uploaded before them has arrived; the
	// parser waits for a missing event through it (see http2Links)
	links http2Links

	// the summaries of the skipped DATA payload (http2_summary.go), made with the metrics
	sums *http2Summaries

	// counters for debugging
	DecodeErrors, FramingErrors, LateSkips, DroppedStreams, Gaps uint64
}

type HTTP2Streaming struct {
	ReqHeader        HTTP2Headers
	RespHeader       HTTP2Headers
	ReqHeaderBuffer  *buffer.Buffer
	ReqBodyBuffer    *buffer.Buffer
	IsInResponse     bool
	Status           int
	RespHeaderBuffer *buffer.Buffer
	RespBodyBuffer   *buffer.Buffer
	Connection       *PartitionConnection
	// ReqSummaries and RespSummaries are the summaries of the calls BPF did not upload inside the DATA
	// payload of the request and of the response (summarize_h2c_payload), in the order of their calls, given
	// to the stream when it is reported (http2_summary.go)
	ReqSummaries  []HTTP2Summary
	RespSummaries []HTTP2Summary
	// summarized is the payload bytes of the stream, by direction, that the frames counted from summary gaps
	// (buffer.SummaryGap): what its summaries must bring
	summarized [3]uint64

	// age links the stream into HTTP2Metrics.streamAges, with the time it was created
	age http2Aged
}

// http2ConsumedPosition records the last position that was consumed by the parser in a direction,
// so bytes are never parsed twice when the buffer position is reset (late or out of order events).
type http2ConsumedPosition struct {
	valid     bool // false until the first frame of the direction is consumed
	dataID    uint64
	seq       int
	startTime uint64 // several events can share a data id and sequence (TLS uprobe), the time tells them apart
	offset    int
}

type http2PendingHeaders struct {
	direction enums.SocketDataDirection
	// slice holds the events the header block was read from so far. It is taken while the elements are
	// still linked: keeping a Position instead would break as soon as RemoveReadElements detaches (and
	// releases) the element the HEADERS frame started in, which happens before the CONTINUATION arrives.
	slice     *buffer.Buffer
	endStream bool
	fragment  []byte
	// decodeOnly: the block is only fed to the decoder when it completes, not attached to a stream (a
	// PUSH_PROMISE block, or the block of a stream reset or finished meanwhile), see http2_headers.go
	decodeOnly bool
	// age links the block into HTTP2Metrics.pendingAges, with the time it was created
	age http2Aged
}

// http2Aged is the link of a stream or a pending header block in an http2AgeList
type http2Aged struct {
	prev, next *http2Aged
	id         uint32
	created    time.Time
	linked     bool
}

// http2AgeList is an intrusive doubly linked list in creation order: every entry is appended when it is
// created (time.Now, so the list is sorted by created) and unlinked when it goes, in O(1) either way
type http2AgeList struct {
	head, tail *http2Aged
}

func (l *http2AgeList) push(a *http2Aged, id uint32, created time.Time) {
	a.id, a.created, a.linked = id, created, true
	a.prev, a.next = l.tail, nil
	if l.tail != nil {
		l.tail.next = a
	} else {
		l.head = a
	}
	l.tail = a
}

func (l *http2AgeList) remove(a *http2Aged) {
	if !a.linked {
		return
	}
	if a.prev != nil {
		a.prev.next = a.next
	} else {
		l.head = a.next
	}
	if a.next != nil {
		a.next.prev = a.prev
	} else {
		l.tail = a.prev
	}
	a.prev, a.next, a.linked = nil, nil, false
}

// addStream opens a stream
func (m *HTTP2Metrics) addStream(id uint32, streaming *HTTP2Streaming) {
	m.deleteStream(id)
	m.Streams[id] = streaming
	m.streamAges.push(&streaming.age, id, streaming.age.created)
	// the concurrency a new stream finds on its connection, itself included
	http2OpenStreams.Observe(int64(len(m.Streams)))
}

// http2OpenStreams is the number of streams open on an HTTP/2 connection, sampled whenever a stream opens
var http2OpenStreams = telemetry.NewHistogram("rover_http2_connection_open_streams",
	"Streams open on an HTTP/2 connection when a stream opens, the new one included",
	[]int64{1, 2, 4, 8, 16, 32, 64, 128, 256, 1024})

// deleteStream forgets the stream of the id, if there is one
func (m *HTTP2Metrics) deleteStream(id uint32) {
	if streaming := m.Streams[id]; streaming != nil {
		m.streamAges.remove(&streaming.age)
		delete(m.Streams, id)
	}
}

// setPending keeps the header block waiting for its CONTINUATION frames, in place of one of the stream
// that was still waiting
func (m *HTTP2Metrics) setPending(id uint32, pending *http2PendingHeaders) {
	m.deletePending(id)
	m.pendingHeaders[id] = pending
	m.pendingAges.push(&pending.age, id, pending.age.created)
}

// deletePending forgets the pending header block of the id, if there is one
func (m *HTTP2Metrics) deletePending(id uint32) {
	if pending := m.pendingHeaders[id]; pending != nil {
		m.pendingAges.remove(&pending.age)
		delete(m.pendingHeaders, id)
	}
}

type http2FrameResult int

const (
	// http2FrameConsumed: the frame has been fully read and handled, the buffer position moved behind it
	http2FrameConsumed http2FrameResult = iota
	// http2FrameWait: the frame is not completely received yet, keep the position and wait for more data
	http2FrameWait
	// http2FrameSkipElement: the data is out of sync (lost data or garbage), skip the current socket event
	http2FrameSkipElement
)

func (r *HTTP2Protocol) GenerateConnection(connectionID, randomID uint64) ProtocolMetrics {
	m := &HTTP2Metrics{
		ConnectionID:   connectionID,
		RandomID:       randomID,
		Streams:        make(map[uint32]*HTTP2Streaming),
		pendingHeaders: make(map[uint32]*http2PendingHeaders),
		sums:           &http2Summaries{},
	}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		m.decoders[d] = hpack.NewDecoder(http2DefaultHeaderTableSize, nil)
		// the encoder of the peer is trusted: accept any dynamic table size update it emits
		// (the real limit is negotiated through SETTINGS, which may be observed after the update)
		m.decoders[d].SetAllowedMaxDynamicTableSize(http2MaxAllowedHeaderTableSize)
		// the decoded fields go straight into the header block of the direction (handleHeaderBlock)
		m.decoders[d].SetEmitFunc(m.headerBlocks[d].emit)
	}
	return m
}

// http2TakenKeep is the largest slice of taken events a connection keeps for its next round
const http2TakenKeep = 4096

//nolint:gocyclo,funlen // per-connection HTTP/2 analysis round over both directions, one flow on the hot path
func (r *HTTP2Protocol) Analyze(connection *PartitionConnection, _ *AnalyzeHelper) error {
	m := connection.Metrics(enums.ConnectionProtocolHTTP2).(*HTTP2Metrics)
	connBuf := connection.Buffer(enums.ConnectionProtocolHTTP2)
	if http2Log.Enable(logrus.DebugLevel) {
		http2Log.Debugf("ready to analyze HTTP/2 protocol data, connection ID: %d, random ID: %d, data len: %d",
			m.ConnectionID, m.RandomID, connBuf.DataLength())
	}

	// the waits of this pass count up to what had reached the connection buffers before the take (http2_links.go)
	m.links.passStart()
	// re-partition the newly received data events per direction, the details stay in the connection buffer
	taken := connBuf.TakeDataEventsInto(m.taken)
	for _, event := range taken {
		// every event that arrived counts for the chain of the uploads, also one dropped here
		m.links.arrive(event.DataID(), http2LinkPrevDataID(&m.links, event))
		d := event.Direction()
		if d != enums.SocketDataDirectionIngress && d != enums.SocketDataDirectionEgress {
			// dropped: give its buffer and in-flight charge back
			buffer.ReleaseEvent(event.ReleaseBuffer())
			continue
		}
		if m.dirBuffers[d] == nil {
			m.dirBuffers[d] = buffer.NewViewBuffer(connBuf)
			// only the analysis of the connection touches the view (under the partition's analysis lock)
			m.dirBuffers[d].SetSingleOwner()
			m.dirBuffers[d].SetFollowTruncation(r.followTruncation())
			// a frame continues only into a following socket call that is linked: one whose earlier
			// calls have all arrived
			m.dirBuffers[d].SetSequenceCheck(m.links.continuable, m.links.waitedSince)
			// the rest of a call is waited for while what was read before it was missed is on its way
			m.dirBuffers[d].SetWaitClock(linkClock, m.links.deliveryBehind)
		}
		if n := buffer.SummarizedBefore(event); n > 0 {
			// the payload bytes BPF summarized in front of the event (http2_summary.go)
			m.dirBuffers[d].AppendDataEvent(buffer.NewSummaryGap(event, n, m.ConnectionID, m.RandomID))
		}
		m.dirBuffers[d].AppendDataEvent(event)
	}
	if taken != nil {
		// the slice is kept for the next round, without the events (a slice grown by a burst is not)
		clear(taken)
		if cap(taken) <= http2TakenKeep {
			m.taken = taken[:0]
		} else {
			m.taken = nil
		}
	}

	directions := []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress}
	for _, d := range directions {
		if m.dirBuffers[d] != nil {
			m.dirBuffers[d].DeleteExpireEvents(maxBufferExpireDuration)
		}
	}

	// the two directions are parsed in the global socket call order (data id), so a SETTINGS frame or
	// a request header block is always applied before the frames of the other direction that follow it
	var blocked [3]bool
analyze:
	for {
		// the head of every direction that still has data, including the directions that are blocked on
		// an incomplete frame: a blocked direction keeps its place in the global order, the other one
		// must not run past it (its frames would be reported before the ones that come earlier)
		var has [3]bool
		var headID [3]uint64
		var headTime [3]uint64
		for _, d := range directions {
			db := m.dirBuffers[d]
			if db == nil || !db.PrepareForReading() {
				continue
			}
			id, _, start, _, _ := db.CurrentPosition()
			has[d], headID[d], headTime[d] = true, id, start
		}
		var best enums.SocketDataDirection
		bestID := uint64(math.MaxUint64)
		for _, d := range directions {
			if has[d] && !blocked[d] && headID[d] < bestID {
				best, bestID = d, headID[d]
			}
		}
		if best == 0 {
			break
		}
		otherID, other := uint64(math.MaxUint64), enums.SocketDataDirection(0)
		for _, d := range directions {
			if has[d] && d != best && headID[d] < otherID {
				otherID, other = headID[d], d
			}
		}
		if otherID < bestID {
			// the earliest data of the connection belongs to a blocked direction (a direction that is
			// not blocked and has an earlier head would have been chosen as best)
			otherBuf := m.dirBuffers[other]
			nextCall := uint64(0)
			if otherBuf.IsCurrentSocketCallComplete() {
				// it is not waiting for a chunk of the call it is reading but for the following one:
				// the frames of the other direction that come before that call may be parsed
				nextCall = otherBuf.NextSocketCallDataID()
			}
			switch {
			case nextCall > bestID:
				otherID = nextCall
			case m.waitedFor(headTime[other]) >= http2GapWaitDuration:
				// the blocked direction is stale: a lost chunk must not stall the peer direction forever
				otherID = uint64(math.MaxUint64)
			default:
				// everything of this connection that comes next belongs to the blocked direction: wait
				// for its missing data instead of reporting later frames first
				break analyze
			}
		}
		// the next event must follow the last parsed one; otherwise an event is still missing: wait for it
		var head buffer.Position
		m.dirBuffers[best].PositionInto(&head)
		if r.waitForMissingEvent(m, &head) {
			break
		}
		if r.analyzeDirection(connection, connBuf, m, best, m.dirBuffers[best], otherID) {
			// data was parsed, so a direction that was blocked on it may be able to continue now
			blocked = [3]bool{}
		} else {
			blocked[best] = true
		}
	}
	m.links.pruneStale(max(http2GapWaitDuration, http2ArrivalWait()))
	r.dropIdleStreams(m)
	r.processSummaries(connection, m)
	return nil
}

// waitedFor is how long an event made at the kernel time has been waited for: since then, less how far the
// delivery of the events read was behind when the analysis pass started (a backlog between the reader and the
// partitions), so a backlog does not make the analysis give up on an event that is still on its way
func (m *HTTP2Metrics) waitedFor(kernelTime uint64) time.Duration {
	waited := time.Since(host.Time(kernelTime))
	if behind := m.links.deliveryBehind(); behind != math.MaxInt64 {
		if lag := time.Duration(linkClock() - behind); lag > 0 {
			waited -= lag
		}
	}
	return waited
}

// waitForMissingEvent reports whether an event uploaded before the event at the position has not been
// delivered yet (the event is not linked, see http2Links), so the parser should wait for it. The missing
// event is given up and parsing continues with a gap once the event at the position is http2GapWaitDuration
// old and has waited http2ArrivalWait since it reached the analysis: the second bound keeps the wait when the
// agent runs behind the kernel, since a missing call is delivered at most about the kick period of the
// per-CPU batches after the calls that returned after it.
func (r *HTTP2Protocol) waitForMissingEvent(m *HTTP2Metrics, pos *buffer.Position) bool {
	if m.links.linked(pos.DataID()) {
		if prev, stale := m.links.takeStaleRoot(pos.DataID()); stale {
			// the prune linked it while the upload before it had not arrived: the gap it would have been here
			m.Gaps++
			m.markParsed(prev)
			m.markSkippedHeaderBlocks(prev)
		}
		return false
	}
	if time.Since(host.Time(pos.StartTime())) < http2GapWaitDuration || m.links.waitedSince(pos.DataID()) < http2ArrivalWait() {
		return true
	}
	if http2Log.Enable(logrus.DebugLevel) {
		// guarded: the boxed arguments alone allocate on every gap
		http2Log.Debugf("give up waiting for the missing HTTP/2 socket event, connection ID: %d, last data id: %d, next data id: %d (prev: %d)",
			m.ConnectionID, m.lastDataID, pos.DataID(), pos.PrevDataID())
	}
	// an upload made before the first event the analysis saw that did not come within the start window was
	// made before the analysis (a connection captured mid stream), it is not lost
	if !m.links.missingSinceStart(pos.DataID()) {
		m.Gaps++
	}
	m.links.force(pos.DataID())
	m.markParsed(pos.PrevDataID())
	// the missing call may be the rest of a header block a direction is in the middle of
	m.markSkippedHeaderBlocks(pos.PrevDataID())
	return false
}

// markSkippedHeaderBlocks marks the directions that are in the middle of a header block (a HEADERS frame waiting
// for its CONTINUATION, or a HEADERS or CONTINUATION frame waiting for the rest of its bytes) header-desynced, when
// the parser gives up a missing call (hole, the data id it was missing): that call may hold the rest of the block,
// and the decoder would be fed without it
func (m *HTTP2Metrics) markSkippedHeaderBlocks(hole uint64) {
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		inBlock := m.headerFrameWait[d]
		if !inBlock {
			for _, pending := range m.pendingHeaders {
				if pending.direction == d {
					inBlock = true
					break
				}
			}
		}
		if inBlock {
			m.skippedHeaderBytes(d, http2DesyncForcedLink, hole)
		}
	}
}

// markParsed advances the sequence position; it never moves backwards (the other direction may be
// parsed after a frame of this direction already spanned past its events)
func (m *HTTP2Metrics) markParsed(dataID uint64) {
	if dataID > m.lastDataID {
		m.lastDataID = dataID
	}
}

// notifyDropEvent hands the event the reader head points to to the analyzer before it is released, so
// its kernel level detail is not lost with it
func (r *HTTP2Protocol) notifyDropEvent(connection *PartitionConnection, db *buffer.Buffer) {
	listener, ok := r.analyzer.(HTTP2DropEventListener)
	if !ok {
		return
	}
	if event := db.HeadDataEvent(); event != nil && !buffer.IsSummaryGap(event) {
		listener.OnDropEvent(connection, event)
	}
}

// analyzeDirection parses the frames of one direction up to the socket call with data id `limit`
// (inclusive). It returns false when nothing could be consumed because the data is incomplete.
//
//nolint:gocyclo,funlen // frame parse loop state machine (gaps, resync, limits) on the hot path
func (r *HTTP2Protocol) analyzeDirection(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, limit uint64) (progress bool) {
	for {
		if !db.PrepareForReading() {
			return progress
		}
		// the position is only looked at while the frame is parsed (a slice copies what it keeps of it)
		var at buffer.Position
		db.PositionInto(&at)
		pos := &at
		if pos.DataID() > limit {
			// the other direction has earlier data, let it catch up first
			return progress
		}
		if r.waitForMissingEvent(m, pos) {
			return progress
		}
		if last := &m.lastConsumed[d]; last.valid {
			if pos.DataID() < last.dataID || (pos.DataID() == last.dataID && pos.Seq() < last.seq) {
				// data older than what is already parsed arrived late: it cannot be parsed in order anymore
				http2Log.Debugf("skip late HTTP/2 data, connection ID: %d, data id: %d, seq: %d", m.ConnectionID, pos.DataID(), pos.Seq())
				if head := db.HeadDataEvent(); head == nil || !buffer.IsSummaryGap(head) {
					// a summary gap goes with its event, which is counted
					m.LateSkips++
					if head == nil || m.droppedHeaderBytes(d, head, pos.Offset()) {
						// the header block bytes it may hold were never fed to the decoder of the direction
						m.skippedHeaderBytes(d, http2DesyncLateSkip, pos.DataID())
					}
				}
				progress = true
				r.notifyDropEvent(connection, db)
				if db.RemoveCurrentElement() {
					return progress
				}
				continue
			}
			if pos.DataID() == last.dataID && pos.Seq() == last.seq && pos.StartTime() == last.startTime && pos.Offset() < last.offset {
				// the position was reset to the beginning of an element that is partially consumed, skip the consumed part
				if _, err := http2DiscardBytes(db, last.offset-pos.Offset()); err != nil {
					if errors.Is(err, io.EOF) {
						return progress
					}
					progress = true
					if head := db.HeadDataEvent(); head == nil || m.droppedHeaderBytes(d, head, last.offset) {
						m.skippedHeaderBytes(d, http2DesyncFramingError, pos.DataID())
					}
					r.notifyDropEvent(connection, db)
					if db.RemoveCurrentElement() {
						return progress
					}
					continue
				}
				progress = true
				if db.RemoveReadElements(false) {
					return progress
				}
				continue
			}
		}

		// a frame may continue in a following socket call of this direction, but only in one that
		// directly follows the data already parsed: otherwise a socket call in between is still missing
		result := r.parseFrame(connection, connBuf, m, d, db, pos)
		switch result {
		case http2FrameConsumed:
			http2FramesConsumed.Add(1)
			progress = true
			m.headerFrameWait[d] = false
			id, seq, start, offset, _ := db.CurrentPosition()
			m.lastConsumed[d] = http2ConsumedPosition{valid: true, dataID: id, seq: seq, startTime: start, offset: offset}
			m.markParsed(id)
			if db.RemoveReadElements(false) {
				return progress
			}
		case http2FrameSkipElement:
			m.FramingErrors++
			progress = true
			m.markParsed(pos.DataID()) // the skipped event still counts as parsed for the sequence
			m.headerFrameWait[d] = false
			if head := db.HeadDataEvent(); head == nil || m.droppedHeaderBytes(d, head, pos.Offset()) {
				// the parser resynchronizes at the next call: the header block bytes the rest of this one may
				// hold are never fed to the decoder
				m.skippedHeaderBytes(d, http2DesyncFramingError, pos.DataID())
			}
			r.notifyDropEvent(connection, db)
			if db.RemoveCurrentElement() || r.dropSkippedPayloads(connection, m, db) {
				return progress
			}
		case http2FrameWait:
			http2FrameWaits.Add(1)
			return progress
		}
	}
}

// dropSkippedPayloads drops the events at the head of the direction that stand for socket calls BPF
// uploaded without their bytes (buffer.PayloadSkippedBuffer) after the parser had to resynchronize: BPF
// only skips a call that lies inside a DATA payload, so none of them starts on a frame boundary, and the
// next frame header can only be in a call that was uploaded. They are dropped like the event that caused
// the resynchronization, without counting another framing error. It returns true when no event is left.
func (r *HTTP2Protocol) dropSkippedPayloads(connection *PartitionConnection, m *HTTP2Metrics, db *buffer.Buffer) bool {
	for {
		head := db.HeadDataEvent()
		if head == nil {
			return true
		}
		if !buffer.IsPayloadSkipped(head) || buffer.SummaryRunGap(head) != nil {
			// (a run of whole frames starts on a frame boundary)
			return false
		}
		m.markParsed(head.DataID())
		r.notifyDropEvent(connection, db)
		if db.RemoveCurrentElement() {
			return true
		}
	}
}

// parsePreface consumes the client connection preface at the start of a direction
func (r *HTTP2Protocol) parsePreface(m *HTTP2Metrics, d enums.SocketDataDirection, db *buffer.Buffer) http2FrameResult {
	var preface [len(http2.ClientPreface)]byte
	if _, err := db.Peek(preface[:]); err != nil {
		return http2ErrorResult(db, err)
	}
	if string(preface[:]) != http2.ClientPreface {
		return http2FrameSkipElement
	}
	if err := db.ReadUntilBufferFull(preface[:]); err != nil {
		return http2FrameSkipElement
	}
	m.requestDirection = d
	http2Log.Debugf("found HTTP/2 client preface, connection ID: %d, direction: %d", m.ConnectionID, d)
	return http2FrameConsumed
}

// The parser's own counters: the frames it completed and their payload bytes, and how often a frame
// could not be completed yet. The analysis restarts a frame from its first byte whenever a pass ends
// before the frame is whole (only a completed frame commits the read position), so waits over frames
// says how often that happens.
var (
	http2PayloadBytes   atomic.Int64
	http2FramesConsumed atomic.Int64
	http2FrameWaits     atomic.Int64
	// http2HeaderDesyncs counts the connection directions whose HPACK decoder went out of sync and cannot
	// recover (see HTTP2Metrics.headerDesync): each such direction stops producing protocol logs, so this
	// explains a protocol log rate far below the request rate after perf ring loss.
	http2HeaderDesyncs atomic.Int64
)

func init() {
	telemetry.Register("rover_http2_payload_bytes_total",
		"Payload bytes of the frames the HTTP/2 parser completed, each counted once",
		telemetry.Counter, func() float64 { return float64(http2PayloadBytes.Load()) })
	telemetry.Register("rover_http2_frames_total",
		"Frames the HTTP/2 parser completed", telemetry.Counter,
		func() float64 { return float64(http2FramesConsumed.Load()) })
	telemetry.Register("rover_http2_frame_waits_total",
		"Times a frame could not be completed because the rest of it had not arrived yet",
		telemetry.Counter, func() float64 { return float64(http2FrameWaits.Load()) })
	telemetry.Register("rover_http2_connections_header_desync_total",
		"HTTP/2 connection directions whose HPACK decoder lost sync and can no longer be decoded (no resync exists)",
		telemetry.Counter, func() float64 { return float64(http2HeaderDesyncs.Load()) })
}

// markHeaderDesync records that a direction's HPACK decoder has lost sync, once per direction, but only
// when a gap was seen on this connection: a decode failure that follows a missing (lost) event is the
// unrecoverable case the HPACK investigation targets, so the direction stops being decoded from here on.
// A connection captured mid stream also fails to decode but keeps today's per-block behavior (its blocks
// that use only the static table still decode), so it is not marked and not stopped.
func (m *HTTP2Metrics) markHeaderDesync(d enums.SocketDataDirection) {
	if m.Gaps == 0 {
		return
	}
	m.setHeaderDesync(d, http2DesyncDecodeError, math.MaxUint64)
}

// skippedHeaderBytes records that the parser went past bytes of direction d that may hold a part of a header
// block without feeding them to the decoder (cause, at the socket call hole): the dynamic table of the direction
// may be wrong from here on, so the direction is marked header-desynced
func (m *HTTP2Metrics) skippedHeaderBytes(d enums.SocketDataDirection, cause int, hole uint64) {
	m.setHeaderDesync(d, cause, hole)
}

// setHeaderDesync marks the direction header-desynced (once): its header blocks are no longer decoded, and the
// open streams whose header block of that direction was decoded from a socket call after the hole are dropped,
// since the decoder may already have been wrong then. A stream already reported cannot be taken back. The cause
// the callers name is not kept.
func (m *HTTP2Metrics) setHeaderDesync(d enums.SocketDataDirection, _ int, hole uint64) {
	if int(d) >= len(m.headerDesync) || d == 0 || m.headerDesync[d] {
		return
	}
	m.headerDesync[d] = true
	http2HeaderDesyncs.Add(1)
	var drop []uint32
	for id, streaming := range m.Streams {
		for _, b := range []*buffer.Buffer{streaming.ReqHeaderBuffer, streaming.RespHeaderBuffer} {
			if first := b.FirstSocketBuffer(); first != nil && first.Direction() == d && first.DataID() > hole {
				drop = append(drop, id)
				break
			}
		}
	}
	for _, id := range drop {
		m.deleteStream(id)
	}
}

// parseFrame reads one frame (or the client connection preface) from the current position
//
//nolint:gocyclo,funlen // frame parser state machine on the per-event hot path
func (r *HTTP2Protocol) parseFrame(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, startPos *buffer.Position) http2FrameResult {
	// whole DATA frames BPF summarized as a run come where a frame header is expected
	if run := buffer.SummaryRunGap(db.HeadDataEvent()); run != nil && startPos.Offset() == 0 {
		return r.handleSummaryRun(connection, connBuf, m, d, db, run, startPos)
	}
	// a whole frame header must be available before reading it: ReadFrameHeader consumes what it can
	// before failing, which would leave the direction positioned inside the header
	var head [http2FrameHeaderLen]byte
	if n, err := db.Peek(head[:]); err != nil || n != len(head) {
		if err == nil {
			return http2FrameWait
		}
		return http2ErrorResult(db, err)
	}
	// the client connection preface (RFC 7540 3.5) precedes the first frame of the client direction
	if !m.lastConsumed[d].valid && bytes.HasPrefix([]byte(http2.ClientPreface), head[:]) {
		return r.parsePreface(m, d, db)
	}
	// the 101 response of an h2c upgrade (RFC 7540 3.2) precedes the first frame of the server direction
	if !m.lastConsumed[d].valid && string(head[:]) == http2UpgradeResponsePrefix {
		return r.parseUpgradeResponse(connection, m, d, db, startPos)
	}

	// the header is the bytes just peeked: read past them and take them as http2.ReadFrameHeader would (the same
	// reads, without its pooled buffer)
	if err := db.ReadUntilBufferFull(head[:]); err != nil {
		http2Log.Debugf("failed to read HTTP/2 frame header, connection ID: %d, error: %v", m.ConnectionID, err)
		return http2ErrorResult(db, err)
	}
	header := http2.FrameHeader{
		Length:   uint32(head[0])<<16 | uint32(head[1])<<8 | uint32(head[2]),
		Type:     http2.FrameType(head[3]),
		Flags:    http2.Flags(head[4]),
		StreamID: binary.BigEndian.Uint32(head[5:]) & (1<<31 - 1),
	}
	if (header.Type > http2MaxFrameType && !http2IgnoredExtensionFrame(&header) && !m.frameBoundaryProven(d, db, startPos)) ||
		header.Length > m.maxFrameLength(d) {
		// not a frame boundary (data lost or the connection was not captured from a frame boundary).
		// DATA frames are bounded too: a mis-framed header with type 0 carries a random 24 bit length,
		// and waiting for up to 16MB of a frame that does not exist blocks the whole direction while
		// every new event of it is kept in memory.
		http2Log.Debugf("HTTP/2 framing out of sync, connection ID: %d, type: %d, length: %d", m.ConnectionID, header.Type, header.Length)
		return http2FrameSkipElement
	}

	switch header.Type {
	case http2.FrameHeaders:
		payload, result := http2ReadPayload(db, header.Length)
		if result != http2FrameConsumed {
			m.headerFrameWait[d] = result == http2FrameWait
			return result
		}
		return r.handleHeaders(connection, connBuf, m, d, db, &header, startPos, payload)
	case http2.FrameContinuation:
		payload, result := http2ReadPayload(db, header.Length)
		if result != http2FrameConsumed {
			m.headerFrameWait[d] = result == http2FrameWait
			return result
		}
		return r.handleContinuation(connection, connBuf, m, d, db, &header, startPos, payload)
	case http2.FramePushPromise:
		// carries a header block of the pushing direction: it must be decoded to keep the dynamic table in sync
		payload, result := http2ReadPayload(db, header.Length)
		if result != http2FrameConsumed {
			m.headerFrameWait[d] = result == http2FrameWait
			return result
		}
		return r.handlePushPromise(m, d, &header, payload)
	case http2.FrameData:
		return r.handleData(connection, connBuf, m, d, db, &header)
	case http2.FrameSettings:
		payload, result := http2ReadPayload(db, header.Length)
		if result != http2FrameConsumed {
			return result
		}
		r.handleSettings(m, d, &header, payload)
		return http2FrameConsumed
	case http2.FrameRSTStream:
		if _, err := http2DiscardBytes(db, int(header.Length)); err != nil {
			return http2ErrorResult(db, err)
		}
		r.resetStreamSummaries(connection, m, header.StreamID, m.Streams[header.StreamID])
		m.deleteStream(header.StreamID)
		// a header block of the stream still waiting for its CONTINUATION frames (the peer's, which may already
		// be on the way) is still decoded when it completes, or the dynamic table of its direction would miss it
		m.decodeOnlyPending(header.StreamID)
		return http2FrameConsumed
	case http2.FrameGoAway:
		payload, result := http2ReadPayload(db, header.Length)
		if result != http2FrameConsumed {
			return result
		}
		r.handleGoAway(connection, m, d, payload)
		return http2FrameConsumed
	default:
		// PRIORITY, PING, WINDOW_UPDATE, the extension frames (http2IgnoredExtensionFrame) and the unknown
		// types at a proven frame boundary (frameBoundaryProven): nothing to analyze
		if _, err := http2DiscardBytes(db, int(header.Length)); err != nil {
			return http2ErrorResult(db, err)
		}
		return http2FrameConsumed
	}
}

// handleGoAway forgets the streams the sender of the GOAWAY will not process: the ones its peer opened above the
// last stream id (RFC 9113 6.8), which get no response and would otherwise wait until they are idle
func (r *HTTP2Protocol) handleGoAway(connection *PartitionConnection, m *HTTP2Metrics, d enums.SocketDataDirection,
	payload []byte) {
	if len(payload) < 8 || m.requestDirection == 0 {
		return
	}
	last := binary.BigEndian.Uint32(payload[:4]) & 0x7fffffff
	// the client opens the odd streams, the server the even ones (a push)
	peerParity := uint32(1)
	if d == m.requestDirection {
		peerParity = 0
	}
	for id, streaming := range m.Streams {
		if id > last && id%2 == peerParity {
			r.resetStreamSummaries(connection, m, id, streaming)
			m.deleteStream(id)
		}
	}
}

func (r *HTTP2Protocol) handleHeaders(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader, startPos *buffer.Position, payload []byte) http2FrameResult {
	fragment, ok := http2StripPadding(payload, header.Flags.Has(http2.FlagHeadersPadded))
	if !ok {
		return http2FrameSkipElement
	}
	if header.Flags.Has(http2.FlagHeadersPriority) {
		if len(fragment) < 5 {
			return http2FrameSkipElement
		}
		fragment = fragment[5:]
	}
	endStream := header.Flags.Has(http2.FlagHeadersEndStream)
	if !header.Flags.Has(http2.FlagHeadersEndHeaders) {
		// the header block continues in CONTINUATION frames
		m.setPending(http2PendingKey(header.StreamID, d), &http2PendingHeaders{
			direction: d, slice: db.Slice(true, startPos, db.Position()), endStream: endStream,
			fragment: append([]byte(nil), fragment...), age: http2Aged{created: time.Now()},
		})
		return http2FrameConsumed
	}
	return r.handleHeaderBlock(connection, connBuf, m, d, db.Slice(true, startPos, db.Position()),
		header.StreamID, endStream, fragment)
}

func (r *HTTP2Protocol) handleContinuation(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader, startPos *buffer.Position,
	payload []byte) http2FrameResult {
	key := http2PendingKey(header.StreamID, d)
	pending := m.pendingHeaders[key]
	if pending == nil || pending.direction != d {
		// the start of the block was not decoded (lost, skipped or dropped with its stream): the decoder misses it
		m.skippedHeaderBytes(d, http2DesyncOrphanContinuation, startPos.DataID())
		return http2FrameConsumed
	}
	if len(pending.fragment)+len(payload) > http2MaxSaneControlFrameLength {
		// a peer that never ends the header block would grow this fragment without bound
		http2Log.Debugf("the HTTP/2 header block is too big, drop it, connection ID: %d, stream ID: %d",
			m.ConnectionID, header.StreamID)
		m.deletePending(key)
		m.FramingErrors++
		// the block is never decoded
		m.skippedHeaderBytes(d, http2DesyncFramingError, startPos.DataID())
		return http2FrameConsumed
	}
	pending.fragment = append(pending.fragment, payload...)
	if !pending.decodeOnly {
		pending.slice = buffer.AppendSlices(true, connBuf, pending.slice, db.Slice(true, startPos, db.Position()))
	}
	if !header.Flags.Has(http2.FlagContinuationEndHeaders) {
		return http2FrameConsumed
	}
	m.deletePending(key)
	if pending.decodeOnly {
		// a PUSH_PROMISE block, or one of a stream already reset or finished: only the dynamic table needs it
		m.decodeOnlyHeaderBlock(d, pending.fragment)
		return http2FrameConsumed
	}
	return r.handleHeaderBlock(connection, connBuf, m, d, pending.slice, header.StreamID, pending.endStream, pending.fragment)
}

// handleHeaderBlock decodes a complete header block and attaches it to the stream. `headerSlice` are
// the events the whole block was read from (HEADERS plus its CONTINUATION frames).
func (r *HTTP2Protocol) handleHeaderBlock(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, headerSlice *buffer.Buffer, streamID uint32, endStream bool, block []byte) http2FrameResult {
	if int(d) < len(m.headerDesync) && m.headerDesync[d] {
		// the decoder of this direction already lost sync and cannot recover: feeding it would still fail
		// and would corrupt its dynamic table further. Drop the block (and its stream) without decoding.
		m.deleteStream(streamID)
		return http2FrameConsumed
	}
	headers := &m.headerBlocks[d]
	headers.reset()
	if err := http2DecodeHeaderBlock(m.decoders[d], block); err != nil {
		// the HPACK dynamic table of this direction is out of sync: a connection captured mid stream, or a
		// lost HEADERS/CONTINUATION event. An indexed dynamic table cannot be resynced, so every later block
		// of this direction would fail too: mark the direction and stop decoding it instead of failing per
		// block. The connection is counted once in rover_http2_connections_header_desync_total.
		http2Log.Debugf("failed to decode HTTP/2 header block, connection ID: %d, stream ID: %d, error: %v",
			m.ConnectionID, streamID, err)
		m.DecodeErrors++
		m.markHeaderDesync(d)
		m.deleteStream(streamID)
		return http2FrameConsumed
	}
	if !http2ValidPseudoHeaders(headers) {
		// the block decoded, but against a dynamic table that is out of sync (e.g. after lost socket
		// events): the values are mixed up, reporting them would create garbage endpoints. As above, the
		// dynamic table cannot be trusted from here on, so the direction is marked and no longer decoded.
		http2Log.Debugf("HTTP/2 header block with invalid pseudo headers, connection ID: %d, stream ID: %d, headers: %v",
			m.ConnectionID, streamID, headers)
		m.DecodeErrors++
		m.markHeaderDesync(d)
		m.deleteStream(streamID)
		return http2FrameConsumed
	}
	isRequest := r.isRequestHeaders(m, d, streamID, headers)
	if isRequest && headers.has(http2HeaderPath) {
		// report the path without the query string, like the HTTP/1 analyzer does (URL.Path)
		path := headers.values[http2HeaderPath]
		if i := strings.IndexByte(path, '?'); i >= 0 {
			headers.set(http2HeaderPath, path[:i])
		}
	}

	streaming := m.Streams[streamID]
	if streaming == nil {
		streaming = &HTTP2Streaming{
			Connection: connection,
			age:        http2Aged{created: time.Now()},
		}
		m.addStream(streamID, streaming)
	}
	if isRequest {
		streaming.ReqHeader.merge(headers)
		streaming.ReqHeaderBuffer = http2AppendHeaderSlice(connBuf, streaming.ReqHeaderBuffer, headerSlice)
		return http2FrameConsumed
	}

	if headers.has(http2HeaderStatus) {
		status := headers.values[http2HeaderStatus]
		code, err := strconv.ParseInt(status, 10, 64)
		if err != nil {
			log.Warnf("cannot parse status code: %s", status)
			code = 200
		}
		streaming.Status = int(code)
	}
	streaming.IsInResponse = true
	streaming.RespHeader.merge(headers)
	streaming.RespHeaderBuffer = http2AppendHeaderSlice(connBuf, streaming.RespHeaderBuffer, headerSlice)
	if endStream {
		r.finishStream(connection, m, streamID, streaming)
	}
	return http2FrameConsumed
}

func (r *HTTP2Protocol) handleData(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader) http2FrameResult {
	streaming := m.Streams[header.StreamID]
	// the start of the body is only read while the frame is appended (the end is kept, as the end of the body)
	var start buffer.Position
	db.PositionInto(&start)
	bodyStart := &start
	if streaming == nil {
		// unknown stream (reset, or not captured from the beginning), the data is not interesting
		if _, err := http2DiscardBytes(db, int(header.Length)); err != nil {
			return http2ErrorResult(db, err)
		}
		return http2FrameConsumed
	}
	if header.Flags.Has(http2.FlagDataPadded) {
		var padLen [1]byte
		if err := db.ReadUntilBufferFull(padLen[:]); err != nil {
			return http2ErrorResult(db, err)
		}
		if int(padLen[0]) >= int(header.Length) {
			return http2FrameSkipElement
		}
		db.PositionInto(&start)
		dataLen := int(header.Length) - 1 - int(padLen[0])
		data, err := http2DiscardBytes(db, dataLen)
		if err != nil {
			return r.truncatedData(connection, connBuf, m, d, db, header, streaming, bodyStart, dataLen-data.Consumed,
				data.Virtual, data.Unread, err, 0)
		}
		bodyEnd := db.Position()
		if pad, err := http2DiscardBytes(db, int(padLen[0])); err != nil {
			// only the padding runs into the bytes a truncated call did not upload: the data part is
			// whole, so it goes into the body, and the parser resynchronizes at the next call
			if padMissing := int64(padLen[0]) - int64(pad.Consumed); padMissing <= 0 || pad.Unread < padMissing {
				return http2ErrorResult(db, err)
			}
			return r.appendDataAndResync(connection, connBuf, m, d, db, header, streaming, bodyStart, bodyEnd, data.Virtual, 0)
		}
		return r.appendDataWithVirtual(connection, connBuf, m, d, db, header, streaming, bodyStart, bodyEnd, data.Virtual, 0)
	}
	// the payload is counted, never read: the socket calls BPF uploaded without their bytes because they
	// lie inside it (skip_h2c_data_payload) are in the body as their sizes, through the virtual bytes
	data, err := http2DiscardBytes(db, int(header.Length))
	if err != nil {
		return r.truncatedData(connection, connBuf, m, d, db, header, streaming, bodyStart,
			int(header.Length)-data.Consumed, data.Virtual, data.Unread, err, data.Summarized)
	}
	return r.appendDataWithVirtual(connection, connBuf, m, d, db, header, streaming, bodyStart, db.Position(), data.Virtual,
		data.Summarized)
}

// handleSummaryRun takes a run of whole DATA frames BPF summarized (buffer.SummaryGap with a stream, see
// http2_summary.go) at a frame boundary: gap.Frames DATA frames of the stream without END_STREAM or PADDED, each
// a socket call of its own today, uploaded cut behind its header. handleData reads nothing of such a frame but
// its length and its stream, and counts its payload into the body; this does it for the frames at once: the
// payload is the size of the run less the frame headers, counted as virtual bytes of the body (the gap, which
// carries no bytes, is the slice of the body), and the summaries of the stream bring the details of its calls,
// headers included (summarized).
//
// When the last frame of the run is open (gap.Open), the rest of its payload follows the gap: it is
// discarded from there as handleData discards the payload of a frame (the bytes of the events behind the gap, the
// calls BPF uploaded without their bytes, the summarized bytes in front of a later event), and the frame, the run with
// its rest, ends where it ends.
func (r *HTTP2Protocol) handleSummaryRun(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, gap *buffer.SummaryGap, startPos *buffer.Position) http2FrameResult {
	frames := int64(gap.Frames)
	// (a head, payload of the frame in front of the run, went with that frame: buffer.SummaryGap)
	size := int64(gap.Size - gap.Head)
	payload := size - frames*http2FrameHeaderLen
	open := gap.Open
	if frames == 0 || payload < 0 || open < 0 || payload+open > frames*int64(m.maxFrameLength(d)) || (!gap.Headed && gap.Head > 0) {
		// not frames the parser would take (BPF summarizes no other)
		return http2FrameSkipElement
	}
	if gap.Headed && gap.Head == 0 {
		// the frame in front of the run was not parsed (the parser resynchronized here, behind lost events): the head is
		// not known, so neither are the frames of the run. They are stepped over, with the rest of an open last frame
		// (known), so the parser goes on at the next frame header as it would behind the frames of the run.
		m.FramingErrors++
		if open > 0 {
			if _, err := http2DiscardBytes(db, int(open)); err != nil {
				return http2ErrorResult(db, err)
			}
		}
		return http2FrameConsumed
	}
	streaming := m.Streams[gap.Stream]
	header := http2.FrameHeader{Type: http2.FrameData, StreamID: gap.Stream, Length: uint32(payload + open)}
	virtual, summarized := payload, size
	if open > 0 {
		// from the gap on: the gap itself holds no bytes, the rest of the frame is behind it
		data, err := http2DiscardBytes(db, int(open))
		if err != nil {
			if streaming == nil {
				return http2ErrorResult(db, err)
			}
			return r.truncatedData(connection, connBuf, m, d, db, &header, streaming, startPos, int(open)-data.Consumed,
				virtual+data.Virtual, data.Unread, err, summarized+data.Summarized)
		}
		virtual += data.Virtual
		summarized += data.Summarized
	}
	// the frames of the run but the one the caller counts
	http2FramesConsumed.Add(frames - 1)
	if streaming == nil {
		// unknown stream (reset, or not captured from the beginning), the data is not interesting
		return http2FrameConsumed
	}
	// the gap holds no bytes: the body slice is the gap itself, its payload all virtual (the end is kept by the
	// body, so it is a position of its own), and the bytes of the rest of an open frame behind it
	return r.appendDataWithVirtual(connection, connBuf, m, d, db, &header, streaming, startPos, db.Position(), virtual,
		summarized)
}

// truncatedData handles a DATA frame whose payload stops at a socket call BPF did not upload in full.
// The kernel did transfer those bytes, so the frame is complete as far as the connection is concerned
// and only the agent is missing them: the body keeps the real length through virtual bytes and the
// stream is finished, instead of waiting for a remainder that will never arrive and leaking the stream
// until the idle timeout. This is what the HTTP/1 reader already does with a truncated message.
// virtual is what the discard already counted without reading (skipped calls, and the not uploaded end
// of a truncated call the payload ran past), unread what the call it stopped at did not upload.
func (r *HTTP2Protocol) truncatedData(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader, streaming *HTTP2Streaming,
	bodyStart *buffer.Position, missing int, virtual, unread int64, err error, summarized int64) http2FrameResult {
	if missing <= 0 || unread < int64(missing) {
		// nothing is missing, or the bytes are missing for another reason than the upload limit: do not
		// invent them
		return http2ErrorResult(db, err)
	}
	http2Log.Debugf("DATA frame of stream %d truncated by the upload limit, %d bytes were not uploaded, "+
		"the body keeps its real length", header.StreamID, missing)
	return r.appendDataAndResync(connection, connBuf, m, d, db, header, streaming, bodyStart, db.Position(),
		virtual+int64(missing), summarized)
}

// appendDataAndResync appends a DATA frame that ends in the bytes a truncated call did not upload, and
// resynchronizes at the next call: the remainder of the truncated call is not readable
func (r *HTTP2Protocol) appendDataAndResync(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader, streaming *HTTP2Streaming,
	bodyStart, bodyEnd *buffer.Position, virtual, summarized int64) http2FrameResult {
	if result := r.appendDataWithVirtual(connection, connBuf, m, d, db, header, streaming, bodyStart, bodyEnd,
		virtual, summarized); result != http2FrameConsumed {
		return result
	}
	return http2FrameSkipElement
}

func (r *HTTP2Protocol) appendDataWithVirtual(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader, streaming *HTTP2Streaming,
	bodyStart, bodyEnd *buffer.Position, virtual, summarized int64) http2FrameResult {
	http2PayloadBytes.Add(int64(header.Length))
	if summarized > 0 && int(d) < len(streaming.summarized) {
		// the summaries of the stream bring the details of these bytes (http2_summary.go)
		streaming.summarized[d] += uint64(summarized)
	}
	endStream := header.Flags.Has(http2.FlagDataEndStream)
	if r.isRequestDirection(m, d, streaming) {
		streaming.ReqBodyBuffer = http2AppendBody(connBuf, streaming.ReqBodyBuffer, db, bodyStart, bodyEnd, virtual)
		r.validateIsStreamOpenTooLong(connection, m, header.StreamID, streaming)
		return http2FrameConsumed
	}
	streaming.IsInResponse = true
	streaming.RespBodyBuffer = http2AppendBody(connBuf, streaming.RespBodyBuffer, db, bodyStart, bodyEnd, virtual)
	if endStream {
		r.finishStream(connection, m, header.StreamID, streaming)
	}
	return http2FrameConsumed
}

// handleSettings applies SETTINGS_HEADER_TABLE_SIZE: the sender of the frame announces the maximum
// dynamic table size it accepts for the header blocks it receives, i.e. the opposite direction.
func (r *HTTP2Protocol) handleSettings(m *HTTP2Metrics, d enums.SocketDataDirection, header *http2.FrameHeader, payload []byte) {
	if header.Flags.Has(http2.FlagSettingsAck) {
		return
	}
	for i := 0; i+6 <= len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		value := binary.BigEndian.Uint32(payload[i+2 : i+6])
		switch id {
		case http2SettingHeaderTableSize:
			if dec := m.decoders[http2OppositeDirection(d)]; dec != nil {
				dec.SetAllowedMaxDynamicTableSize(value)
			}
		case http2SettingMaxFrameSize:
			if value >= http2MinMaxFrameSize && value <= http2MaxMaxFrameSize {
				m.maxFrameSize[http2OppositeDirection(d)] = value
			}
		}
	}
}

// maxFrameLength is the biggest frame the peer may send in this direction. Until the peer's SETTINGS
// frame has been seen, the sanity bound of a control frame is used (the real default, 16KB, would
// reject the legitimately bigger DATA frames of a connection that was captured mid stream).
func (m *HTTP2Metrics) maxFrameLength(d enums.SocketDataDirection) uint32 {
	if d < enums.SocketDataDirection(len(m.maxFrameSize)) && m.maxFrameSize[d] > 0 {
		return m.maxFrameSize[d]
	}
	return http2MaxSaneControlFrameLength
}

// isRequestHeaders decides whether a header block is a request (or request trailers) or a response
func (r *HTTP2Protocol) isRequestHeaders(m *HTTP2Metrics, d enums.SocketDataDirection, streamID uint32, headers *HTTP2Headers) bool {
	if headers.has(http2HeaderStatus) {
		if m.requestDirection == 0 {
			m.requestDirection = http2OppositeDirection(d)
		}
		return false
	}
	if headers.has(http2HeaderMethod) {
		if m.requestDirection == 0 {
			m.requestDirection = d
		}
		return true
	}
	if headers.has(http2HeaderPath) {
		if m.requestDirection == 0 {
			m.requestDirection = d
		}
		return true
	}
	// trailers: no pseudo headers, decide by the direction
	if m.requestDirection != 0 {
		return d == m.requestDirection
	}
	if streaming := m.Streams[streamID]; streaming != nil {
		return !streaming.IsInResponse
	}
	return true
}

func (r *HTTP2Protocol) isRequestDirection(m *HTTP2Metrics, d enums.SocketDataDirection, streaming *HTTP2Streaming) bool {
	if m.requestDirection != 0 {
		return d == m.requestDirection
	}
	return !streaming.IsInResponse
}

func (r *HTTP2Protocol) finishStream(connection *PartitionConnection, m *HTTP2Metrics, streamID uint32, streaming *HTTP2Streaming) {
	m.deleteStream(streamID)
	// a block of the other direction still waiting for its CONTINUATION frames is still decoded (table sync)
	m.decodeOnlyPending(streamID)
	if streaming.ReqHeader.Empty() {
		// the request was never seen (e.g. the connection was captured after the request), nothing to report
		http2Log.Debugf("drop HTTP/2 stream without request headers, connection ID: %d, stream ID: %d", m.ConnectionID, streamID)
		m.DroppedStreams++
		return
	}
	r.reportStream(connection, m, streamID, streaming)
}

// dropIdleStreams drops the streams, and the header blocks waiting for CONTINUATION frames, that were
// created more than maxHTTP2StreamIdleTime ago. The age lists are in creation order, so only their
// expired heads are looked at: amortized O(1) per analysis, whatever the number of open streams.
func (r *HTTP2Protocol) dropIdleStreams(m *HTTP2Metrics) {
	now := time.Now()
	for a := m.streamAges.head; a != nil && now.Sub(a.created) > maxHTTP2StreamIdleTime; a = m.streamAges.head {
		id := a.id
		if http2Log.Enable(logrus.DebugLevel) {
			http2Log.Debugf("drop idle HTTP/2 stream, connection ID: %d, stream ID: %d", m.ConnectionID, id)
		}
		m.deleteStream(id)
		m.deletePendingOfStream(id)
		if a.linked {
			// never left linked behind (deleteStream unlinks the stream the map holds)
			m.streamAges.remove(a)
		}
	}
	// a HEADERS frame whose CONTINUATION never arrives leaves an entry that no stream references, so
	// it is never reached by the loop above
	for a := m.pendingAges.head; a != nil && now.Sub(a.created) > maxHTTP2StreamIdleTime; a = m.pendingAges.head {
		id := a.id
		if http2Log.Enable(logrus.DebugLevel) {
			http2Log.Debugf("drop idle HTTP/2 header block, connection ID: %d, stream ID: %d", m.ConnectionID, id)
		}
		m.deletePending(id)
		if a.linked {
			m.pendingAges.remove(a)
		}
	}
}

// PendingDataLength implements PendingDataMetrics: the data events the parser moved out of the
// connection buffer into the per direction views and has not consumed yet
func (m *HTTP2Metrics) PendingDataLength() int {
	// the summaries and the streams waiting for theirs keep the connection as well
	result := m.pendingSummaries()
	for _, db := range m.dirBuffers {
		result += db.DataLength()
	}
	return result
}

// ReleasePendingData implements PendingDataMetrics
func (m *HTTP2Metrics) ReleasePendingData() {
	m.releaseSummaries()
	for _, db := range m.dirBuffers {
		db.ReleaseAll()
	}
	m.links.release()
}

func (r *HTTP2Protocol) ForProtocol() enums.ConnectionProtocol {
	return enums.ConnectionProtocolHTTP2
}

func (r *HTTP2Protocol) validateIsStreamOpenTooLong(connection *PartitionConnection,
	metrics *HTTP2Metrics, id uint32, streaming *HTTP2Streaming) {
	// if in the response mode or the request body is not nil, then skip
	if streaming.IsInResponse || streaming.ReqBodyBuffer == nil {
		return
	}

	// is the body sending too long, then split the stream
	socketBuffer := streaming.ReqBodyBuffer.FirstSocketBuffer()
	if socketBuffer == nil {
		return
	}
	if time.Since(host.Time(socketBuffer.StartTime())) > maxHTTP2StreamingTime {
		http2Log.Debugf("detect the HTTP/2 stream is too long, split the stream, connection ID: %d, stream ID: %d, headers: %v",
			metrics.ConnectionID, id, &streaming.ReqHeader)

		_ = r.analyzer.HandleWholeStream(connection, streaming)

		// forget the sent body: it is a slice of the direction buffer, which owns its events and releases
		// them. Cleaning the slice released them a second time (the in-flight accounting drifted negative)
		// and gave back the pooled buffer of the event still at the head of the direction buffer.
		streaming.ReqBodyBuffer = nil
	}
}

// http2DecodeHeaderBlock is hpack.Decoder.DecodeFull without collecting the fields (they go to the
// emit function): the same Write then Close, so the decoder state ends up the same.
func http2DecodeHeaderBlock(decoder *hpack.Decoder, block []byte) error {
	// several dynamic table size updates at the start of the block (RFC 7541 4.2), see http2_headers.go
	block = http2ApplyLeadingSizeUpdates(decoder, block)
	if _, err := decoder.Write(block); err != nil {
		return err
	}
	return decoder.Close()
}

// http2AppendHeaderSlice adds the events of a header block to the header buffer of a stream side. The
// slice of the first block is owned by nobody else, so it is kept as it is instead of being copied by
// CombineSlices (same events, size and details); later blocks are combined into a new buffer.
func http2AppendHeaderSlice(connBuf, exist, slice *buffer.Buffer) *buffer.Buffer {
	if exist == nil && slice != nil {
		return slice
	}
	return buffer.CombineSlices(true, connBuf, exist, slice)
}

// http2AppendBodySlice is http2AppendHeaderSlice for the DATA frames of a stream side: the first slice
// is kept as it is, later ones go through AppendSlices.
func http2AppendBodySlice(connBuf, exist, slice *buffer.Buffer) *buffer.Buffer {
	if exist == nil && slice != nil {
		return slice
	}
	return buffer.AppendSlices(true, connBuf, exist, slice)
}

// http2AppendBody appends the DATA frame payload between start and end of the direction buffer (with the virtual
// bytes the kernel transferred but BPF did not upload) to the body of a stream side: what http2AppendBodySlice
// does with the slice of the frame, without making the slice when the body is one AppendSlices appends onto
// (buffer.AppendSliceOf)
func http2AppendBody(connBuf, body, db *buffer.Buffer, start, end *buffer.Position, virtual int64) *buffer.Buffer {
	if buffer.AppendSliceOf(true, body, db, start, end, virtual) {
		return body
	}
	if combined := buffer.CombineSliceOf(true, connBuf, body, db, start, end, virtual); combined != nil {
		return combined
	}
	slice := db.Slice(true, start, end)
	if slice != nil && virtual > 0 {
		// the bytes the kernel transferred but BPF did not upload still count towards the body size
		slice.AddVirtualBytes(virtual)
	}
	return http2AppendBodySlice(connBuf, body, slice)
}

// http2DropScan is where the frame walk of a dropped socket event ended: in the call of the data id, the chunk
// seq, which ends at the offset end of the call, and the last frame walked, which ends at frameEnd
type http2DropScan struct {
	valid         bool
	dataID        uint64
	seq           int
	end, frameEnd uint64
}

// droppedHeaderBytes tells whether a socket event of direction d the parser drops (late, or to resynchronize) may
// hold, from the offset `from` of its event on, bytes of a header block (HEADERS or CONTINUATION frames). A call
// BPF uploaded without its content lies inside a DATA payload and holds none. Otherwise its frames are walked
// from the offset, where the parser expects a frame, or, for the next chunk of a call whose previous chunk was
// dropped just before, from where the frames of that chunk left off: a header frame, bytes that are no frame
// header (the offset is not a frame boundary, or the end of the bytes cuts a frame header), or bytes of the call
// that were not uploaded behind its last frame (BPF truncated it) mean it may.
//
//nolint:gocyclo // ordered decision over the BPF frame cursor and the walk of the dropped call
func (m *HTTP2Metrics) droppedHeaderBytes(d enums.SocketDataDirection, event buffer.SocketDataBuffer, from int) bool {
	if int(d) >= len(m.dropScan) {
		return true
	}
	scan := &m.dropScan[d]
	if buffer.IsPayloadSkipped(event) || buffer.IsSummaryGap(event) {
		scan.valid = false
		return false
	}
	// what BPF knew of the frames of the call (h2c_frames), see http2CallFrames
	frames, _ := http2CallFramesOf(event)
	if frames.CursorKnown {
		if frames.NoHeaderBytes {
			scan.valid = false
			return false
		}
		if event.DataSequence() == 0 && (frames.FirstFrameOffset < 0 || from < frames.FirstFrameOffset) && frames.StartsInHeaderBlock {
			// the bytes in front of the first frame header, from on, are the rest of a header block frame
			scan.valid = false
			return true
		}
		if event.DataSequence() == 0 && frames.FirstFrameOffset < 0 {
			// no frame header in the call: all of it is the rest of a frame that is no header block
			scan.valid = false
			return false
		}
	}
	// where the event starts in its call, when it is known, and where the frames walked before end in it
	callStart, known, walked := uint64(0), event.DataSequence() == 0, uint64(0)
	if !known && from == 0 && scan.valid && scan.dataID == event.DataID() && scan.seq+1 == event.DataSequence() {
		callStart, known, walked = scan.end, true, scan.frameEnd
		if walked > callStart {
			from = int(min(walked-callStart, uint64(event.BufferLen())))
		}
	}
	var may bool
	var at int
	if frames.CursorKnown && known {
		// the frames are where BPF says: walked from the first one (or from where the walk of the chunk before
		// ended), a frame of any type and length is stepped over, only the header blocks from the offset count
		start := from
		if event.DataSequence() == 0 {
			start = frames.FirstFrameOffset
		}
		may, at = http2WalkKnownFrames(event, start, from)
	} else {
		may, at = http2WalkForHeaderBytes(event, from, m.maxFrameLength(d))
	}
	frameEnd := max(walked, callStart+uint64(at))
	*scan = http2DropScan{valid: known && !may, dataID: event.DataID(), seq: event.DataSequence(),
		end: callStart + uint64(event.BufferLen()), frameEnd: frameEnd}
	if may {
		return true
	}
	if !event.IsFinished() || !event.HaveReduceDataAfterChunk() {
		// the call ends with its bytes, or goes on in the next chunk event, which is looked at on its own
		return false
	}
	// BPF did not upload the end of the call, which ends at its total size: a frame that runs to its end or
	// beyond leaves nothing else in it. (BPF's own cut of a followed call is always inside a DATA payload that runs
	// to the end of the call, which this lets through; the upload limit can cut anywhere, which this catches.)
	return !known || frameEnd < event.TotalSize()
}

// http2WalkKnownFrames walks the frames of the event's bytes from start, a frame boundary BPF vouched for: may is
// whether a HEADERS, CONTINUATION or PUSH_PROMISE frame reaches past the offset from, or a frame header cut by the
// end of the bytes does not tell its type; frameEnd is where the last frame walked ends in the event (past the
// bytes when it runs on in the rest of the call)
func http2WalkKnownFrames(event buffer.SocketDataBuffer, start, from int) (may bool, frameEnd int) {
	data := event.BufferData()
	n := min(event.BufferLen(), len(data))
	if n == 0 && event.TotalSize() > 0 {
		// the bytes of the call were not delivered (shed under memory pressure)
		return true, 0
	}
	at := max(start, 0)
	for at < n {
		if n-at < 4 {
			// the type of the frame is not in the bytes
			return true, at
		}
		frameType := http2.FrameType(data[at+3])
		end := at + http2FrameHeaderLen + int(uint32(data[at])<<16|uint32(data[at+1])<<8|uint32(data[at+2]))
		if (frameType == http2.FrameHeaders || frameType == http2.FrameContinuation || frameType == http2.FramePushPromise) &&
			end > from {
			return true, at
		}
		at = end
	}
	return false, at
}

// http2WalkForHeaderBytes walks the frames of the event's bytes from the offset: may is whether it met a header
// frame or bytes that are no frame header, frameEnd the offset in the event where the last frame walked ends
// (past the bytes when it runs on in the rest of the call)
func http2WalkForHeaderBytes(event buffer.SocketDataBuffer, from int, maxFrame uint32) (may bool, frameEnd int) {
	data := event.BufferData()
	n := min(event.BufferLen(), len(data))
	if n == 0 && event.TotalSize() > 0 {
		// the bytes of the call were not delivered (shed under memory pressure)
		return true, 0
	}
	at := max(from, 0)
	if at == 0 && event.DataSequence() == 0 && bytes.HasPrefix(data[:n], []byte(http2.ClientPreface)) {
		at = len(http2.ClientPreface)
	}
	for at < n {
		if n-at < http2FrameHeaderLen {
			return true, at
		}
		length := uint32(data[at])<<16 | uint32(data[at+1])<<8 | uint32(data[at+2])
		frameType := http2.FrameType(data[at+3])
		if (frameType > http2MaxFrameType && !http2IgnoredExtensionFrame(&http2.FrameHeader{Type: frameType, Length: length})) ||
			length > maxFrame {
			return true, at
		}
		if frameType == http2.FrameHeaders || frameType == http2.FrameContinuation || frameType == http2.FramePushPromise {
			return true, at
		}
		at += http2FrameHeaderLen + int(length)
	}
	return false, at
}

// http2FrameHeaderLen is the fixed size of an HTTP/2 frame header (RFC 7540 4.1)
const http2FrameHeaderLen = 9

// http2ReadPayload reads a complete frame payload
func http2ReadPayload(db *buffer.Buffer, length uint32) ([]byte, http2FrameResult) {
	payload := make([]byte, length)
	if err := db.ReadUntilBufferFull(payload); err != nil {
		return nil, http2ErrorResult(db, err)
	}
	return payload, http2FrameConsumed
}

// http2DiscardBytes consumes n bytes of a frame payload without reading them, see buffer.DiscardBytes:
// the bytes BPF never uploaded, the socket calls it uploaded without content because they lie inside a
// DATA payload (skip_h2c_data_payload) and the end of a truncated call the payload runs past, count
// towards the size of a body as virtual bytes
func http2DiscardBytes(db *buffer.Buffer, n int) (buffer.DiscardResult, error) {
	return db.DiscardBytes(n)
}

// http2ErrorResult maps a buffer read error to a frame result: EOF means the rest of the frame has
// not been received yet, a not-complete buffer means the next chunk of the current socket call, or a call
// uploaded before the next one, is still on its way (events of different CPUs are delivered out of order)
// and is waited for until the gap timeout, and everything else means the data is not contiguous anymore.
func http2ErrorResult(db *buffer.Buffer, err error) http2FrameResult {
	if errors.Is(err, io.EOF) {
		return http2FrameWait
	}
	if errors.Is(err, buffer.ErrNotComplete) {
		if pos := db.Position(); pos.HasElement() && time.Since(host.Time(pos.StartTime())) < http2GapWaitDuration {
			return http2FrameWait
		}
		if db.IncompleteInDelivery() {
			// the rest of the call may be among the events the reader has read and the analysis not taken yet
			// (a backlog of the partitions): that is not a loss
			return http2FrameWait
		}
		// the next socket call waits for an earlier upload: as long as the parser waits at its head when the
		// agent runs behind the kernel (waitForMissingEvent)
		if refused, waited := db.SequenceRefusedWait(); refused && waited < http2ArrivalWait() {
			return http2FrameWait
		}
	}
	// buffer.ErrTruncated: BPF did not upload the rest of this socket call, the frame can never be
	// completed - resynchronize at the next socket call instead of reading its bytes as this frame.
	// buffer.ErrPayloadSkipped: a frame would start, or end, inside a socket call BPF skipped as a part of
	// a DATA payload, so the parser is not where the frames are - resynchronize as well
	return http2FrameSkipElement
}

// http2StripPadding removes the pad length prefix and the trailing padding of a PADDED frame payload
func http2StripPadding(payload []byte, padded bool) ([]byte, bool) {
	if !padded {
		return payload, true
	}
	if len(payload) < 1 {
		return nil, false
	}
	padLen := int(payload[0])
	payload = payload[1:]
	if padLen > len(payload) {
		return nil, false
	}
	return payload[:len(payload)-padLen], true
}

// http2ValidPseudoHeaders checks the pseudo headers of a decoded block for plausibility: a path starts
// with "/" (or is "*" for OPTIONS), a method is a token (http2ValidMethod) and a status is numeric
func http2ValidPseudoHeaders(headers *HTTP2Headers) bool {
	if headers.has(http2HeaderPath) {
		path := headers.values[http2HeaderPath]
		if path == "" || (path[0] != '/' && path != "*") {
			return false
		}
	}
	if headers.has(http2HeaderMethod) && !http2ValidMethod(headers.values[http2HeaderMethod]) {
		return false
	}
	if headers.has(http2HeaderStatus) {
		status := headers.values[http2HeaderStatus]
		if len(status) != 3 {
			return false
		}
		for i := 0; i < len(status); i++ {
			if status[i] < '0' || status[i] > '9' {
				return false
			}
		}
	}
	return true
}

func http2OppositeDirection(d enums.SocketDataDirection) enums.SocketDataDirection {
	if d == enums.SocketDataDirectionIngress {
		return enums.SocketDataDirectionEgress
	}
	return enums.SocketDataDirectionIngress
}
