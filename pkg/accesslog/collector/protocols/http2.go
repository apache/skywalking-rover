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
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// maxHTTP2StreamingTime is the max time of an HTTP/2 streaming, if the streaming is too long, then this streaming will split
var maxHTTP2StreamingTime = time.Minute * 3

// maxHTTP2StreamIdleTime is the max time a stream may stay open without completing, after that it is dropped
var maxHTTP2StreamIdleTime = time.Minute * 5

// http2GapWaitDuration is how long the parser waits for a socket event that is missing from the sequence
// (events of different CPUs can be delivered out of order) before it gives up and continues with a gap,
// which most likely desynchronizes the HPACK dynamic table of that direction
var http2GapWaitDuration = 3 * time.Second

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

func NewHTTP2Analyzer(ctx *common.AccessLogContext, analyzer HTTP2StreamAnalyzer) *HTTP2Protocol {
	protocol := &HTTP2Protocol{ctx: ctx}
	if analyzer == nil {
		protocol.analyzer = protocol
	} else {
		protocol.analyzer = analyzer
	}
	return protocol
}

// HTTP2Metrics keeps the per connection HTTP/2 parsing state.
//
// HTTP/2 has one independent HPACK compression context per direction (RFC 7540 4.3), and a frame
// never spans two socket calls of different directions, so the data events of the connection are
// re-partitioned per direction and each direction keeps its own HPACK decoder and read position.
type HTTP2Metrics struct {
	ConnectionID uint64
	RandomID     uint64
	Streams      map[uint32]*HTTP2Streaming

	// decoders / dirBuffers / lastConsumed are indexed by enums.SocketDataDirection (1: ingress, 2: egress)
	decoders     [3]*hpack.Decoder
	dirBuffers   [3]*buffer.Buffer
	lastConsumed [3]*http2ConsumedPosition
	// pendingHeaders holds the header block fragments of a HEADERS frame waiting for CONTINUATION frames
	pendingHeaders map[uint32]*http2PendingHeaders
	// maxFrameSize is the SETTINGS_MAX_FRAME_SIZE the peer announced for the frames of a direction
	// (0 when it has not been observed), a frame bigger than that means the framing is out of sync
	maxFrameSize [3]uint32
	// requestDirection is the direction the requests flow in, learned from the client preface or
	// the first request / response header block, 0 when still unknown
	requestDirection enums.SocketDataDirection

	// lastDataID is the data id of the last socket event that was (at least partially) parsed, in any
	// direction; every uploaded event carries the data id of the previous uploaded event of the connection,
	// so the parser can detect a missing (late) event and wait for it
	lastDataID uint64

	// counters for debugging
	DecodeErrors, FramingErrors, LateSkips, DroppedStreams, Gaps uint64
}

type HTTP2Streaming struct {
	ReqHeader        map[string]string
	RespHeader       map[string]string
	ReqHeaderBuffer  *buffer.Buffer
	ReqBodyBuffer    *buffer.Buffer
	IsInResponse     bool
	Status           int
	RespHeaderBuffer *buffer.Buffer
	RespBodyBuffer   *buffer.Buffer
	Connection       *PartitionConnection

	created time.Time
}

// http2ConsumedPosition records the last position that was consumed by the parser in a direction,
// so bytes are never parsed twice when the buffer position is reset (late or out of order events).
type http2ConsumedPosition struct {
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
	created   time.Time
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
	}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		m.decoders[d] = hpack.NewDecoder(http2DefaultHeaderTableSize, nil)
		// the encoder of the peer is trusted: accept any dynamic table size update it emits
		// (the real limit is negotiated through SETTINGS, which may be observed after the update)
		m.decoders[d].SetAllowedMaxDynamicTableSize(http2MaxAllowedHeaderTableSize)
	}
	return m
}

func (r *HTTP2Protocol) Analyze(connection *PartitionConnection, _ *AnalyzeHelper) error {
	m := connection.Metrics(enums.ConnectionProtocolHTTP2).(*HTTP2Metrics)
	connBuf := connection.Buffer(enums.ConnectionProtocolHTTP2)
	http2Log.Debugf("ready to analyze HTTP/2 protocol data, connection ID: %d, random ID: %d, data len: %d",
		m.ConnectionID, m.RandomID, connBuf.DataLength())

	// re-partition the newly received data events per direction, the details stay in the connection buffer
	for _, event := range connBuf.TakeDataEvents() {
		d := event.Direction()
		if d != enums.SocketDataDirectionIngress && d != enums.SocketDataDirectionEgress {
			continue
		}
		if m.dirBuffers[d] == nil {
			m.dirBuffers[d] = buffer.NewViewBuffer(connBuf)
		}
		m.dirBuffers[d].AppendDataEvent(event)
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
			pos := db.Position()
			has[d], headID[d], headTime[d] = true, pos.DataID(), pos.StartTime()
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
			case time.Since(host.Time(headTime[other])) >= http2GapWaitDuration:
				// the blocked direction is stale: a lost chunk must not stall the peer direction forever
				otherID = uint64(math.MaxUint64)
			default:
				// everything of this connection that comes next belongs to the blocked direction: wait
				// for its missing data instead of reporting later frames first
				break analyze
			}
		}
		// the next event must follow the last parsed one; otherwise an event is still missing: wait for it
		if r.waitForMissingEvent(m, m.dirBuffers[best].Position()) {
			break
		}
		if r.analyzeDirection(connection, connBuf, m, best, m.dirBuffers[best], otherID) {
			// data was parsed, so a direction that was blocked on it may be able to continue now
			blocked = [3]bool{}
		} else {
			blocked[best] = true
		}
	}
	r.dropIdleStreams(m)
	return nil
}

// waitForMissingEvent reports whether the event at the position does not follow the last parsed event
// (an event in between has not been delivered yet) and the parser should wait for it. After
// http2GapWaitDuration the missing event is given up and parsing continues with a gap.
func (r *HTTP2Protocol) waitForMissingEvent(m *HTTP2Metrics, pos *buffer.Position) bool {
	// an event is missing only when the previous event of this one has a higher id than the last
	// parsed one: a frame that spans two socket calls of one direction already moved lastDataID past
	// the events of the other direction in between, those are not missing
	if m.lastDataID == 0 || pos.PrevDataID() <= m.lastDataID {
		return false
	}
	if time.Since(host.Time(pos.StartTime())) < http2GapWaitDuration {
		return true
	}
	http2Log.Debugf("give up waiting for the missing HTTP/2 socket event, connection ID: %d, last data id: %d, next data id: %d (prev: %d)",
		m.ConnectionID, m.lastDataID, pos.DataID(), pos.PrevDataID())
	m.Gaps++
	m.markParsed(pos.PrevDataID())
	return false
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
	if event := db.HeadDataEvent(); event != nil {
		listener.OnDropEvent(connection, event)
	}
}

// analyzeDirection parses the frames of one direction up to the socket call with data id `limit`
// (inclusive). It returns false when nothing could be consumed because the data is incomplete.
func (r *HTTP2Protocol) analyzeDirection(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, limit uint64) (progress bool) {
	for {
		if !db.PrepareForReading() {
			return progress
		}
		pos := db.Position()
		if pos.DataID() > limit {
			// the other direction has earlier data, let it catch up first
			return progress
		}
		if r.waitForMissingEvent(m, pos) {
			return progress
		}
		if last := m.lastConsumed[d]; last != nil {
			if pos.DataID() < last.dataID || (pos.DataID() == last.dataID && pos.Seq() < last.seq) {
				// data older than what is already parsed arrived late: it cannot be parsed in order anymore
				http2Log.Debugf("skip late HTTP/2 data, connection ID: %d, data id: %d, seq: %d", m.ConnectionID, pos.DataID(), pos.Seq())
				m.LateSkips++
				progress = true
				r.notifyDropEvent(connection, db)
				if db.RemoveCurrentElement() {
					return progress
				}
				continue
			}
			if pos.DataID() == last.dataID && pos.Seq() == last.seq && pos.StartTime() == last.startTime && pos.Offset() < last.offset {
				// the position was reset to the beginning of an element that is partially consumed, skip the consumed part
				if err := http2DiscardBytes(db, last.offset-pos.Offset()); err != nil {
					if errors.Is(err, io.EOF) {
						return progress
					}
					progress = true
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
		db.SetSequenceBarrier(m.lastDataID)
		result := r.parseFrame(connection, connBuf, m, d, db, pos)
		switch result {
		case http2FrameConsumed:
			progress = true
			cur := db.Position()
			m.lastConsumed[d] = &http2ConsumedPosition{dataID: cur.DataID(), seq: cur.Seq(), startTime: cur.StartTime(), offset: cur.Offset()}
			m.markParsed(cur.DataID())
			if db.RemoveReadElements(false) {
				return progress
			}
		case http2FrameSkipElement:
			m.FramingErrors++
			progress = true
			m.markParsed(pos.DataID()) // the skipped event still counts as parsed for the sequence
			r.notifyDropEvent(connection, db)
			if db.RemoveCurrentElement() {
				return progress
			}
		case http2FrameWait:
			return progress
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

// parseFrame reads one frame (or the client connection preface) from the current position
func (r *HTTP2Protocol) parseFrame(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, startPos *buffer.Position) http2FrameResult {
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
	if m.lastConsumed[d] == nil && bytes.HasPrefix([]byte(http2.ClientPreface), head[:]) {
		return r.parsePreface(m, d, db)
	}

	header, err := http2.ReadFrameHeader(db)
	if err != nil {
		http2Log.Debugf("failed to read HTTP/2 frame header, connection ID: %d, error: %v", m.ConnectionID, err)
		return http2ErrorResult(db, err)
	}
	if header.Type > http2MaxFrameType || header.Length > m.maxFrameLength(d) {
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
			return result
		}
		return r.handleHeaders(connection, connBuf, m, d, db, &header, startPos, payload)
	case http2.FrameContinuation:
		payload, result := http2ReadPayload(db, header.Length)
		if result != http2FrameConsumed {
			return result
		}
		return r.handleContinuation(connection, connBuf, m, d, db, &header, startPos, payload)
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
		if err := http2DiscardBytes(db, int(header.Length)); err != nil {
			return http2ErrorResult(db, err)
		}
		delete(m.Streams, header.StreamID)
		delete(m.pendingHeaders, header.StreamID)
		return http2FrameConsumed
	default:
		// PRIORITY, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE: nothing to analyze
		if err := http2DiscardBytes(db, int(header.Length)); err != nil {
			return http2ErrorResult(db, err)
		}
		return http2FrameConsumed
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
		m.pendingHeaders[header.StreamID] = &http2PendingHeaders{
			direction: d, slice: db.Slice(true, startPos, db.Position()), endStream: endStream,
			fragment: append([]byte(nil), fragment...), created: time.Now(),
		}
		return http2FrameConsumed
	}
	return r.handleHeaderBlock(connection, connBuf, m, d, db.Slice(true, startPos, db.Position()),
		header.StreamID, endStream, fragment)
}

func (r *HTTP2Protocol) handleContinuation(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader, startPos *buffer.Position,
	payload []byte) http2FrameResult {
	pending := m.pendingHeaders[header.StreamID]
	if pending == nil || pending.direction != d {
		return http2FrameConsumed
	}
	if len(pending.fragment)+len(payload) > http2MaxSaneControlFrameLength {
		// a peer that never ends the header block would grow this fragment without bound
		http2Log.Debugf("the HTTP/2 header block is too big, drop it, connection ID: %d, stream ID: %d",
			m.ConnectionID, header.StreamID)
		delete(m.pendingHeaders, header.StreamID)
		m.FramingErrors++
		return http2FrameConsumed
	}
	pending.fragment = append(pending.fragment, payload...)
	pending.slice = buffer.CombineSlices(true, connBuf, pending.slice, db.Slice(true, startPos, db.Position()))
	if !header.Flags.Has(http2.FlagContinuationEndHeaders) {
		return http2FrameConsumed
	}
	delete(m.pendingHeaders, header.StreamID)
	return r.handleHeaderBlock(connection, connBuf, m, d, pending.slice, header.StreamID, pending.endStream, pending.fragment)
}

// handleHeaderBlock decodes a complete header block and attaches it to the stream. `headerSlice` are
// the events the whole block was read from (HEADERS plus its CONTINUATION frames).
func (r *HTTP2Protocol) handleHeaderBlock(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, headerSlice *buffer.Buffer, streamID uint32, endStream bool, block []byte) http2FrameResult {
	fields, err := m.decoders[d].DecodeFull(block)
	if err != nil {
		// the HPACK dynamic table of this direction is out of sync, most likely the connection was not
		// captured from its beginning. Only this stream is lost, the connection keeps being analyzed.
		http2Log.Debugf("failed to decode HTTP/2 header block, connection ID: %d, stream ID: %d, error: %v",
			m.ConnectionID, streamID, err)
		m.DecodeErrors++
		delete(m.Streams, streamID)
		return http2FrameConsumed
	}
	headers := r.parseHeaders(fields)
	if !http2ValidPseudoHeaders(headers) {
		// the block decoded, but against a dynamic table that is out of sync (e.g. after lost socket
		// events): the values are mixed up, reporting them would create garbage endpoints
		http2Log.Debugf("HTTP/2 header block with invalid pseudo headers, connection ID: %d, stream ID: %d, headers: %v",
			m.ConnectionID, streamID, headers)
		m.DecodeErrors++
		delete(m.Streams, streamID)
		return http2FrameConsumed
	}
	isRequest := r.isRequestHeaders(m, d, streamID, headers)
	if path, ok := headers[":path"]; ok && isRequest {
		// report the path without the query string, like the HTTP/1 analyzer does (URL.Path)
		if i := strings.IndexByte(path, '?'); i >= 0 {
			headers[":path"] = path[:i]
		}
	}

	streaming := m.Streams[streamID]
	if streaming == nil {
		streaming = &HTTP2Streaming{
			ReqHeader:  make(map[string]string),
			RespHeader: make(map[string]string),
			Connection: connection,
			created:    time.Now(),
		}
		m.Streams[streamID] = streaming
	}
	if isRequest {
		r.AppendHeaders(streaming.ReqHeader, headers)
		streaming.ReqHeaderBuffer = buffer.CombineSlices(true, connBuf, streaming.ReqHeaderBuffer, headerSlice)
		return http2FrameConsumed
	}

	if status, contains := headers[":status"]; contains {
		code, err := strconv.ParseInt(status, 10, 64)
		if err != nil {
			log.Warnf("cannot parse status code: %s", status)
			code = 200
		}
		streaming.Status = int(code)
	}
	streaming.IsInResponse = true
	r.AppendHeaders(streaming.RespHeader, headers)
	streaming.RespHeaderBuffer = buffer.CombineSlices(true, connBuf, streaming.RespHeaderBuffer, headerSlice)
	if endStream {
		r.finishStream(connection, m, streamID, streaming)
	}
	return http2FrameConsumed
}

func (r *HTTP2Protocol) handleData(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader) http2FrameResult {
	streaming := m.Streams[header.StreamID]
	bodyStart := db.Position()
	if streaming == nil {
		// unknown stream (reset, or not captured from the beginning), the data is not interesting
		if err := http2DiscardBytes(db, int(header.Length)); err != nil {
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
		bodyStart = db.Position()
		if err := http2DiscardBytes(db, int(header.Length)-1-int(padLen[0])); err != nil {
			return http2ErrorResult(db, err)
		}
		bodyEnd := db.Position()
		if err := http2DiscardBytes(db, int(padLen[0])); err != nil {
			return http2ErrorResult(db, err)
		}
		return r.appendData(connection, connBuf, m, d, db, header, streaming, bodyStart, bodyEnd)
	}
	if err := http2DiscardBytes(db, int(header.Length)); err != nil {
		return http2ErrorResult(db, err)
	}
	return r.appendData(connection, connBuf, m, d, db, header, streaming, bodyStart, db.Position())
}

func (r *HTTP2Protocol) appendData(connection *PartitionConnection, connBuf *buffer.Buffer, m *HTTP2Metrics,
	d enums.SocketDataDirection, db *buffer.Buffer, header *http2.FrameHeader, streaming *HTTP2Streaming, bodyStart, bodyEnd *buffer.Position) http2FrameResult {
	slice := db.Slice(true, bodyStart, bodyEnd)
	endStream := header.Flags.Has(http2.FlagDataEndStream)
	if r.isRequestDirection(m, d, streaming) {
		streaming.ReqBodyBuffer = buffer.CombineSlices(true, connBuf, streaming.ReqBodyBuffer, slice)
		r.validateIsStreamOpenTooLong(connection, m, header.StreamID, streaming)
		return http2FrameConsumed
	}
	streaming.IsInResponse = true
	streaming.RespBodyBuffer = buffer.CombineSlices(true, connBuf, streaming.RespBodyBuffer, slice)
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
func (r *HTTP2Protocol) isRequestHeaders(m *HTTP2Metrics, d enums.SocketDataDirection, streamID uint32, headers map[string]string) bool {
	if _, ok := headers[":status"]; ok {
		if m.requestDirection == 0 {
			m.requestDirection = http2OppositeDirection(d)
		}
		return false
	}
	if _, ok := headers[":method"]; ok {
		if m.requestDirection == 0 {
			m.requestDirection = d
		}
		return true
	}
	if _, ok := headers[":path"]; ok {
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
	delete(m.Streams, streamID)
	delete(m.pendingHeaders, streamID)
	if len(streaming.ReqHeader) == 0 {
		// the request was never seen (e.g. the connection was captured after the request), nothing to report
		http2Log.Debugf("drop HTTP/2 stream without request headers, connection ID: %d, stream ID: %d", m.ConnectionID, streamID)
		m.DroppedStreams++
		return
	}
	if err := r.analyzer.HandleWholeStream(connection, streaming); err != nil {
		http2Log.Debugf("failed to handle HTTP/2 stream, connection ID: %d, stream ID: %d, error: %v", m.ConnectionID, streamID, err)
	}
}

func (r *HTTP2Protocol) dropIdleStreams(m *HTTP2Metrics) {
	for id, streaming := range m.Streams {
		if !streaming.created.IsZero() && time.Since(streaming.created) > maxHTTP2StreamIdleTime {
			http2Log.Debugf("drop idle HTTP/2 stream, connection ID: %d, stream ID: %d", m.ConnectionID, id)
			delete(m.Streams, id)
			delete(m.pendingHeaders, id)
		}
	}
	// a HEADERS frame whose CONTINUATION never arrives leaves an entry that no stream references, so
	// it is never reached by the loop above
	for id, pending := range m.pendingHeaders {
		if !pending.created.IsZero() && time.Since(pending.created) > maxHTTP2StreamIdleTime {
			http2Log.Debugf("drop idle HTTP/2 header block, connection ID: %d, stream ID: %d", m.ConnectionID, id)
			delete(m.pendingHeaders, id)
		}
	}
}

// PendingDataLength implements PendingDataMetrics: the data events the parser moved out of the
// connection buffer into the per direction views and has not consumed yet
func (m *HTTP2Metrics) PendingDataLength() int {
	var result int
	for _, db := range m.dirBuffers {
		result += db.DataLength()
	}
	return result
}

// ReleasePendingData implements PendingDataMetrics
func (m *HTTP2Metrics) ReleasePendingData() {
	for _, db := range m.dirBuffers {
		db.ReleaseAll()
	}
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
			metrics.ConnectionID, id, streaming.ReqHeader)

		_ = r.analyzer.HandleWholeStream(connection, streaming)

		// clean sent buffers
		if streaming.ReqBodyBuffer != nil {
			streaming.ReqBodyBuffer.Clean()
		}
	}
}

func (r *HTTP2Protocol) HandleWholeStream(_ *PartitionConnection, stream *HTTP2Streaming) error {
	details := make([]events.SocketDetail, 0)
	allInclude := true
	var idRange *buffer.DataIDRange
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.ReqHeaderBuffer, idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.ReqBodyBuffer, idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.RespHeaderBuffer, idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.RespBodyBuffer, idRange, allInclude)

	// idRange is nil / details empty when no buffer contributed any event (e.g. all buffers absent);
	// guard it so the error path never dereferences a nil buffer as it used to (which panicked).
	if !allInclude || idRange == nil || len(details) == 0 {
		from, to := DataIDRangeBounds(idRange)
		return fmt.Errorf("cannot found full detail events for HTTP/2 protocol, data id: %d-%d, current details count: %d",
			from, to, len(details))
	}
	// the details are NOT deleted by the data id range here: with multiplexed streams the contiguous
	// range of a finished stream also covers the data ids of the frames of the other open streams, and
	// deleting those makes every one of them fail with "cannot found full detail events" when it
	// finishes. They are removed by the expiry instead (Buffer.DeleteExpireEvents).

	streamHost := stream.ReqHeader[":authority"]
	if streamHost == "" {
		streamHost = stream.ReqHeader[":host"]
	}
	forwarder.SendTransferProtocolEvent(r.ctx, common.NewProtocolLogEvent(details, &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: forwarder.BuildOffsetTimestamp(r.FirstDetail(stream.ReqBodyBuffer, details[0]).GetStartTime()),
				EndTime:   forwarder.BuildOffsetTimestamp(details[len(details)-1].GetEndTime()),
				Version:   v3.AccessLogHTTPProtocolVersion_HTTP2,
				Request: &v3.AccessLogHTTPProtocolRequest{
					Method:             r.ParseHTTPMethod(stream),
					Path:               stream.ReqHeader[":path"],
					SizeOfHeadersBytes: r.BufferSizeOfZero(stream.ReqHeaderBuffer),
					SizeOfBodyBytes:    r.BufferSizeOfZero(stream.ReqBodyBuffer),
					Host:               streamHost,
					Trace: AnalyzeTraceInfo(func(key string) string {
						return stream.ReqHeader[key]
					}, http2Log),
				},
				Response: &v3.AccessLogHTTPProtocolResponse{
					StatusCode:         int32(stream.Status),
					SizeOfHeadersBytes: r.BufferSizeOfZero(stream.RespHeaderBuffer),
					SizeOfBodyBytes:    r.BufferSizeOfZero(stream.RespBodyBuffer),
				},
			},
		},
	}))
	return nil
}

func (r *HTTP2Protocol) OnProtocolBreak(*PartitionConnection, *HTTP2Metrics) {
}

func (r *HTTP2Protocol) ParseHTTPMethod(streaming *HTTP2Streaming) v3.AccessLogHTTPProtocolRequestMethod {
	method := streaming.ReqHeader[":method"]
	if method == "" {
		return v3.AccessLogHTTPProtocolRequestMethod_Get
	}

	return TransformHTTPMethod(strings.ToUpper(method))
}

func (r *HTTP2Protocol) FirstDetail(buf *buffer.Buffer, def events.SocketDetail) events.SocketDetail {
	if buf == nil {
		return def
	}
	details := buf.BuildDetails()
	if details == nil || details.Len() == 0 {
		return def
	}
	return details.Front().Value.(events.SocketDetail)
}

func (r *HTTP2Protocol) BufferSizeOfZero(buf *buffer.Buffer) uint64 {
	if buf == nil {
		return 0
	}
	return uint64(buf.DataSize())
}

func (r *HTTP2Protocol) AppendHeaders(exist, needAppends map[string]string) {
	for k, v := range needAppends {
		exist[k] = v
	}
}

func (r *HTTP2Protocol) parseHeaders(headers []hpack.HeaderField) map[string]string {
	result := make(map[string]string)
	for _, header := range headers {
		result[header.Name] = header.Value
	}
	return result
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

// http2DiscardBytes moves the read position forward by n bytes without keeping the content. The
// scratch buffer is local: Analyze runs on every partition goroutine in parallel, a package level
// one would be written by all of them at the same time.
func http2DiscardBytes(db *buffer.Buffer, n int) error {
	var scratch [4096]byte
	for n > 0 {
		chunk := n
		if chunk > len(scratch) {
			chunk = len(scratch)
		}
		if err := db.ReadUntilBufferFull(scratch[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// http2ErrorResult maps a buffer read error to a frame result: EOF means the rest of the frame has
// not been received yet, a not-complete buffer means the next chunk of the current socket call is
// still on its way (events of different CPUs are delivered out of order) and is waited for until the
// gap timeout, and everything else means the data is not contiguous anymore.
func http2ErrorResult(db *buffer.Buffer, err error) http2FrameResult {
	if errors.Is(err, io.EOF) {
		return http2FrameWait
	}
	if errors.Is(err, buffer.ErrNotComplete) {
		if pos := db.Position(); pos.HasElement() && time.Since(host.Time(pos.StartTime())) < http2GapWaitDuration {
			return http2FrameWait
		}
	}
	// buffer.ErrTruncated: BPF did not upload the rest of this socket call, the frame can never be
	// completed - resynchronize at the next socket call instead of reading its bytes as this frame
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
// with "/" (or is "*" for OPTIONS), a method is a token of upper case letters and a status is numeric
func http2ValidPseudoHeaders(headers map[string]string) bool {
	if path, ok := headers[":path"]; ok {
		if path == "" || (path[0] != '/' && path != "*") {
			return false
		}
	}
	if method, ok := headers[":method"]; ok {
		if method == "" || len(method) > 16 {
			return false
		}
		for i := 0; i < len(method); i++ {
			if c := method[i]; (c < 'A' || c > 'Z') && c != '-' && c != '_' {
				return false
			}
		}
	}
	if status, ok := headers[":status"]; ok {
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
