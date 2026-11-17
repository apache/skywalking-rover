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
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// http2HeaderKey identifies a header field HTTP2Headers keeps, in the order of the names (String)
type http2HeaderKey uint8

const (
	http2HeaderAuthority http2HeaderKey = iota
	http2HeaderHost
	http2HeaderMethod
	http2HeaderPath
	http2HeaderStatus
	// the tracing context headers read by AnalyzeTraceInfo (tracing.AnalyzeTracingContext)
	http2HeaderB3
	http2HeaderSW8
	http2HeaderB3SpanID
	http2HeaderB3TraceID
	http2HeaderKeyCount
)

// the names of the header fields HTTP2Headers keeps (":host" is no pseudo header, see http2HeaderKeyOf)
const (
	http2FieldAuthority = ":authority"
	http2FieldHost      = ":host"
	http2FieldMethod    = ":method"
	http2FieldPath      = ":path"
	http2FieldStatus    = ":status"
)

var http2HeaderNames = [http2HeaderKeyCount]string{
	http2HeaderAuthority: http2FieldAuthority,
	http2HeaderHost:      http2FieldHost,
	http2HeaderMethod:    http2FieldMethod,
	http2HeaderPath:      http2FieldPath,
	http2HeaderStatus:    http2FieldStatus,
	http2HeaderB3:        tracing.HeaderB3,
	http2HeaderSW8:       tracing.HeaderSW8,
	http2HeaderB3SpanID:  tracing.HeaderB3SpanID,
	http2HeaderB3TraceID: tracing.HeaderB3TraceID,
}

// http2HeaderKeyOf maps a header name to the field HTTP2Headers keeps for it. Names are matched exactly,
// as the lookups in the map the headers used to be stored in did (HTTP/2 header names are lower case).
func http2HeaderKeyOf(name string) (http2HeaderKey, bool) {
	switch name {
	case http2FieldAuthority:
		return http2HeaderAuthority, true
	case http2FieldHost, "host":
		// ":host" is no pseudo header; the regular "host" field stands in for a missing ":authority"
		// (RFC 9113 8.3.1), it is what the analyzers fall back to
		return http2HeaderHost, true
	case http2FieldMethod:
		return http2HeaderMethod, true
	case http2FieldPath:
		return http2HeaderPath, true
	case http2FieldStatus:
		return http2HeaderStatus, true
	case tracing.HeaderB3:
		return http2HeaderB3, true
	case tracing.HeaderSW8:
		return http2HeaderSW8, true
	case tracing.HeaderB3SpanID:
		return http2HeaderB3SpanID, true
	case tracing.HeaderB3TraceID:
		return http2HeaderB3TraceID, true
	}
	return 0, false
}

// HTTP2Headers keeps the header fields of one side (request or response) of an HTTP/2 stream that the
// analyzers read: the pseudo headers and the tracing context headers. Every other field of a header
// block is still decoded by HPACK (the dynamic table must stay in sync) but not kept, which saves the
// maps the whole header blocks used to be copied into. Like those maps, a field of a later header block
// (trailers) replaces the value of an earlier one, and within a block the last occurrence wins.
type HTTP2Headers struct {
	values  [http2HeaderKeyCount]string
	present uint16
	// seen is set once any header field was added, like a map that is not empty
	seen bool
}

// Get returns the value of a kept header field, "" when it is absent or not kept
func (h *HTTP2Headers) Get(name string) string {
	if key, ok := http2HeaderKeyOf(name); ok {
		return h.values[key]
	}
	return ""
}

// Empty reports whether no header field was added at all
func (h *HTTP2Headers) Empty() bool {
	return !h.seen
}

func (h *HTTP2Headers) has(key http2HeaderKey) bool {
	return h.present&(1<<key) != 0
}

func (h *HTTP2Headers) set(key http2HeaderKey, value string) {
	h.values[key] = value
	h.present |= 1 << key
}

// emit is the hpack.Decoder emit function: it is called for every decoded field of a header block
func (h *HTTP2Headers) emit(f hpack.HeaderField) {
	h.seen = true
	if key, ok := http2HeaderKeyOf(f.Name); ok {
		h.set(key, f.Value)
	}
}

// reset prepares the headers to collect a new header block
func (h *HTTP2Headers) reset() {
	*h = HTTP2Headers{}
}

// merge adds the fields of a header block, replacing the values of the fields the block contains
func (h *HTTP2Headers) merge(block *HTTP2Headers) {
	h.seen = h.seen || block.seen
	for key := http2HeaderKey(0); key < http2HeaderKeyCount; key++ {
		if block.has(key) {
			h.set(key, block.values[key])
		}
	}
}

// String prints the kept fields like fmt prints a map, used by the debug logs
func (h *HTTP2Headers) String() string {
	var result strings.Builder
	result.WriteString("map[")
	for key := http2HeaderKey(0); key < http2HeaderKeyCount; key++ {
		if !h.has(key) {
			continue
		}
		if result.Len() > len("map[") {
			result.WriteByte(' ')
		}
		result.WriteString(http2HeaderNames[key])
		result.WriteByte(':')
		result.WriteString(h.values[key])
	}
	result.WriteByte(']')
	return result.String()
}

// handlePushPromise takes a PUSH_PROMISE frame (RFC 9113 6.6): the promised request is not reported, but its
// header block is encoded with the dynamic table of the pushing direction, so it is decoded (or kept until its
// CONTINUATION frames complete it) like any other block of the direction, or every later block would be decoded
// against a table that misses its entries
func (r *HTTP2Protocol) handlePushPromise(m *HTTP2Metrics, d enums.SocketDataDirection, header *http2.FrameHeader,
	payload []byte) http2FrameResult {
	fragment, ok := http2StripPadding(payload, header.Flags.Has(http2.FlagPushPromisePadded))
	if !ok || len(fragment) < 4 {
		return http2FrameSkipElement
	}
	// the promised stream id
	fragment = fragment[4:]
	if !header.Flags.Has(http2.FlagPushPromiseEndHeaders) {
		m.setPending(http2PendingKey(header.StreamID, d), &http2PendingHeaders{
			direction: d, decodeOnly: true,
			fragment: append([]byte(nil), fragment...), age: http2Aged{created: time.Now()},
		})
		return http2FrameConsumed
	}
	m.decodeOnlyHeaderBlock(d, fragment)
	return http2FrameConsumed
}

// decodeOnlyHeaderBlock feeds a complete header block to the decoder of the direction without attaching it to a
// stream: only its effect on the dynamic table counts
func (m *HTTP2Metrics) decodeOnlyHeaderBlock(d enums.SocketDataDirection, block []byte) {
	if int(d) >= len(m.headerDesync) || m.headerDesync[d] {
		return
	}
	headers := &m.headerBlocks[d]
	headers.reset()
	if err := http2DecodeHeaderBlock(m.decoders[d], block); err != nil {
		m.DecodeErrors++
		m.markHeaderDesync(d)
	}
	headers.reset()
}

// decodeOnlyPending keeps the header block of the stream that waits for its CONTINUATION frames, if there is one,
// but only to be decoded once it completes: the stream is gone (reset, or finished by the other direction), yet
// the block went through the encoder of its direction, so its decoder must see it as well
func (m *HTTP2Metrics) decodeOnlyPending(id uint32) {
	for _, key := range [...]uint32{http2PendingKey(id, enums.SocketDataDirectionIngress), http2PendingKey(id, enums.SocketDataDirectionEgress)} {
		if pending := m.pendingHeaders[key]; pending != nil {
			pending.decodeOnly = true
			pending.slice = nil
		}
	}
}

// http2PendingKey is the key of a header block waiting for its CONTINUATION frames: the stream id (31 bits) and the
// direction in the top bit. Both peers may be in the middle of a header block of the same stream at once (request
// trailers and response headers), and each block must complete on its own.
func http2PendingKey(id uint32, d enums.SocketDataDirection) uint32 {
	if d == enums.SocketDataDirectionEgress {
		return id | 1<<31
	}
	return id &^ (1 << 31)
}

// deletePendingOfStream forgets the pending header blocks of the stream, of both directions
func (m *HTTP2Metrics) deletePendingOfStream(id uint32) {
	m.deletePending(http2PendingKey(id, enums.SocketDataDirectionIngress))
	m.deletePending(http2PendingKey(id, enums.SocketDataDirectionEgress))
}

// HTTP2CallFrames is what BPF can report about the frames of one socket call when it followed them
// (h2c_frames / first_frame_off of the event)
type HTTP2CallFrames struct {
	// CursorKnown: BPF knew where the frames of the direction were at the start of the call (h2c_frames bit 0)
	CursorKnown bool
	// NoHeaderBytes: the call holds no byte of a HEADERS, CONTINUATION or PUSH_PROMISE frame (h2c_frames bit 1)
	NoHeaderBytes bool
	// StartsInHeaderBlock: the bytes in front of the first frame header (all of them when there is none) are the
	// rest of a HEADERS, CONTINUATION or PUSH_PROMISE frame of the call before (h2c_frames bit 2)
	StartsInHeaderBlock bool
	// FirstFrameOffset: where the first frame header starts in the call, with CursorKnown; -1 when none does
	FirstFrameOffset int
}

// http2CallFramesSource reads HTTP2CallFrames from an event of a build whose events carry them (nil: none do)
var http2CallFramesSource func(event buffer.SocketDataBuffer) (HTTP2CallFrames, bool)

// SetHTTP2CallFramesSource installs the reader of the frame flags BPF attaches to the socket calls
func SetHTTP2CallFramesSource(source func(event buffer.SocketDataBuffer) (HTTP2CallFrames, bool)) {
	http2CallFramesSource = source
}

func http2CallFramesOf(event buffer.SocketDataBuffer) (HTTP2CallFrames, bool) {
	if http2CallFramesSource == nil || event == nil {
		return HTTP2CallFrames{}, false
	}
	return http2CallFramesSource(event)
}

// frameBoundaryProven tells whether the frame header at the position certainly starts a frame: the previous frame
// of the direction ended exactly there, inside the same socket event, or BPF knew the frames of the call and its
// first frame starts there. Only then is a frame of an unknown type stepped over (RFC 9113 5.5); elsewhere the type
// stays the signal that the parser is not on a frame boundary.
func (m *HTTP2Metrics) frameBoundaryProven(d enums.SocketDataDirection, db *buffer.Buffer, pos *buffer.Position) bool {
	if int(d) >= len(m.lastConsumed) {
		return false
	}
	if last := &m.lastConsumed[d]; last.valid && pos.Offset() > 0 && last.dataID == pos.DataID() && last.seq == pos.Seq() &&
		last.startTime == pos.StartTime() && last.offset == pos.Offset() {
		return true
	}
	if pos.Seq() != 0 {
		return false
	}
	event := db.HeadDataEvent()
	if event == nil || event.DataID() != pos.DataID() || event.DataSequence() != 0 {
		return false
	}
	f, ok := http2CallFramesOf(event)
	return ok && f.CursorKnown && f.FirstFrameOffset == pos.Offset()
}

// http2MaxMethodLength bounds a request method: RFC 9110 allows any token, but a long one is a value of a block
// decoded against a dynamic table that is out of sync rather than a method
const http2MaxMethodLength = 24

// http2ValidMethod tells whether a :method value is a plausible method: an RFC 9110 token (tchar) of at most
// http2MaxMethodLength bytes with at least one letter (a number is a mixed up :status or content-length)
func http2ValidMethod(method string) bool {
	if method == "" || len(method) > http2MaxMethodLength {
		return false
	}
	letter := false
	for i := 0; i < len(method); i++ {
		switch c := method[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
			letter = true
		case c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return letter
}

// http2MaxExtensionFrameLength bounds the frames of an extension type the parser steps over: they are small
// control frames, and a bound keeps a misframed header from being taken for one of them with a long payload
const http2MaxExtensionFrameLength = http2MinMaxFrameSize

// http2IgnoredExtensionFrame tells whether a frame of a type above CONTINUATION is one of the extension frames
// real peers send, which a receiver must ignore (RFC 9113 4.1, 5.5): ALTSVC (RFC 7838), ORIGIN (RFC 8336),
// PRIORITY_UPDATE (RFC 9218) and the reserved "GREASE" types 0x0b + 0x1f * N that clients send to keep peers
// tolerant of unknown types. Any other type above CONTINUATION is still taken as lost framing.
func http2IgnoredExtensionFrame(header *http2.FrameHeader) bool {
	if header.Length > http2MaxExtensionFrameLength {
		return false
	}
	switch t := uint8(header.Type); {
	case t == 0x0a, t == 0x0c, t == 0x10:
		return true
	case t >= 0x0b && (t-0x0b)%0x1f == 0:
		return true
	}
	return false
}

// http2ApplyLeadingSizeUpdates applies all but the last of several dynamic table size updates that start a header
// block and returns the block from the last one on. RFC 7541 4.2 lets an encoder signal the smallest size the table
// went through, then the final one (nghttp2 does), but hpack.Decoder refuses a second update while the table still
// holds entries. Applying the first ones directly (evicting as the decoder would) leaves it one update to decode.
// A block with at most one leading update is returned as it is.
func http2ApplyLeadingSizeUpdates(decoder *hpack.Decoder, block []byte) []byte {
	if len(block) == 0 || block[0]&0xe0 != 0x20 {
		return block
	}
	// the updates are checked first, so a malformed one leaves the decoder untouched (it reports it)
	count, at, last := 0, 0, 0
	for at < len(block) && block[at]&0xe0 == 0x20 {
		value, n, ok := http2ReadHPACKInt(block[at:], 5)
		if !ok || value > math.MaxUint32 {
			return block
		}
		count++
		last = at
		at += n
	}
	if count < 2 {
		return block
	}
	for at = 0; at < last; {
		value, n, _ := http2ReadHPACKInt(block[at:], 5)
		decoder.SetMaxDynamicTableSize(uint32(value))
		at += n
	}
	return block[last:]
}

// http2ReadHPACKInt reads an HPACK integer with an n bit prefix (RFC 7541 5.1): its value, the bytes it takes,
// and false when it is incomplete or does not fit 63 bits
func http2ReadHPACKInt(p []byte, n uint) (value uint64, size int, ok bool) {
	if len(p) == 0 {
		return 0, 0, false
	}
	limit := uint64(1)<<n - 1
	value = uint64(p[0]) & limit
	if value < limit {
		return value, 1, true
	}
	var shift uint
	for i := 1; i < len(p); i++ {
		b := p[i]
		value += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, i + 1, true
		}
		shift += 7
		if shift >= 63 {
			return 0, 0, false
		}
	}
	return 0, 0, false
}

// the causes of a header desync of a direction
const (
	// http2DesyncDecodeError: a header block failed to decode, or decoded to invalid pseudo headers, after a gap
	http2DesyncDecodeError = iota
	// http2DesyncLateSkip: a call that may hold header block bytes arrived after the parser went past it
	http2DesyncLateSkip
	// http2DesyncFramingError: the parser resynchronized at the next call, past bytes that may hold a header block
	// (or dropped a header block too big to keep)
	http2DesyncFramingError
	// http2DesyncForcedLink: the parser gave up a missing call while the direction was in the middle of a header
	// block
	http2DesyncForcedLink
	// http2DesyncOrphanContinuation: a CONTINUATION frame whose header block start was not decoded
	http2DesyncOrphanContinuation
	http2DesyncCauses
)
