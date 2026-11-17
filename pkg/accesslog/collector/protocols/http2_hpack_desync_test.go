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
	"testing"
	"time"

	"golang.org/x/net/http2"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// TestHTTP2HeaderDesyncAfterLoss: when a HEADERS event is lost (a gap) and its HPACK dynamic table
// additions are therefore missing, the next blocks of that direction cannot be decoded. The parser must
// mark the direction as header-desynced once, count it in rover_http2_connections_header_desync_total, and
// stop decoding that direction (no resync exists for an indexed dynamic table), rather than failing per
// block forever.
func TestHTTP2HeaderDesyncAfterLoss(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.settings()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0) // id 1
	server.settings()
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0) // id 2

	before := http2HeaderDesyncs.Load()

	// id 3: first request, establishes dynamic table entries in both the peer encoder and our decoder (it
	// decodes cleanly; the stream stays open until a response, which this test does not send)
	client.headers(1, true, requestFields("/first")...)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	c.analyze()
	if c.metrics().DecodeErrors != 0 || c.metrics().headerDesync[enums.SocketDataDirectionIngress] {
		t.Fatalf("first request must decode cleanly: decodeErr=%d desync=%t",
			c.metrics().DecodeErrors, c.metrics().headerDesync[enums.SocketDataDirectionIngress])
	}

	// the peer encodes a second request that adds a distinctive entry to its dynamic table, but the event is
	// LOST: the encoder advances, our decoder never sees it
	client.headers(3, true, append(requestFields("/second"), hf("x-session", "shared-session-abcdefghij"))...)
	_ = client.take() // dropped on the wire

	// a third request references that dynamic entry by index. It arrives after the lost one (a gap), with a
	// timestamp old enough that the parser gives up waiting at once instead of after 3s
	client.headers(5, true, append(requestFields("/third"), hf("x-session", "shared-session-abcdefghij"))...)
	// the backdated event stands for one that already waited in the agent, since it reached the analysis too
	defer func(old time.Duration) { http2ArrivalWaitDuration = old }(http2ArrivalWaitDuration)
	http2ArrivalWaitDuration = 0
	old := bpfNow() - uint64(http2GapWaitDuration) - uint64(time.Second)
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 5, 4, old) // id 4 (the second request) is lost
	c.analyze()

	if c.metrics().Gaps == 0 {
		t.Fatalf("the lost event must register as a gap")
	}
	if c.metrics().DecodeErrors == 0 {
		t.Fatalf("the block that referenced the lost dynamic entry must fail to decode")
	}
	if !c.metrics().headerDesync[enums.SocketDataDirectionIngress] {
		t.Fatalf("the ingress direction must be marked header-desynced")
	}
	if got := http2HeaderDesyncs.Load() - before; got != 1 {
		t.Fatalf("the connection must be counted once as header-desynced, got %d", got)
	}

	// once marked, later blocks of that direction are dropped without decoding and without counting more
	// errors or desyncs; the stream count does not grow
	streamsNow := len(c.analyzer.streams)
	errsNow := c.metrics().DecodeErrors
	client.headers(7, true, requestFields("/fourth")...)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	c.analyze()
	if len(c.analyzer.streams) != streamsNow {
		t.Fatalf("a desynced direction must not report more streams: %d then %d", streamsNow, len(c.analyzer.streams))
	}
	if c.metrics().DecodeErrors != errsNow {
		t.Fatalf("a desynced direction must not keep counting decode errors: %d then %d", errsNow, c.metrics().DecodeErrors)
	}
	if got := http2HeaderDesyncs.Load() - before; got != 1 {
		t.Fatalf("the desync must be counted only once, got %d", got)
	}
}

// TestHTTP2HeaderDecodeErrorWithoutGapNotMarked: a connection captured mid stream fails to decode too, but
// without any lost event (no gap) it keeps the per-block behaviour (its static-table-only blocks still
// decode), so it is not marked desynced and not counted.
func TestHTTP2HeaderDecodeErrorWithoutGapNotMarked(t *testing.T) {
	c := newHTTP2TestConn(t)
	before := http2HeaderDesyncs.Load()

	// a header block that references a dynamic table entry that was never established (captured mid stream):
	// index 62 is the first dynamic slot, empty here, so the decode fails. No gap precedes it.
	block := []byte{0xbe} // indexed header field, dynamic index 62
	c.feed(enums.SocketDataDirectionIngress, http2HeadersFrame(1, true, block), 0)
	c.analyze()

	if c.metrics().Gaps != 0 {
		t.Fatalf("no gap expected")
	}
	if c.metrics().DecodeErrors == 0 {
		t.Fatalf("the block must fail to decode")
	}
	if c.metrics().headerDesync[enums.SocketDataDirectionIngress] {
		t.Fatalf("without a gap the direction must not be marked desynced")
	}
	if got := http2HeaderDesyncs.Load() - before; got != 0 {
		t.Fatalf("without a gap nothing must be counted, got %d", got)
	}
}

// http2HeadersFrame builds a HEADERS frame (END_HEADERS, optional END_STREAM) carrying block as its
// fragment, without an HPACK encoder, so a deliberately broken block can be sent
func http2HeadersFrame(stream uint32, endStream bool, block []byte) []byte {
	frame := make([]byte, 9+len(block))
	frame[0] = byte(len(block) >> 16)
	frame[1] = byte(len(block) >> 8)
	frame[2] = byte(len(block))
	frame[3] = 0x1 // HEADERS
	frame[4] = 0x4 // END_HEADERS
	if endStream {
		frame[4] |= 0x1
	}
	frame[8] = byte(stream)
	copy(frame[9:], block)
	return frame
}

// TestHTTP2LateHeaderBlockMarksDesync: the socket call that entered first returned last (its upload names the
// later call as its previous one), so the parser reads the later call first and skips the earlier one as late
// when it arrives; no event is missing, so there is no gap. The late call holds a header block that adds to the
// dynamic table, which the decoder never sees: the block read before it was decoded against a table without it,
// and so may be every later one. The direction is marked header-desynced at the late skip, the open stream
// decoded after the skipped call is dropped instead of being reported with the headers the decoder may have got
// wrong, and the stream decoded before it is still reported.
func TestHTTP2LateHeaderBlockMarksDesync(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.settings()
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 1, 0, bpfNow())
	server.settings()
	c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 2, 1, bpfNow())
	client.headers(1, true, requestFields("/a")...)
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 3, 2, bpfNow())
	client.headers(3, true, append(requestFields("/b"), hf("x-session", "only-in-the-late-block"))...)
	late := client.take()
	client.headers(5, true, append(requestFields("/b"), hf("x-session", "only-in-the-late-block"))...)
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 5, 3, bpfNow())
	c.analyze()

	c.feedWithID(enums.SocketDataDirectionIngress, late, 0, 4, 5, bpfNow())
	c.analyze()
	if c.metrics().LateSkips != 1 || c.metrics().Gaps != 0 {
		t.Fatalf("late skips %d, gaps %d", c.metrics().LateSkips, c.metrics().Gaps)
	}
	if !c.metrics().headerDesync[enums.SocketDataDirectionIngress] || c.metrics().headerDesync[enums.SocketDataDirectionEgress] {
		t.Fatalf("the request direction must be marked, only it: %v", c.metrics().headerDesync)
	}

	server.headers(1, true, responseFields("200")...)
	c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 6, 4, bpfNow())
	server.headers(5, true, responseFields("200")...)
	c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 7, 6, bpfNow())
	c.analyze()
	if len(c.analyzer.streams) != 1 || c.analyzer.streams[0].req[":path"] != "/a" {
		t.Fatalf("only the stream decoded before the late call may be reported: %+v", c.analyzer.streams)
	}
}

// TestHTTP2ForcedLinkInHeaderBlockMarksDesync: a HEADERS frame waits for its CONTINUATION, and the call holding
// it is lost: when the parser gives it up the header block can never be decoded whole, so the direction is marked
func TestHTTP2ForcedLinkInHeaderBlockMarksDesync(t *testing.T) {
	defer func(old time.Duration) { http2ArrivalWaitDuration = old }(http2ArrivalWaitDuration)
	http2ArrivalWaitDuration = 0
	c := newHTTP2TestConn(t)
	client := newHTTP2Peer()
	client.preface()
	client.settings()
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 1, 0, bpfNow())
	block := client.encode(requestFields("/split")...)
	if err := client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:4], EndStream: true}); err != nil {
		t.Fatal(err)
	}
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 2, 1, bpfNow())
	c.analyze()
	// the CONTINUATION (id 3) is lost; the next call is old enough to be given up at once
	client.headers(3, true, requestFields("/next")...)
	old := bpfNow() - uint64(http2GapWaitDuration) - uint64(time.Second)
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 4, 3, old)
	c.analyze()
	if c.metrics().Gaps != 1 || !c.metrics().headerDesync[enums.SocketDataDirectionIngress] {
		t.Fatalf("gaps %d, desync %v", c.metrics().Gaps, c.metrics().headerDesync)
	}
	if len(c.analyzer.streams) != 0 {
		t.Fatalf("no stream may be reported: %+v", c.analyzer.streams)
	}
}

// TestHTTP2DroppedHeaderBytes: what a dropped socket event may hold of a header block
func TestHTTP2DroppedHeaderBytes(t *testing.T) {
	p := newHTTP2Peer()
	p.headers(1, false, requestFields("/x")...)
	headers := p.take()
	p.data(1, false, bytes.Repeat([]byte{'d'}, 1000))
	data := p.take()
	_ = p.framer.WriteWindowUpdate(0, 100)
	window := p.take()
	event := func(b []byte, seq uint16, finished bool, total int) *aclevents.SocketDataUploadEvent {
		ev := &aclevents.SocketDataUploadEvent{Protocol0: enums.ConnectionProtocolHTTP2, DataID0: 9, Sequence0: seq,
			DataLen: uint16(len(b)), TotalSize0: uint64(total)}
		if finished {
			ev.Finished = 1
		}
		if total > len(b) && finished {
			ev.HaveReduce = 1
		}
		ev.Buffer = buffer.AdmittedEventData(b)
		return ev
	}
	d := enums.SocketDataDirectionIngress
	cases := []struct {
		name string
		ev   *aclevents.SocketDataUploadEvent
		from int
		want bool
	}{
		{"control and data frames", event(append(append([]byte(nil), window...), data...), 0, true, len(window)+len(data)), 0, false},
		{"a header frame", event(append(append([]byte(nil), window...), headers...), 0, true, len(window)+len(headers)), 0, true},
		{"header frame before the offset", event(append(append([]byte(nil), headers...), data...), 0, true, len(headers)+len(data)), len(headers), false},
		{"not a frame boundary", event(data[20:], 0, true, len(data)-20), 0, true},
		{"a cut frame header", event(append(append([]byte(nil), data...), window[:5]...), 0, true, len(data)+5), 0, true},
		{"truncated inside the last frame", event(data[:300], 0, true, len(data)), 0, false},
		{"truncated with bytes behind the last frame", event(data[:300], 0, true, len(data)+len(headers)), 0, true},
	}
	for _, c := range cases {
		m := &HTTP2Metrics{}
		if got := m.droppedHeaderBytes(d, c.ev, c.from); got != c.want {
			t.Errorf("%s: %t, expected %t", c.name, got, c.want)
		}
	}
	skipped := event(nil, 0, true, 5000)
	skipped.PayloadSkipped0 = 1
	if (&HTTP2Metrics{}).droppedHeaderBytes(d, skipped, 0) {
		t.Errorf("a call skipped inside a payload holds no header bytes")
	}
	// the chunks of one call: the second one lies inside the DATA frame the first one starts
	m := &HTTP2Metrics{}
	if m.droppedHeaderBytes(d, event(data[:400], 0, false, len(data)), 0) || m.droppedHeaderBytes(d, event(data[400:800], 1, false, len(data)), 0) ||
		m.droppedHeaderBytes(d, event(data[800:], 2, true, len(data)), 0) {
		t.Errorf("the chunks of a DATA frame hold no header bytes")
	}
	m = &HTTP2Metrics{}
	if !m.droppedHeaderBytes(d, event(data[400:800], 1, false, len(data)), 0) {
		t.Errorf("a chunk whose call start is unknown may hold anything")
	}
}
