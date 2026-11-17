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
	"encoding/base64"
	"strings"
	"testing"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"golang.org/x/net/http2"
)

// TestHTTP2PendingBlocksPerDirection: both peers are in the middle of a header block of the same stream at once
// (response headers and request trailers in CONTINUATION frames): each block completes on its own
func TestHTTP2PendingBlocksPerDirection(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)
	client.headers(1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":path", "/both"), hf(":authority", "a"))
	client.data(1, false, []byte("abc"))
	c.feed(hpIn, client.take(), 0)

	resp := server.encode(hf(":status", "200"), hf("x-r", strings.Repeat("r", 40)))
	_ = server.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: resp[:6]})
	c.feed(hpOut, server.take(), 0)
	trailers := client.encode(hf("x-checksum", strings.Repeat("c", 40)))
	_ = client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: trailers[:4], EndStream: true})
	c.feed(hpIn, client.take(), 0)
	_ = server.framer.WriteContinuation(1, true, resp[6:])
	c.feed(hpOut, server.take(), 0)
	_ = client.framer.WriteContinuation(1, true, trailers[4:])
	c.feed(hpIn, client.take(), 0)
	server.data(1, true, []byte("done"))
	c.feed(hpOut, server.take(), 0)
	// later blocks of both directions refer to the entries of the two blocks
	client.headers(3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/both"), hf(":authority", "a"),
		hf("x-checksum", strings.Repeat("c", 40)))
	c.feed(hpIn, client.take(), 0)
	server.headers(3, true, hf(":status", "200"), hf("x-r", strings.Repeat("r", 40)))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "POST /both 200", "GET /both 200")
	if c.blocks[hpIn][1]["x-checksum"] == "" || c.blocks[hpOut][1]["x-r"] == "" {
		t.Fatalf("blocks: %v / %v", c.blocks[hpIn], c.blocks[hpOut])
	}
}

func testEvent(data []byte, direction enums.SocketDataDirection) *aclevents.SocketDataUploadEvent {
	ev := &aclevents.SocketDataUploadEvent{Protocol0: enums.ConnectionProtocolHTTP2, Direction0: direction, DataLen: uint16(len(data)),
		ConnectionID: 1, RandomID: 1, DataID0: 7, TotalSize0: uint64(len(data)), Finished: 1}
	ev.Buffer = buffer.AdmittedEventData(data)
	return ev
}

// TestHTTP2WalkForHeaderBytes: the walk of a dropped call counts PUSH_PROMISE as header bytes and steps over the
// extension frames
func TestHTTP2WalkForHeaderBytes(t *testing.T) {
	frames := func(write func(f *http2.Framer)) []byte {
		var b bytes.Buffer
		write(http2.NewFramer(&b, nil))
		return b.Bytes()
	}
	control := frames(func(f *http2.Framer) {
		_ = f.WritePing(false, [8]byte{})
		_ = f.WriteRawFrame(0x0a, 0, 0, []byte{0, 1, 'a', 'x'})
		_ = f.WriteRawFrame(0x2a, 0, 3, nil)
		_ = f.WriteWindowUpdate(0, 10)
		_ = f.WriteData(1, false, []byte("payload"))
	})
	if may, end := http2WalkForHeaderBytes(testEvent(control, hpOut), 0, 1<<20); may || end != len(control) {
		t.Fatalf("control and extension frames: may=%v end=%d/%d", may, end, len(control))
	}
	push := frames(func(f *http2.Framer) {
		_ = f.WritePing(false, [8]byte{})
		_ = f.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: []byte{0x82}, EndHeaders: true})
	})
	if may, _ := http2WalkForHeaderBytes(testEvent(push, hpOut), 0, 1<<20); !may {
		t.Fatalf("a PUSH_PROMISE holds header bytes")
	}
}

// TestHTTP2UnknownFrameTypeAtProvenBoundary: an unknown frame type right behind a frame of the same call is
// stepped over; at the start of a call only when BPF reports where the frames of the call are
func TestHTTP2UnknownFrameTypeAtProvenBoundary(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)
	_ = client.framer.WritePing(false, [8]byte{1})
	_ = client.framer.WriteRawFrame(0xfe, 0x3, 0, []byte("unknown"))
	client.headers(1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/x"), hf(":authority", "a"))
	_ = client.framer.WriteRawFrame(0x77, 0, 1, nil)
	c.feed(hpIn, client.take(), 0)
	server.headers(1, true, hf(":status", "200"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "GET /x 200")

	// at the start of a call: still lost framing, unless BPF knew the cursor of the call
	defer SetHTTP2CallFramesSource(nil)
	SetHTTP2CallFramesSource(func(buffer.SocketDataBuffer) (HTTP2CallFrames, bool) {
		return HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 0}, true
	})
	_ = client.framer.WriteRawFrame(0xfe, 0, 0, []byte{1})
	c.feed(hpIn, client.take(), 0)
	client.headers(3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/y"), hf(":authority", "a"))
	c.feed(hpIn, client.take(), 0)
	server.headers(3, true, hf(":status", "200"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "GET /x 200", "GET /y 200")
}

// TestHTTP2CallHeaderBytesHint: the frame flags of a call answer droppedHeaderBytes without the walk
func TestHTTP2CallHeaderBytesHint(t *testing.T) {
	m := newHTTP2TestConn(t).metrics()
	garbage := testEvent([]byte("not a frame at all, the walk says it may hold header bytes"), hpIn)
	if !m.droppedHeaderBytes(hpIn, garbage, 0) {
		t.Fatalf("without flags the walk decides")
	}
	defer SetHTTP2CallFramesSource(nil)
	SetHTTP2CallFramesSource(func(buffer.SocketDataBuffer) (HTTP2CallFrames, bool) {
		return HTTP2CallFrames{CursorKnown: true, NoHeaderBytes: true}, true
	})
	if m.droppedHeaderBytes(hpIn, garbage, 0) {
		t.Fatalf("a call without header bytes holds none")
	}
}

func TestHTTP2ValidMethod(t *testing.T) {
	for _, ok := range []string{"GET", "propfind", "M-SEARCH", "BASELINE-CONTROL", "UPDATEREDIRECTREF", "custom1", "X_Y.Z~"} {
		if !http2ValidMethod(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "200", "application/json", "gzip, deflate", "text plain", strings.Repeat("A", 25), "Mon, 20 Oct"} {
		if http2ValidMethod(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)
	client.headers(1, true, hf(":method", "purge"), hf(":scheme", "http"), hf(":path", "/cache"), hf(":authority", "a"))
	c.feed(hpIn, client.take(), 0)
	server.headers(1, true, hf(":status", "200"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "purge /cache 200")
}

// ---- h2c upgrade (RFC 7540 3.2) ---------------------------------------------------------------------------------

// http2UpgradeConn is a connection analysed by the HTTP/1 and the HTTP/2 parser, as the queue does: the HTTP/1 data
// first (smaller data ids)
type http2UpgradeConn struct {
	*http2TestConn
	h1 *HTTP1Protocol
}

func newHTTP2UpgradeConn(t *testing.T) *http2UpgradeConn {
	c := newHTTP2TestConn(t)
	h1 := NewHTTP1Analyzer(nil, nil)
	c.conn.dataBuffers[enums.ConnectionProtocolHTTP] = buffer.NewBuffer()
	c.conn.protocol[enums.ConnectionProtocolHTTP] = 0
	c.conn.protocolAnalyzer[enums.ConnectionProtocolHTTP] = h1
	c.conn.protocolMetrics[enums.ConnectionProtocolHTTP] = h1.GenerateConnection(1, 1)
	return &http2UpgradeConn{http2TestConn: c, h1: h1}
}

func (u *http2UpgradeConn) feedProto(protocol enums.ConnectionProtocol, d enums.SocketDataDirection, data []byte, dataID uint64) {
	ev := &aclevents.SocketDataUploadEvent{Protocol0: protocol, Direction0: d, DataLen: uint16(len(data)), StartTime0: bpfNow(),
		EndTime0: bpfNow(), ConnectionID: 1, RandomID: 1, DataID0: dataID, PrevDataID0: dataID - 1, TotalSize0: uint64(len(data)), Finished: 1}
	// a pooled buffer, as the reader takes it: the HTTP/1 analysis releases the bytes of the request head before the
	// HTTP/2 parser meets the 101 (the headers of the upgrade must be kept by the head reader)
	ev.Buffer = buffer.TakeBuffer(len(data))
	copy(ev.Buffer, data)
	u.conn.AppendData(ev)
	if dataID > u.dataID {
		u.dataID = dataID
	}
}

func (u *http2UpgradeConn) analyzeAll() {
	if err := u.h1.Analyze(u.conn, &AnalyzeHelper{}); err != nil {
		u.t.Fatal(err)
	}
	u.analyze()
}

func upgradeRequest(settings []byte) []byte {
	return []byte("GET /up/load?x=1 HTTP/1.1\r\nHost: up.test:8080\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" +
		"HTTP2-Settings: " + base64.RawURLEncoding.EncodeToString(settings) + "\r\nsw8: 1-trace-upgrade\r\nUser-Agent: test\r\n\r\n")
}

const upgradeResponse = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"

// TestHTTP2UpgradeFromHTTP1: the upgrade request is HTTP/1 data, the 101 call (with the server preface and the
// response of stream 1 behind it in the same call) and everything after it HTTP/2 data, as BPF reports them.
// Stream 1 is the HTTP/1.1 request; the client's HTTP2-Settings (a 100 byte table) bound the server's encoder.
func TestHTTP2UpgradeFromHTTP1(t *testing.T) {
	for _, variant := range []string{"in-order", "request-late", "split-101"} {
		t.Run(variant, func(t *testing.T) {
			u := newHTTP2UpgradeConn(t)
			client, server := newHTTP2Peer(), newHTTP2Peer()
			var settings bytes.Buffer
			_ = http2.NewFramer(&settings, nil).WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 100})
			request := upgradeRequest(settings.Bytes()[http2FrameHeaderLen:])

			server.buf.WriteString(upgradeResponse)
			server.settings()
			server.enc.SetMaxDynamicTableSizeLimit(100)
			server.headers(1, false, hf(":status", "200"), hf("content-type", "text/plain"))
			server.data(1, true, []byte("upgraded"))
			first := server.take()

			switch variant {
			case "in-order":
				u.feedProto(enums.ConnectionProtocolHTTP, hpIn, request, 1)
				u.feedProto(enums.ConnectionProtocolHTTP2, hpOut, first, 2)
			case "request-late":
				// the 101 is analysed before the HTTP/1 analysis has the request: it waits for it
				u.feedProto(enums.ConnectionProtocolHTTP2, hpOut, first, 2)
				u.analyzeAll()
				if n := len(u.analyzer.streams); n != 0 {
					t.Fatalf("streams before the request: %d", n)
				}
				u.feedProto(enums.ConnectionProtocolHTTP, hpIn, request, 1)
			case "split-101":
				u.feedProto(enums.ConnectionProtocolHTTP, hpIn, request, 1)
				u.feedProto(enums.ConnectionProtocolHTTP2, hpOut, first[:20], 2)
				u.analyzeAll()
				u.feedProto(enums.ConnectionProtocolHTTP2, hpOut, first[20:], 3)
			}
			u.analyzeAll()

			client.preface()
			client.settings()
			_ = client.framer.WriteSettingsAck()
			client.headers(3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/after"), hf(":authority", "up.test:8080"))
			u.feedProto(enums.ConnectionProtocolHTTP2, hpIn, client.take(), u.dataID+1)
			_ = server.framer.WriteSettingsAck()
			server.headers(3, true, hf(":status", "404"), hf("content-type", "text/plain"))
			u.feedProto(enums.ConnectionProtocolHTTP2, hpOut, server.take(), u.dataID+1)
			u.analyzeAll()

			u.expectClean(t)
			u.expectStreams(t, "GET /up/load 200", "GET /after 404")
			s := u.analyzer.streams[0]
			if s.req[":authority"] != "up.test:8080" || s.req["sw8"] != "1-trace-upgrade" || s.respBody != 8 ||
				s.reqHeaderBytes != int64(len(request)) {
				t.Fatalf("stream 1: %+v (request %d bytes)", s, len(request))
			}
			if m := u.metrics(); m.requestDirection != hpIn || len(m.Streams) != 0 {
				t.Fatalf("request direction %d, open streams %d", m.requestDirection, len(m.Streams))
			}
			// the HTTP2-Settings of the request bound the table of the server's encoder to 100 bytes
			if err := http2DecodeHeaderBlock(u.metrics().decoders[hpOut], hpSizeUpdate(200)); err == nil {
				t.Fatalf("HTTP2-Settings not applied: a 200 byte table was accepted")
			}
		})
	}
}

// TestHTTP2UpgradeOtherProtocol: a 101 to another protocol is no HTTP/2
func TestHTTP2UpgradeOtherProtocol(t *testing.T) {
	if http2IsH2CUpgradeHead([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")) {
		t.Fatalf("websocket taken for h2c")
	}
	if !http2IsH2CUpgradeHead([]byte("HTTP/1.1 101 Switching Protocols\r\nupgrade: H2C\r\n\r\n")) {
		t.Fatalf("h2c not recognised")
	}
}
