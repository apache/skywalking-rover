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

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"golang.org/x/net/http2"
)

// TestHTTP2FrameAcrossMissingEvent: a frame that spans two socket calls of one direction must not be
// completed with the bytes of a later socket call while the one in between has not been delivered.
// Reading across the gap decodes garbage and desynchronizes the HPACK table of the whole connection.
func TestHTTP2FrameAcrossMissingEvent(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.settings()
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 1, 0, bpfNow())
	server.settings()
	c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 2, 1, bpfNow())

	client.headers(1, false, requestFields("/first")...)
	client.data(1, true, bytes.Repeat([]byte("a"), 100))
	first := client.take()
	client.headers(3, false, requestFields("/second")...)
	client.data(3, true, bytes.Repeat([]byte("b"), 100))
	second := client.take()

	// the first request is written in two socket calls, the second one of them (data id 4) is late
	c.feedWithID(enums.SocketDataDirectionIngress, first[:30], 0, 3, 2, bpfNow())
	c.feedWithID(enums.SocketDataDirectionIngress, second, 0, 5, 4, bpfNow())
	c.analyze()
	m := c.metrics()
	if m.DecodeErrors != 0 || m.FramingErrors != 0 || len(m.Streams) != 0 {
		t.Fatalf("nothing may be parsed while data id 4 is missing: decodeErr=%d framingErr=%d open=%d",
			m.DecodeErrors, m.FramingErrors, len(m.Streams))
	}

	c.feedWithID(enums.SocketDataDirectionIngress, first[30:], 0, 4, 3, bpfNow())
	server.headers(1, true, responseFields("200")...)
	c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 6, 5, bpfNow())
	server.headers(3, true, responseFields("200")...)
	c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 7, 6, bpfNow())
	c.analyze()

	m = c.metrics()
	if m.DecodeErrors != 0 || m.FramingErrors != 0 || m.LateSkips != 0 {
		t.Fatalf("the late event must complete the frame: decodeErr=%d framingErr=%d late=%d",
			m.DecodeErrors, m.FramingErrors, m.LateSkips)
	}
	if len(c.analyzer.streams) != 2 {
		t.Fatalf("expected both streams, got %d: %+v", len(c.analyzer.streams), c.analyzer.streams)
	}
	if c.analyzer.streams[0].req[":path"] != "/first" || c.analyzer.streams[1].req[":path"] != "/second" {
		t.Fatalf("unexpected streams: %+v", c.analyzer.streams)
	}
}

// TestHTTP2ContinuationAcrossReleasedEvents: the header block of a HEADERS frame without END_HEADERS
// is kept as a slice of the events it was read from. Those events are released before the
// CONTINUATION arrives, so keeping only the start position loses every event in between and
// under-reports the header size.
func TestHTTP2ContinuationAcrossReleasedEvents(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)

	block := client.encode(requestFields("/continued-across-events")...)
	cut := len(block) / 2
	_ = client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:cut], EndHeaders: false})
	_ = client.framer.WriteContinuation(1, true, block[cut:])
	_ = client.framer.WriteData(1, true, bytes.Repeat([]byte("a"), 10))
	req := client.take()
	headerFrameBytes := int64(len(req) - (9 + 10)) // everything but the DATA frame

	// the request is analyzed while it arrives in small pieces, so the events the HEADERS frame was
	// read from are removed before the CONTINUATION is parsed
	const piece = 30
	for off := 0; off < len(req); off += piece {
		end := off + piece
		if end > len(req) {
			end = len(req)
		}
		c.feed(enums.SocketDataDirectionIngress, req[off:end], 0)
		c.analyze()
	}
	server.headers(1, true, responseFields("200")...)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	c.analyze()

	if len(c.analyzer.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d (decodeErr=%d framingErr=%d)", len(c.analyzer.streams),
			c.metrics().DecodeErrors, c.metrics().FramingErrors)
	}
	if got := c.analyzer.streams[0].reqHeaderBytes; got != headerFrameBytes {
		t.Fatalf("the header block size must cover every event it was read from: got %d, expected %d", got, headerFrameBytes)
	}
}

// TestHTTP2TruncatedSocketCallResync: a socket call that BPF truncated at the upload limit must not
// be completed with the bytes of the next socket call; the parser resynchronizes at the next call so
// the following requests still decode
func TestHTTP2TruncatedSocketCallResync(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.settings()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	server.settings()
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	// a big response written in one syscall, only the first part of it is uploaded
	server.headers(1, false, responseFields("200")...)
	server.data(1, false, bytes.Repeat([]byte("b"), 40000))
	truncated := server.take()
	c.dataID++
	ev := &aclevents.SocketDataUploadEvent{
		Protocol0: enums.ConnectionProtocolHTTP2, Direction0: enums.SocketDataDirectionEgress,
		DataLen: uint16(len(truncated) / 4), StartTime0: bpfNow(), EndTime0: bpfNow(), Finished: 1, HaveReduce: 1,
		ConnectionID: 1, RandomID: 1, DataID0: c.dataID, PrevDataID0: c.dataID - 1, TotalSize0: uint64(len(truncated)),
	}
	copy(ev.Buffer[:], truncated[:len(truncated)/4])
	c.conn.AppendData(ev)

	// the next socket call carries a complete request/response pair for another stream
	client.headers(3, true, requestFields("/after-truncation")...)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	server.headers(3, true, responseFields("200")...)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	c.analyze()

	if c.metrics().DecodeErrors != 0 {
		t.Fatalf("the header blocks after a truncated socket call must still decode: decodeErr=%d", c.metrics().DecodeErrors)
	}
	found := false
	for _, s := range c.analyzer.streams {
		if s.req[":path"] == "/after-truncation" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the stream after the truncated socket call was lost: %+v", c.analyzer.streams)
	}
}

// TestHTTP2DataFrameLengthIsBounded: a mis-framed header that decodes as a DATA frame with a random
// 24 bit length must not block the direction waiting for bytes that will never arrive
func TestHTTP2DataFrameLengthIsBounded(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.settings()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	server.settings()
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	// type 0 (DATA) with a length of ~8MB, as a mis-framed read would produce
	garbage := []byte{0x7f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'x', 'y'}
	c.feed(enums.SocketDataDirectionIngress, garbage, 0)
	client.headers(1, true, requestFields("/after-garbage")...)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	server.headers(1, true, responseFields("200")...)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	c.analyze()

	if len(c.analyzer.streams) != 1 || c.analyzer.streams[0].req[":path"] != "/after-garbage" {
		t.Fatalf("the parser must resynchronize instead of waiting for the bogus DATA frame: %+v, framingErr=%d",
			c.analyzer.streams, c.metrics().FramingErrors)
	}
}
