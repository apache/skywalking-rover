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
	"fmt"
	"math/rand"
	"testing"
	"time"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ---- test harness -------------------------------------------------------------------------------

type recordedStream struct {
	req, resp      map[string]string
	status         int
	reqBody        int64
	respBody       int64
	reqHeaderBytes int64
}

type recordingAnalyzer struct {
	streams []recordedStream
}

func (a *recordingAnalyzer) HandleWholeStream(_ *PartitionConnection, s *HTTP2Streaming) error {
	cp := func(m map[string]string) map[string]string {
		out := make(map[string]string, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	a.streams = append(a.streams, recordedStream{
		req: cp(s.ReqHeader), resp: cp(s.RespHeader), status: s.Status,
		reqBody: s.ReqBodyBuffer.DataSize(), respBody: s.RespBodyBuffer.DataSize(), reqHeaderBytes: s.ReqHeaderBuffer.DataSize(),
	})
	return nil
}

func (a *recordingAnalyzer) OnProtocolBreak(*PartitionConnection, *HTTP2Metrics) {}

// http2TestConn is a fake connection: the server side is captured, so client bytes are ingress
// and server bytes are egress, exactly like a server pod observed by the agent.
type http2TestConn struct {
	t        *testing.T
	proto    *HTTP2Protocol
	analyzer *recordingAnalyzer
	conn     *PartitionConnection
	dataID   uint64
}

func newHTTP2TestConn(t *testing.T) *http2TestConn {
	analyzer := &recordingAnalyzer{}
	proto := NewHTTP2Analyzer(nil, analyzer)
	conn := &PartitionConnection{
		connectionID:     1,
		randomID:         1,
		dataBuffers:      map[enums.ConnectionProtocol]*buffer.Buffer{enums.ConnectionProtocolHTTP2: buffer.NewBuffer()},
		protocol:         map[enums.ConnectionProtocol]uint64{enums.ConnectionProtocolHTTP2: 0},
		protocolAnalyzer: map[enums.ConnectionProtocol]Protocol{enums.ConnectionProtocolHTTP2: proto},
		protocolMetrics:  map[enums.ConnectionProtocol]ProtocolMetrics{enums.ConnectionProtocolHTTP2: proto.GenerateConnection(1, 1)},
	}
	return &http2TestConn{t: t, proto: proto, analyzer: analyzer, conn: conn}
}

func bpfNow() uint64 {
	return uint64(time.Since(host.BootTime))
}

// feed delivers the bytes as one socket call (one data id), optionally split in BPF chunks
func (c *http2TestConn) feed(direction enums.SocketDataDirection, data []byte, chunk int) {
	c.dataID++
	c.feedWithID(direction, data, chunk, c.dataID, c.dataID-1, bpfNow())
}

// feedWithID delivers one socket call with explicit data id / previous data id / start time (BPF time)
func (c *http2TestConn) feedWithID(direction enums.SocketDataDirection, data []byte, chunk int, dataID, prevDataID, start uint64) {
	if chunk <= 0 || chunk > len(data) {
		chunk = len(data)
	}
	if len(data) == 0 {
		return
	}
	seq := uint16(0)
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		ev := &aclevents.SocketDataUploadEvent{
			Protocol0: enums.ConnectionProtocolHTTP2, Direction0: direction, Sequence0: seq,
			DataLen: uint16(end - off), StartTime0: start, EndTime0: start,
			ConnectionID: 1, RandomID: 1, DataID0: dataID, PrevDataID0: prevDataID, TotalSize0: uint64(len(data)),
		}
		if end == len(data) {
			ev.Finished = 1
		}
		copy(ev.Buffer[:], data[off:end])
		c.conn.AppendData(ev)
		seq++
	}
}

func (c *http2TestConn) analyze() {
	if err := c.proto.Analyze(c.conn, &AnalyzeHelper{}); err != nil {
		c.t.Fatalf("analyze: %v", err)
	}
}

func (c *http2TestConn) metrics() *HTTP2Metrics {
	return c.conn.Metrics(enums.ConnectionProtocolHTTP2).(*HTTP2Metrics)
}

// http2Peer generates the bytes one endpoint sends, with its own HPACK encoder (one per direction)
type http2Peer struct {
	buf    bytes.Buffer
	framer *http2.Framer
	hbuf   bytes.Buffer
	enc    *hpack.Encoder
}

func newHTTP2Peer() *http2Peer {
	p := &http2Peer{}
	p.framer = http2.NewFramer(&p.buf, nil)
	p.enc = hpack.NewEncoder(&p.hbuf)
	return p
}

func (p *http2Peer) take() []byte {
	out := append([]byte(nil), p.buf.Bytes()...)
	p.buf.Reset()
	return out
}

func (p *http2Peer) encode(fields ...hpack.HeaderField) []byte {
	p.hbuf.Reset()
	for _, f := range fields {
		if err := p.enc.WriteField(f); err != nil {
			panic(err)
		}
	}
	return append([]byte(nil), p.hbuf.Bytes()...)
}

func hf(name, value string) hpack.HeaderField {
	return hpack.HeaderField{Name: name, Value: value}
}

func (p *http2Peer) preface() {
	p.buf.WriteString(http2.ClientPreface)
}

func (p *http2Peer) settings(settings ...http2.Setting) {
	if err := p.framer.WriteSettings(settings...); err != nil {
		panic(err)
	}
}

func (p *http2Peer) headers(stream uint32, endStream bool, fields ...hpack.HeaderField) {
	err := p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: p.encode(fields...), EndStream: endStream, EndHeaders: true})
	if err != nil {
		panic(err)
	}
}

func (p *http2Peer) data(stream uint32, endStream bool, body []byte) {
	if err := p.framer.WriteData(stream, endStream, body); err != nil {
		panic(err)
	}
}

func requestFields(path string) []hpack.HeaderField {
	return []hpack.HeaderField{hf(":method", "POST"), hf(":path", path), hf(":scheme", "http"), hf(":authority", "stress-server.spm-stress.svc:8081"),
		hf("content-type", "application/octet-stream"), hf("user-agent", "Go-http-client/2.0"), hf("x-request-id", "req-"+path)}
}

func responseFields(status string) []hpack.HeaderField {
	return []hpack.HeaderField{hf(":status", status), hf("content-type", "text/plain"), hf("date", "Mon, 20 Oct 2026 21:00:00 GMT"), hf("content-length", "1024")}
}

// ---- tests ----------------------------------------------------------------------------------------

// TestHTTP2PrefaceRequestResponse: a captured-from-the-start h2c connection, END_STREAM on the DATA frames
func TestHTTP2PrefaceRequestResponse(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.settings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
	_ = client.framer.WriteWindowUpdate(0, 1<<20)
	client.headers(1, false, requestFields("/api/stress?size=1024&delay=0")...)
	client.data(1, true, bytes.Repeat([]byte("a"), 1024))
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)

	server.settings()
	_ = server.framer.WriteSettingsAck()
	server.headers(1, false, responseFields("200")...)
	server.data(1, true, bytes.Repeat([]byte("b"), 1024))
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	c.analyze()
	if len(c.analyzer.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(c.analyzer.streams))
	}
	s := c.analyzer.streams[0]
	if s.req[":method"] != "POST" || s.req[":path"] != "/api/stress" || s.status != 200 || s.resp["content-type"] != "text/plain" {
		t.Fatalf("unexpected stream: %+v", s)
	}
	if s.reqBody != 1024 || s.respBody != 1024 {
		t.Fatalf("unexpected body sizes: req=%d resp=%d", s.reqBody, s.respBody)
	}
	if c.metrics().requestDirection != enums.SocketDataDirectionIngress {
		t.Fatalf("request direction should be learned from the preface")
	}
	if s.req[":path"] != "/api/stress" {
		t.Fatalf("the stored :path must not contain the query string, got %q", s.req[":path"])
	}
	if len(c.metrics().Streams) != 0 {
		t.Fatalf("stream should be removed after completion")
	}
}

// TestHTTP2DynamicTableAndInterleaving: many concurrent streams reuse headers through the HPACK dynamic
// table of each direction, requests and responses are interleaved in a realistic order (a batch of
// requests, then their responses), and the bytes arrive in arbitrary socket call / chunk boundaries with
// analyze calls in between (flush ticks). Nothing may be parsed twice or lost.
func TestHTTP2DynamicTableAndInterleaving(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	rnd := rand.New(rand.NewSource(7))

	type message struct {
		direction enums.SocketDataDirection
		data      []byte
	}
	var messages []message
	client.preface()
	client.settings()
	messages = append(messages, message{enums.SocketDataDirectionIngress, client.take()})
	server.settings()
	messages = append(messages, message{enums.SocketDataDirectionEgress, server.take()})
	const streams, batch = 40, 8
	for i := 0; i < streams; i += batch {
		for j := i; j < i+batch; j++ {
			id := uint32(2*j + 1)
			client.headers(id, false, requestFields(fmt.Sprintf("/api/stress/%d", j%4))...)
			client.data(id, true, bytes.Repeat([]byte("a"), 100+j))
		}
		messages = append(messages, message{enums.SocketDataDirectionIngress, client.take()})
		for j := i; j < i+batch; j++ {
			id := uint32(2*j + 1)
			server.headers(id, false, responseFields("200")...)
			server.data(id, false, bytes.Repeat([]byte("b"), 50))
			server.data(id, true, bytes.Repeat([]byte("c"), 50+j))
		}
		messages = append(messages, message{enums.SocketDataDirectionEgress, server.take()})
	}

	// deliver every message in random sized socket calls and BPF chunks, analyzing every now and then
	for _, msg := range messages {
		data := msg.data
		for len(data) > 0 {
			n := 1 + rnd.Intn(400)
			if n > len(data) {
				n = len(data)
			}
			c.feed(msg.direction, data[:n], 1+rnd.Intn(n))
			data = data[n:]
			if rnd.Intn(3) == 0 {
				c.analyze()
			}
		}
	}
	c.analyze()

	if len(c.analyzer.streams) != streams {
		m := c.metrics()
		t.Fatalf("expected %d streams, got %d (open=%d decodeErr=%d framingErr=%d late=%d dropped=%d)", streams, len(c.analyzer.streams),
			len(m.Streams), m.DecodeErrors, m.FramingErrors, m.LateSkips, m.DroppedStreams)
	}
	for i, s := range c.analyzer.streams {
		if s.req[":path"] != fmt.Sprintf("/api/stress/%d", i%4) || s.status != 200 || s.resp["date"] == "" {
			t.Fatalf("stream %d unexpected: %+v", i, s)
		}
		if s.reqBody != int64(100+i) || s.respBody != int64(100+i) {
			t.Fatalf("stream %d unexpected body sizes: req=%d resp=%d", i, s.reqBody, s.respBody)
		}
	}
	if m := c.metrics(); len(m.Streams) != 0 || len(m.pendingHeaders) != 0 || m.DecodeErrors != 0 || m.FramingErrors != 0 {
		t.Fatalf("no stream should stay open and no error expected: open=%d decodeErr=%d framingErr=%d", len(m.Streams), m.DecodeErrors, m.FramingErrors)
	}
}

// TestHTTP2ContinuationPaddingPriority: header block split over CONTINUATION frames, PADDED/PRIORITY flags
func TestHTTP2ContinuationPaddingPriority(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	block := client.encode(requestFields("/continued")...)
	cut := len(block) / 2
	_ = client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:cut], EndHeaders: false, EndStream: false,
		PadLength: 7, Priority: http2.PriorityParam{StreamDep: 0, Weight: 15}})
	_ = client.framer.WriteContinuation(1, true, block[cut:])
	_ = client.framer.WriteDataPadded(1, true, bytes.Repeat([]byte("a"), 300), bytes.Repeat([]byte{0}, 9))
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)

	rblock := server.encode(responseFields("201")...)
	_ = server.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: rblock[:3], EndHeaders: false})
	_ = server.framer.WriteContinuation(1, false, rblock[3:5])
	_ = server.framer.WriteContinuation(1, true, rblock[5:])
	_ = server.framer.WriteDataPadded(1, true, bytes.Repeat([]byte("b"), 200), bytes.Repeat([]byte{0}, 3))
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	c.analyze()
	if len(c.analyzer.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(c.analyzer.streams))
	}
	s := c.analyzer.streams[0]
	if s.req[":path"] != "/continued" || s.req["x-request-id"] != "req-/continued" || s.status != 201 {
		t.Fatalf("unexpected stream: %+v", s)
	}
	if s.reqBody != 300 || s.respBody != 200 {
		t.Fatalf("padding must not be counted: req=%d resp=%d", s.reqBody, s.respBody)
	}
}

// TestHTTP2GRPCTrailers: gRPC style exchange, the response ends with a trailers HEADERS frame
func TestHTTP2GRPCTrailers(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.settings()
	client.headers(1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":path", "/pkg.Service/Call"), hf(":authority", "svc"),
		hf("content-type", "application/grpc"), hf("te", "trailers"))
	client.data(1, true, []byte{0, 0, 0, 0, 5, 1, 2, 3, 4, 5})
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)

	server.settings()
	server.headers(1, false, hf(":status", "200"), hf("content-type", "application/grpc"))
	server.data(1, false, []byte{0, 0, 0, 0, 2, 9, 9})
	server.headers(1, true, hf("grpc-status", "0"), hf("grpc-message", ""))
	// trailers-only response on a second stream
	client.headers(3, true, hf(":method", "POST"), hf(":scheme", "http"), hf(":path", "/pkg.Service/Fail"), hf(":authority", "svc"), hf("content-type", "application/grpc"))
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	server.headers(3, true, hf(":status", "200"), hf("content-type", "application/grpc"), hf("grpc-status", "14"))
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	c.analyze()
	if len(c.analyzer.streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(c.analyzer.streams))
	}
	if s := c.analyzer.streams[0]; s.req[":path"] != "/pkg.Service/Call" || s.status != 200 || s.resp["grpc-status"] != "0" || s.respBody != 7 {
		t.Fatalf("unexpected unary stream: %+v", s)
	}
	if s := c.analyzer.streams[1]; s.req[":path"] != "/pkg.Service/Fail" || s.resp["grpc-status"] != "14" {
		t.Fatalf("unexpected trailers-only stream: %+v", s)
	}
}

// TestHTTP2MidConnectionJoin: the capture starts after the first request. The second request references
// the HPACK dynamic table and cannot be decoded: only that stream is lost, the connection keeps working
// and a later request that uses only static names and new values is reported.
func TestHTTP2MidConnectionJoin(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.settings()
	client.headers(1, true, requestFields("/first")...)
	client.take() // never captured
	server.settings()
	server.headers(1, true, responseFields("200")...)
	server.take() // never captured

	client.headers(3, true, requestFields("/first")...) // fully indexed against the lost dynamic table
	client.headers(5, true, hf(":method", "GET"), hf(":path", "/third"), hf(":scheme", "http"), hf(":authority", "other-host"))
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	server.headers(3, true, responseFields("200")...) // indexed against the lost response table
	server.headers(5, true, hf(":status", "404"), hf("content-length", "0"))
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	c.analyze()
	if len(c.analyzer.streams) != 1 {
		t.Fatalf("expected the decodable stream only, got %d", len(c.analyzer.streams))
	}
	if s := c.analyzer.streams[0]; s.req[":path"] != "/third" || s.status != 404 {
		t.Fatalf("unexpected stream: %+v", s)
	}
	if c.conn.skipAllDataAnalyze {
		t.Fatalf("the connection must not be downgraded")
	}
}

// TestHTTP2RSTStreamAndResync: a reset stream is forgotten, garbage bytes in one socket call do not
// break the connection, and the following frames are parsed again
func TestHTTP2RSTStreamAndResync(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.headers(1, false, requestFields("/cancelled")...)
	_ = client.framer.WriteRSTStream(1, http2.ErrCodeCancel)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	c.analyze()
	if len(c.metrics().Streams) != 0 {
		t.Fatalf("reset stream must be removed")
	}

	// a lost socket call: the next event is not contiguous, the parser must resync at the next event
	garbage := bytes.Repeat([]byte{0xff}, 100)
	c.feed(enums.SocketDataDirectionEgress, garbage, 0)
	server.headers(1, true, responseFields("200")...) // response for the reset stream: ignored
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	client.headers(3, true, requestFields("/after-reset")...)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	server.headers(3, true, hf(":status", "204"))
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	c.analyze()

	if len(c.analyzer.streams) != 1 || c.analyzer.streams[0].req[":path"] != "/after-reset" || c.analyzer.streams[0].status != 204 {
		t.Fatalf("unexpected streams: %+v", c.analyzer.streams)
	}
}

// TestHTTP2SettingsHeaderTableSize: the peer announces a bigger HPACK table and the encoder uses it
func TestHTTP2SettingsHeaderTableSize(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	server.settings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536})
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	client.preface()
	client.enc.SetMaxDynamicTableSizeLimit(65536)
	client.enc.SetMaxDynamicTableSize(65536) // emits a dynamic table size update in the next block
	for i := 0; i < 3; i++ {
		client.headers(uint32(2*i+1), true, requestFields(fmt.Sprintf("/big/%d", i))...)
		server.headers(uint32(2*i+1), true, responseFields("200")...)
	}
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	c.analyze()
	if len(c.analyzer.streams) != 3 {
		t.Fatalf("expected 3 streams, got %d", len(c.analyzer.streams))
	}
}

// TestHTTP2WaitForIncompleteFrame: a frame split across two socket calls with an analyze call in between
// is parsed exactly once when the rest arrives
func TestHTTP2WaitForIncompleteFrame(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.headers(1, false, requestFields("/split")...)
	client.data(1, true, bytes.Repeat([]byte("a"), 2000))
	in := client.take()
	c.feed(enums.SocketDataDirectionIngress, in[:40], 0) // preface + part of the HEADERS frame
	c.analyze()
	if len(c.metrics().Streams) != 0 {
		t.Fatalf("incomplete HEADERS must not create a stream")
	}
	c.feed(enums.SocketDataDirectionIngress, in[40:1500], 0)
	c.analyze()
	c.feed(enums.SocketDataDirectionIngress, in[1500:], 0)
	c.analyze()
	server.headers(1, true, responseFields("200")...)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	c.analyze()
	if len(c.analyzer.streams) != 1 || c.analyzer.streams[0].reqBody != 2000 {
		t.Fatalf("unexpected streams: %+v", c.analyzer.streams)
	}
}

// TestHTTP2OutOfOrderDelivery: socket events of different CPUs can be delivered out of order. The parser
// must wait for the missing event instead of skipping it (a skipped HEADERS frame desynchronizes HPACK),
// and give up only after the wait duration.
func TestHTTP2OutOfOrderDelivery(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.settings()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0) // data id 1
	client.headers(1, true, requestFields("/first")...)
	first := client.take()
	client.headers(3, true, requestFields("/second")...) // references the dynamic table entries of /first
	second := client.take()
	server.headers(1, true, responseFields("200")...)
	server.headers(3, true, responseFields("200")...)
	responses := server.take()

	// data id 2 (first request) is late: 3 and 4 arrive first
	c.feedWithID(enums.SocketDataDirectionIngress, second, 0, 3, 2, bpfNow())
	c.feedWithID(enums.SocketDataDirectionEgress, responses, 0, 4, 3, bpfNow())
	c.analyze()
	if len(c.analyzer.streams) != 0 || c.metrics().DecodeErrors != 0 {
		t.Fatalf("nothing must be parsed while data id 2 is missing: streams=%d decodeErr=%d", len(c.analyzer.streams), c.metrics().DecodeErrors)
	}
	c.feedWithID(enums.SocketDataDirectionIngress, first, 0, 2, 1, bpfNow())
	c.analyze()
	if len(c.analyzer.streams) != 2 || c.metrics().DecodeErrors != 0 || c.metrics().Gaps != 0 {
		t.Fatalf("expected both streams once the late event arrived: streams=%d decodeErr=%d gaps=%d", len(c.analyzer.streams), c.metrics().DecodeErrors, c.metrics().Gaps)
	}
	if c.analyzer.streams[0].req[":path"] != "/first" || c.analyzer.streams[1].req[":path"] != "/second" {
		t.Fatalf("unexpected order: %+v", c.analyzer.streams)
	}

	// an event that never arrives: the parser gives up after the wait duration and continues
	client.headers(5, true, hf(":method", "GET"), hf(":path", "/after-gap"), hf(":scheme", "http"), hf(":authority", "x"))
	old := bpfNow() - uint64(http2GapWaitDuration) - uint64(time.Second)
	c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 7, 6, old) // data id 6 is lost
	c.analyze()
	if c.metrics().Gaps != 1 || len(c.metrics().Streams) != 1 {
		t.Fatalf("expected the parser to continue after the gap: gaps=%d open=%d", c.metrics().Gaps, len(c.metrics().Streams))
	}
}

// TestHTTP2FrameSpanningOtherDirection: a request DATA frame split over two client writes with a
// server write in between must not be reported as a missing event (no 3s wait, no gap)
func TestHTTP2FrameSpanningOtherDirection(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.settings()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0) // 1
	server.settings()
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0) // 2
	client.headers(1, false, requestFields("/span")...)
	client.data(1, true, bytes.Repeat([]byte("a"), 3000))
	req := client.take()
	c.feed(enums.SocketDataDirectionIngress, req[:1500], 0) // 3: HEADERS + first part of DATA
	_ = server.framer.WriteWindowUpdate(0, 65535)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0) // 4: egress in the middle of the request DATA frame
	c.feed(enums.SocketDataDirectionIngress, req[1500:], 0)   // 5: rest of the DATA frame
	server.headers(1, true, responseFields("200")...)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0) // 6
	c.analyze()
	if len(c.analyzer.streams) != 1 || c.analyzer.streams[0].reqBody != 3000 || c.metrics().Gaps != 0 {
		t.Fatalf("expected the stream without any gap: streams=%d gaps=%d", len(c.analyzer.streams), c.metrics().Gaps)
	}
}

// TestHTTP2InvalidPseudoHeadersDropped: a block decoded against an out of sync dynamic table yields
// implausible pseudo headers; such streams must be dropped instead of reported
func TestHTTP2InvalidPseudoHeadersDropped(t *testing.T) {
	for _, h := range []map[string]string{{":method": "POST", ":path": "9993384u"}, {":method": "po st", ":path": "/x"}, {":status": "2x0"}, {":path": ""}} {
		if http2ValidPseudoHeaders(h) {
			t.Fatalf("headers %v must be rejected", h)
		}
	}
	for _, h := range []map[string]string{{":method": "POST", ":path": "/api/stress?x=1"}, {":method": "OPTIONS", ":path": "*"}, {":status": "404"}, {"grpc-status": "0"}} {
		if !http2ValidPseudoHeaders(h) {
			t.Fatalf("headers %v must be accepted", h)
		}
	}
}

// TestHTTP2TLSWriteEventsShareDataID: the Go TLS uprobe reports every crypto/tls Write call as its own
// event, all with the data id of the enclosing socket call and sequence 0, delivered in any order. The
// frame header and the payload of one frame arrive as separate events and must be parsed in time order.
func TestHTTP2TLSWriteEventsShareDataID(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.settings()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0) // 1
	client.headers(1, false, requestFields("/tls")...)
	headersFrame := client.take()
	client.data(1, true, bytes.Repeat([]byte("a"), 100))
	dataFrame := client.take()
	// every piece is a separate TLS write with the same data id 2, timestamps give the order; deliver the
	// payload events before their headers
	base := bpfNow()
	c.feedWithID(enums.SocketDataDirectionIngress, headersFrame[9:], 0, 2, 1, base+2)
	c.feedWithID(enums.SocketDataDirectionIngress, headersFrame[:9], 0, 2, 1, base+1)
	c.feedWithID(enums.SocketDataDirectionIngress, dataFrame[9:], 0, 2, 1, base+4)
	c.feedWithID(enums.SocketDataDirectionIngress, dataFrame[:9], 0, 2, 1, base+3)
	c.analyze()
	server.headers(1, true, responseFields("200")...)
	resp := server.take()
	c.feedWithID(enums.SocketDataDirectionEgress, resp[:9], 0, 3, 2, base+5)
	c.feedWithID(enums.SocketDataDirectionEgress, resp[9:], 0, 3, 2, base+6)
	c.analyze()
	if len(c.analyzer.streams) != 1 || c.analyzer.streams[0].req[":path"] != "/tls" || c.analyzer.streams[0].reqBody != 100 || c.analyzer.streams[0].status != 200 {
		m := c.metrics()
		t.Fatalf("unexpected result: streams=%+v decodeErr=%d framing=%d gaps=%d", c.analyzer.streams, m.DecodeErrors, m.FramingErrors, m.Gaps)
	}
}
