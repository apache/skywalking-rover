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
	"strings"
	"testing"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

type recordingHTTP1 struct {
	handled []string
	details []buffer.SocketDataBuffer // the response body events kept for the kernel log details
}

func (a *recordingHTTP1) HandleHTTPData(_ *HTTP1Metrics, _ *PartitionConnection, req *reader.Request, resp *reader.Response) error {
	a.handled = append(a.handled, fmt.Sprintf("%s %s -> %d req=%d resp=%d", req.Original().Method, req.Original().URL.Path,
		resp.Original().StatusCode, req.BodyBuffer().DataSize(), resp.BodyBuffer().DataSize()))
	a.details = resp.BodyBuffer().TotalBuffer()
	return nil
}

func (a *recordingHTTP1) OnProtocolBreak(*HTTP1Metrics, *PartitionConnection) {}

type http1TestConn struct {
	t        *testing.T
	proto    *HTTP1Protocol
	analyzer *recordingHTTP1
	conn     *PartitionConnection
	dataID   uint64
}

func newHTTP1TestConn(t *testing.T) *http1TestConn {
	analyzer := &recordingHTTP1{}
	proto := NewHTTP1Analyzer(nil, analyzer)
	conn := &PartitionConnection{
		connectionID:     1,
		randomID:         1,
		dataBuffers:      map[enums.ConnectionProtocol]*buffer.Buffer{enums.ConnectionProtocolHTTP: buffer.NewBuffer()},
		protocol:         map[enums.ConnectionProtocol]uint64{enums.ConnectionProtocolHTTP: 0},
		protocolAnalyzer: map[enums.ConnectionProtocol]Protocol{enums.ConnectionProtocolHTTP: proto},
		protocolMetrics:  map[enums.ConnectionProtocol]ProtocolMetrics{enums.ConnectionProtocolHTTP: proto.GenerateConnection(1, 1)},
	}
	return &http1TestConn{t: t, proto: proto, analyzer: analyzer, conn: conn}
}

// feed delivers one socket call: `data` is what the application wrote/read, BPF uploads it in chunks of
// 20480 bytes but at most maxChunks of them (SOCKET_UPLOAD_CHUNK_LIMIT); the rest is marked as reduced.
func (c *http1TestConn) feed(direction enums.SocketDataDirection, data []byte, maxChunks int) {
	c.dataID++
	const chunk = 20480
	seq := uint16(0)
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		ev := &aclevents.SocketDataUploadEvent{
			Protocol0: enums.ConnectionProtocolHTTP, Direction0: direction, Sequence0: seq,
			DataLen: uint16(end - off), StartTime0: bpfNow(), EndTime0: bpfNow(),
			ConnectionID: 1, RandomID: 1, DataID0: c.dataID, PrevDataID0: c.dataID - 1, TotalSize0: uint64(len(data)),
		}
		copy(ev.Buffer[:], data[off:end])
		last := end == len(data)
		// BPF flags every chunk that does not complete the socket call, and marks the last chunk it
		// uploads as finished, whether the call ended or the chunk budget ran out
		if !last {
			ev.HaveReduce = 1
		}
		if last || int(seq)+1 == maxChunks {
			ev.Finished = 1
		}
		c.conn.AppendData(ev)
		if int(seq)+1 == maxChunks && !last {
			return // the chunk budget of the socket call is used up, the rest is never uploaded
		}
		seq++
	}
}

func (c *http1TestConn) analyze() {
	if err := c.proto.Analyze(c.conn, &AnalyzeHelper{}); err != nil {
		c.t.Fatalf("analyze: %v", err)
	}
}

func (c *http1TestConn) pending() int {
	return c.conn.Buffer(enums.ConnectionProtocolHTTP).DataLength()
}

func http1Request(path string, body int) []byte {
	return []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: stress-server\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\n\r\n", path, body) + strings.Repeat("a", body))
}

func http1Response(body int) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n", body) + strings.Repeat("b", body))
}

// a 256KB response written by the server in one syscall: BPF uploads only 6 x 20KB of it
func TestHTTP1LargeResponseTruncatedByBPF(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionIngress, http1Request("/api/stress", 1024), 6)
	c.feed(enums.SocketDataDirectionEgress, http1Response(262144), 6)
	c.analyze()
	t.Logf("handled: %v, pending events: %d", c.analyzer.handled, c.pending())
	if len(c.analyzer.handled) != 1 {
		t.Fatalf("the request/response was not handled: %v", c.analyzer.handled)
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending after the message was handled", c.pending())
	}
	if !strings.HasSuffix(c.analyzer.handled[0], "resp=262144") {
		t.Fatalf("the response body size must be the real one (Content-Length), got %s", c.analyzer.handled[0])
	}
}

// a 256KB response read by the client in 16KB syscalls: nothing is truncated
func TestHTTP1LargeResponseInSmallReads(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionEgress, http1Request("/api/stress", 1024), 6)
	resp := http1Response(262144)
	for off := 0; off < len(resp); off += 16384 {
		end := off + 16384
		if end > len(resp) {
			end = len(resp)
		}
		c.feed(enums.SocketDataDirectionIngress, resp[off:end], 6)
	}
	c.analyze()
	t.Logf("handled: %v, pending events: %d", c.analyzer.handled, c.pending())
	if len(c.analyzer.handled) != 1 {
		t.Fatalf("the request/response was not handled: %v", c.analyzer.handled)
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending after the message was handled", c.pending())
	}
}

// the same traffic as the stress test: 1KB requests / 256KB responses on one keep-alive connection,
// the response written in one syscall each time; the buffer must not grow with the number of requests
func TestHTTP1LargeResponsesKeepAliveDoNotAccumulate(t *testing.T) {
	c := newHTTP1TestConn(t)
	for i := 0; i < 20; i++ {
		c.feed(enums.SocketDataDirectionIngress, http1Request("/api/stress", 1024), 6)
		c.feed(enums.SocketDataDirectionEgress, http1Response(262144), 6)
		c.analyze()
	}
	t.Logf("handled: %d, pending events: %d", len(c.analyzer.handled), c.pending())
	if len(c.analyzer.handled) != 20 {
		t.Fatalf("expected 20 handled messages, got %d", len(c.analyzer.handled))
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending", c.pending())
	}
}

// streaming: the body of a Content-Length message is consumed as it arrives, the events are released
// before the message is complete, and the kernel log details of every socket call are kept
func TestHTTP1LargeBodyStreamedRelease(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionEgress, http1Request("/api/stress", 1024), 6)
	resp := http1Response(262144)
	chunks := [][]byte{}
	for off := 0; off < len(resp); off += 16384 {
		end := off + 16384
		if end > len(resp) {
			end = len(resp)
		}
		chunks = append(chunks, resp[off:end])
	}
	maxPending := 0
	for i, ch := range chunks {
		c.feed(enums.SocketDataDirectionIngress, ch, 6)
		if i%4 == 3 {
			c.analyze()
			if c.pending() > maxPending {
				maxPending = c.pending()
			}
		}
	}
	c.analyze()
	t.Logf("handled: %v, max pending during the body: %d, pending at the end: %d", c.analyzer.handled, maxPending, c.pending())
	if len(c.analyzer.handled) != 1 || !strings.HasSuffix(c.analyzer.handled[0], "resp=262144") {
		t.Fatalf("message not handled correctly: %v", c.analyzer.handled)
	}
	if maxPending > 2 {
		t.Fatalf("body events were held instead of being released as they arrived: %d pending", maxPending)
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending", c.pending())
	}
	if got := len(c.analyzer.details); got != len(chunks) {
		t.Fatalf("the kernel log details of the body must be kept: %d details for %d socket calls", got, len(chunks))
	}
	// the kept details must be metadata only: a copy that still carries the 20KB array releases nothing
	for i, d := range c.analyzer.details {
		if len(d.BufferData()) != 0 {
			t.Fatalf("the kept detail %d still carries its data buffer (%d bytes), no memory was released", i, len(d.BufferData()))
		}
		if d.BufferLen() == 0 {
			t.Fatalf("the kept detail %d lost its size", i)
		}
	}
}

// a request body in one truncated socket call followed by the response on the same connection
func TestHTTP1LargeRequestTruncatedThenResponse(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionIngress, http1Request("/api/stress", 262144), 6)
	c.analyze()
	c.feed(enums.SocketDataDirectionEgress, http1Response(1024), 6)
	c.analyze()
	t.Logf("handled: %v, pending: %d", c.analyzer.handled, c.pending())
	if len(c.analyzer.handled) != 1 || !strings.HasSuffix(c.analyzer.handled[0], "req=262144 resp=1024") {
		t.Fatalf("message not handled correctly: %v", c.analyzer.handled)
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending", c.pending())
	}
}

func http1ChunkedResponse(chunks []int) []byte {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
	for _, n := range chunks {
		b.WriteString(fmt.Sprintf("%x;ext=1\r\n", n))
		b.WriteString(strings.Repeat("c", n))
		b.WriteString("\r\n")
	}
	b.WriteString("0\r\nX-Trailer: done\r\n\r\n")
	return []byte(b.String())
}

// http1ChunkedResponseParts builds a chunked response together with offsets that fall inside a
// chunk-size line, between its CR and LF, and inside the trailer block
func http1ChunkedResponseParts(chunks []int) (data []byte, cuts []int) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
	for _, n := range chunks {
		line := fmt.Sprintf("%x;ext=1\r\n", n)
		cuts = append(cuts, b.Len()+2, b.Len()+len(line)-1)
		b.WriteString(line)
		b.WriteString(strings.Repeat("c", n))
		b.WriteString("\r\n")
	}
	trailer := "0\r\nX-Trailer: done\r\n\r\n"
	cuts = append(cuts, b.Len()+1, b.Len()+len(trailer)-4)
	b.WriteString(trailer)
	return []byte(b.String()), cuts
}

// TestHTTP1ChunkedBodySizeLineSplitAcrossEvents: the chunk-size lines and the trailer block are cut
// in the middle by the socket call boundaries, so the partial-line accumulation of the chunked
// consumer is exercised
func TestHTTP1ChunkedBodySizeLineSplitAcrossEvents(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionEgress, http1Request("/api/stress", 1024), 6)
	chunks := []int{70000, 70000, 70000, 52144} // 262144 data bytes
	resp, cuts := http1ChunkedResponseParts(chunks)
	prev := 0
	for _, cut := range append(cuts, len(resp)) {
		if cut <= prev || cut > len(resp) {
			continue
		}
		c.feed(enums.SocketDataDirectionIngress, resp[prev:cut], 6)
		c.analyze()
		prev = cut
	}
	c.analyze()
	if len(c.analyzer.handled) != 1 || !strings.HasSuffix(c.analyzer.handled[0], "resp=262144") {
		t.Fatalf("message not handled correctly: %v", c.analyzer.handled)
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending", c.pending())
	}
	// the position ended exactly after the trailers: the next exchange must parse
	c.feed(enums.SocketDataDirectionEgress, http1Request("/api/stress", 1024), 6)
	c.feed(enums.SocketDataDirectionIngress, http1Response(1024), 6)
	c.analyze()
	if len(c.analyzer.handled) != 2 || c.pending() != 0 {
		t.Fatalf("the next message after a chunked body failed: %v pending=%d", c.analyzer.handled, c.pending())
	}
}

// chunked transfer encoding: parsed as the data arrives (size lines split across events), the body size
// is the chunk data and the events are released as they are consumed
func TestHTTP1ChunkedBodyStreamedRelease(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionEgress, http1Request("/api/stress", 1024), 6)
	chunks := []int{70000, 70000, 70000, 52144} // 262144 data bytes
	resp := http1ChunkedResponse(chunks)
	maxPending := 0
	for off, i := 0, 0; off < len(resp); off, i = off+16000, i+1 { // 16000: boundaries fall inside size lines
		end := off + 16000
		if end > len(resp) {
			end = len(resp)
		}
		c.feed(enums.SocketDataDirectionIngress, resp[off:end], 6)
		if i%3 == 2 {
			c.analyze()
			if c.pending() > maxPending {
				maxPending = c.pending()
			}
		}
	}
	c.analyze()
	t.Logf("handled: %v, max pending: %d, pending at the end: %d", c.analyzer.handled, maxPending, c.pending())
	if len(c.analyzer.handled) != 1 || !strings.HasSuffix(c.analyzer.handled[0], "resp=262144") {
		t.Fatalf("message not handled correctly: %v", c.analyzer.handled)
	}
	if maxPending > 2 || c.pending() != 0 {
		t.Fatalf("chunked body events were held: max %d, end %d", maxPending, c.pending())
	}
	// a second exchange on the same connection must still parse (the position ended exactly after the trailers)
	c.feed(enums.SocketDataDirectionEgress, http1Request("/api/stress", 1024), 6)
	c.feed(enums.SocketDataDirectionIngress, http1Response(1024), 6)
	c.analyze()
	if len(c.analyzer.handled) != 2 || c.pending() != 0 {
		t.Fatalf("the next message after a chunked body failed: %v pending=%d", c.analyzer.handled, c.pending())
	}
}

// a socket call whose chunk budget ran out while entries of the iov list were left: BPF uploads the
// chunks it could and flags the last one, total_size keeps the real length of the call. The analyzer
// must complete the message and report the real body size, not the uploaded bytes.
func TestHTTP1IovChunkBudgetExhausted(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionEgress, http1Request("/api/stress", 1024), 6)
	// 8 x 20480 bytes written with writev, only 6 chunks fit: 122880 of 163840 bytes are uploaded
	body := 163840 - len(http1Response(0))
	c.feed(enums.SocketDataDirectionIngress, http1Response(body), 6)
	c.analyze()
	t.Logf("handled: %v, pending: %d", c.analyzer.handled, c.pending())
	if len(c.analyzer.handled) != 1 {
		t.Fatalf("the truncated message was not handled: %v", c.analyzer.handled)
	}
	if !strings.HasSuffix(c.analyzer.handled[0], fmt.Sprintf("resp=%d", body)) {
		t.Fatalf("the body size must be the real Content-Length %d, got %s", body, c.analyzer.handled[0])
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending", c.pending())
	}
}
