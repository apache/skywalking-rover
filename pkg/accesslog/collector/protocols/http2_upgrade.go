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

// HTTP/2 over cleartext started by an HTTP/1.1 Upgrade (RFC 7540 3.2).
//
// The client sends an HTTP/1.1 request with "Upgrade: h2c" and "HTTP2-Settings"; the server answers
// "HTTP/1.1 101 Switching Protocols" and continues with its connection preface (SETTINGS) and the response to
// that request as stream 1; the client sends its connection preface after the 101. The request of stream 1 is
// never sent as HTTP/2: it is the HTTP/1.1 request.
//
// What BPF must emit (protocol of the data events):
//   - every call up to and including the upgrade request (and its body): CONNECTION_PROTOCOL_HTTP1, as today;
//   - the call that carries the "HTTP/1.1 101" response head of an "Upgrade: h2c" exchange, uploaded whole (the
//     head and whatever frames the server wrote behind it in the same call), and every later call of both
//     directions: CONNECTION_PROTOCOL_HTTP2.
//
// The previous data id of the 101 call names an HTTP/1 call the HTTP/2 analysis never sees: the 101 call starts
// the chain of the uploads of the HTTP/2 analysis (http2LinkPrevDataID), whatever previous data id it carries.
//
// The user space then hands the request over: the HTTP/1 analysis (it runs first, its data ids are smaller) keeps
// the upgrade request waiting for its response; the HTTP/2 parser meets the 101 head where the first frame of the
// server direction is expected (parseUpgradeResponse), takes the request from the HTTP/1 metrics of the connection
// (HTTP1Metrics.TakeUpgradeRequest), opens stream 1 with it and applies its HTTP2-Settings. The client preface that
// follows in the other direction is parsed as usual.

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// http2UpgradeResponsePrefix starts the 101 head; it is exactly as long as a frame header
	http2UpgradeResponsePrefix = "HTTP/1.1 "
	// http2MaxUpgradeHead bounds the 101 head
	http2MaxUpgradeHead = 8192
	// http2UpgradeStream is the stream the upgraded request becomes (RFC 7540 3.2)
	http2UpgradeStream = 1
)

// http2LinkPrevDataID is the previous data id an arrived event counts with in the chain of the uploads: the first
// event of the analysis that is the 101 response of an h2c upgrade starts the chain (its previous upload is an
// HTTP/1 call, analyzed by the HTTP/1 parser)
func http2LinkPrevDataID(links *http2Links, event buffer.SocketDataBuffer) uint64 {
	if !links.started && event.DataSequence() == 0 && http2IsUpgradeResponseStart(event.BufferData()) {
		return 0
	}
	return event.PrevDataID()
}

func http2IsUpgradeResponseStart(data []byte) bool {
	return bytes.HasPrefix(data, []byte("HTTP/1.1 101"))
}

// parseUpgradeResponse consumes the 101 head of an h2c upgrade where the first frame of a direction is expected,
// and opens stream 1 with the HTTP/1.1 request it answers
func (r *HTTP2Protocol) parseUpgradeResponse(connection *PartitionConnection, m *HTTP2Metrics, d enums.SocketDataDirection,
	db *buffer.Buffer, startPos *buffer.Position) http2FrameResult {
	head, result := http2PeekHead(db)
	if result != http2FrameConsumed {
		return result
	}
	if !http2IsH2CUpgradeHead(head) {
		// a 101 to another protocol (or no 101 at all): the bytes are not HTTP/2
		return http2FrameSkipElement
	}
	var request *reader.Request
	if connection != nil {
		if http1, ok := connection.Metrics(enums.ConnectionProtocolHTTP).(*HTTP1Metrics); ok && http1 != nil {
			request = http1.TakeUpgradeRequest("h2c")
		}
	}
	if request == nil && m.waitedFor(startPos.StartTime()) < http2GapWaitDuration {
		// the HTTP/1 analysis has not read the request yet (its event is late): wait for it
		return http2FrameWait
	}
	if err := db.ReadUntilBufferFull(make([]byte, len(head))); err != nil {
		return http2ErrorResult(db, err)
	}
	client := http2OppositeDirection(d)
	m.requestDirection = client
	if request == nil {
		http2Log.Debugf("HTTP/2 upgrade without its HTTP/1.1 request, connection ID: %d", m.ConnectionID)
		return http2FrameConsumed
	}
	// the client's SETTINGS travel in the request (base64url, RFC 7540 3.2.1)
	if settings := http1RequestHeader(request, "HTTP2-Settings"); settings != "" {
		if payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(settings, "=")); err == nil {
			r.handleSettings(m, client, &http2.FrameHeader{Type: http2.FrameSettings}, payload)
		}
	}
	streaming := &HTTP2Streaming{Connection: connection, age: http2Aged{created: time.Now()}}
	http2UpgradeRequestHeaders(&streaming.ReqHeader, request)
	streaming.ReqHeaderBuffer = request.HeaderBuffer()
	streaming.ReqBodyBuffer = request.BodyBuffer()
	// the 101 head is the first part of the response headers, like an HTTP/2 1xx block
	streaming.RespHeaderBuffer = db.Slice(true, startPos, db.Position())
	m.addStream(http2UpgradeStream, streaming)
	return http2FrameConsumed
}

// http2UpgradeRequestHeaders fills the kept fields of stream 1 from the HTTP/1.1 request, as the pseudo headers of an
// HTTP/2 request would (the path without its query, like handleHeaderBlock)
func http2UpgradeRequestHeaders(headers *HTTP2Headers, request *reader.Request) {
	original := request.Original()
	if original == nil {
		return
	}
	headers.emit(hpack.HeaderField{Name: http2FieldMethod, Value: original.Method})
	if path, ok := http2UpgradePath(original); ok {
		headers.emit(hpack.HeaderField{Name: http2FieldPath, Value: path})
	}
	authority := request.Headers().Get("Host")
	if authority == "" {
		authority = original.Host
	}
	if authority != "" {
		headers.emit(hpack.HeaderField{Name: http2FieldAuthority, Value: authority})
	}
	for _, name := range []string{tracing.HeaderSW8, tracing.HeaderB3, tracing.HeaderB3TraceID, tracing.HeaderB3SpanID} {
		if value := request.Headers().Get(name); value != "" {
			headers.emit(hpack.HeaderField{Name: name, Value: value})
		}
	}
}

// http2UpgradePath is the path of stream 1 as the :path of the other streams of the connection is reported: the
// request target as it was sent (not decoded), without its query
func http2UpgradePath(original *http.Request) (string, bool) {
	target := original.RequestURI
	if target == "" {
		if original.URL == nil {
			return "", false
		}
		return original.URL.EscapedPath(), true
	}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}
	return target, true
}

// http2PeekHead peeks an HTTP/1 head up to its empty line without consuming it
func http2PeekHead(db *buffer.Buffer) ([]byte, http2FrameResult) {
	buf := make([]byte, http2MaxUpgradeHead)
	got, size, step := 0, 64, 64
	for {
		size = min(size, http2MaxUpgradeHead)
		n, err := db.Peek(buf[:size])
		if err != nil {
			if size == got+1 {
				// the bytes end at got: the rest of the head has not arrived (or never will)
				return nil, http2ErrorResult(db, err)
			}
			// fewer bytes than asked for: narrow down to where they end
			step, size = 1, got+1
			continue
		}
		got = n
		if i := bytes.Index(buf[:n], []byte("\r\n\r\n")); i >= 0 {
			return buf[:i+4], http2FrameConsumed
		}
		if n >= http2MaxUpgradeHead {
			return nil, http2FrameSkipElement
		}
		size = n + step
	}
}

// http2IsH2CUpgradeHead tells whether a response head is a 101 that switches to h2c
func http2IsH2CUpgradeHead(head []byte) bool {
	lines := strings.Split(string(head), "\r\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "HTTP/1.1 101") {
		return false
	}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name)) == "Upgrade" && http2HasToken(value, "h2c") {
			return true
		}
	}
	return false
}

// http2HasToken tells whether a comma separated header value holds the token (case-insensitive)
func http2HasToken(value, token string) bool {
	for _, t := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(t), token) {
			return true
		}
	}
	return false
}

// TakeUpgradeRequest removes and returns the oldest request waiting for its response that asks to upgrade the
// connection to the protocol (a token of its Upgrade header), nil when there is none. The HTTP/2 parser takes the
// request of an h2c upgrade this way: its response continues as HTTP/2 (stream 1), the HTTP/1 analysis never sees it.
func (m *HTTP1Metrics) TakeUpgradeRequest(protocol string) *reader.Request {
	for element := m.halfRequests.Front(); element != nil; element = element.Next() {
		request := element.Value.(*reader.Request)
		if http2HasToken(http1RequestHeader(request, "Upgrade"), protocol) {
			m.halfRequests.Remove(element)
			return request
		}
	}
	return nil
}

// http1RequestHeader is the value of a header of an HTTP/1 request. The head reader keeps Upgrade and HTTP2-Settings
// (reader.fastHeaderNames): the bytes of the head may be released by the time the HTTP/2 parser meets the 101. A head
// the reader parsed otherwise (textproto keeps every header) has them as well; the bytes of the head are only read
// when the header is not there, while they are still held.
func http1RequestHeader(request *reader.Request, name string) string {
	if value := request.Headers().Get(name); value != "" {
		return value
	}
	var head []byte
	for _, event := range buffer.CombinedSocketBuffers(request.HeaderBuffer()) {
		data := event.BufferData()
		head = append(head, data[:min(event.BufferLen(), len(data))]...)
		if bytes.Contains(head, []byte("\r\n\r\n")) || len(head) > http2MaxUpgradeHead {
			break
		}
	}
	if end := bytes.Index(head, []byte("\r\n\r\n")); end >= 0 {
		head = head[:end]
	}
	lines := strings.Split(string(head), "\r\n")
	for _, line := range lines[min(1, len(lines)):] {
		if key, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
