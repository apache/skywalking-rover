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
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ---- the map based header handling the parser used before HTTP2Headers, kept as the reference -------

func http2RefParseHeaders(fields []hpack.HeaderField) map[string]string {
	result := make(map[string]string)
	for _, f := range fields {
		result[f.Name] = f.Value
	}
	return result
}

func http2RefValidPseudoHeaders(headers map[string]string) bool {
	h := &HTTP2Headers{}
	for k, v := range headers {
		h.emit(hf(k, v))
	}
	return http2ValidPseudoHeaders(h)
}

type http2RefStream struct {
	req, resp      map[string]string
	status         int
	reqHeaderSize  int64
	respHeaderSize int64
}

// http2RefSide decodes the header blocks of one direction with DecodeFull, as handleHeaderBlock did
type http2RefSide struct {
	dec *hpack.Decoder
}

func newHTTP2RefSide() *http2RefSide {
	dec := hpack.NewDecoder(http2DefaultHeaderTableSize, nil)
	dec.SetAllowedMaxDynamicTableSize(http2MaxAllowedHeaderTableSize)
	return &http2RefSide{dec: dec}
}

func (s *http2RefSide) apply(t *testing.T, stream *http2RefStream, request bool, block []byte) {
	fields, err := s.dec.DecodeFull(block)
	if err != nil {
		t.Fatalf("reference decode: %v", err)
	}
	headers := http2RefParseHeaders(fields)
	if !http2RefValidPseudoHeaders(headers) {
		t.Fatalf("reference headers are invalid: %v", headers)
	}
	if path, ok := headers[":path"]; ok && request {
		if i := strings.IndexByte(path, '?'); i >= 0 {
			headers[":path"] = path[:i]
		}
	}
	target := stream.resp
	if request {
		target = stream.req
	} else if status, ok := headers[":status"]; ok {
		code, err := strconv.ParseInt(status, 10, 64)
		if err != nil {
			code = 200
		}
		stream.status = int(code)
	}
	for k, v := range headers {
		target[k] = v
	}
}

// http2RefKept is the part of a reference header map HTTP2Headers keeps
func http2RefKept(headers map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range headers {
		if _, ok := http2HeaderKeyOf(k); ok {
			out[k] = v
		}
	}
	return out
}

// ---- the recording of what the analyzers read ----------------------------------------------------------

type http2FieldsStream struct {
	req, resp            HTTP2Headers
	status               int
	reqHeaderBytes       int64
	respHeaderBytes      int64
	reqBody, respBodyLen int64
}

type http2FieldsAnalyzer struct {
	streams map[string]http2FieldsStream // by the reported :path
}

func (a *http2FieldsAnalyzer) HandleWholeStream(_ *PartitionConnection, s *HTTP2Streaming) error {
	a.streams[s.ReqHeader.Get(":path")] = http2FieldsStream{
		req: s.ReqHeader, resp: s.RespHeader, status: s.Status,
		reqHeaderBytes: s.ReqHeaderBuffer.DataSize(), respHeaderBytes: s.RespHeaderBuffer.DataSize(),
		reqBody: s.ReqBodyBuffer.DataSize(), respBodyLen: s.RespBodyBuffer.DataSize(),
	}
	return nil
}

func (a *http2FieldsAnalyzer) OnProtocolBreak(*PartitionConnection, *HTTP2Metrics) {}

// writeSplitBlock writes a header block as a HEADERS frame followed by a CONTINUATION frame per cut, and
// returns the bytes of all the frames
func writeSplitBlock(p *http2Peer, stream uint32, endStream bool, block []byte, cuts ...int) int64 {
	pieces := make([][]byte, 0, len(cuts)+1)
	prev := 0
	for _, c := range cuts {
		if c <= prev || c >= len(block) {
			continue
		}
		pieces = append(pieces, block[prev:c])
		prev = c
	}
	pieces = append(pieces, block[prev:])
	if err := p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: pieces[0],
		EndStream: endStream, EndHeaders: len(pieces) == 1}); err != nil {
		panic(err)
	}
	for i := 1; i < len(pieces); i++ {
		if err := p.framer.WriteContinuation(stream, i == len(pieces)-1, pieces[i]); err != nil {
			panic(err)
		}
	}
	return int64(len(block) + http2FrameHeaderLen*len(pieces))
}

// TestHTTP2HeadersMatchMapPath feeds header blocks split over HEADERS and CONTINUATION frames, with
// dynamic table references (indexed fields, literals with incremental indexing, never indexed literals)
// and dynamic table size updates, over several interleaved streams with trailers, and checks that what
// the analyzers read (HTTP2Headers, without keeping every field) is what the old map path produced.
func TestHTTP2HeadersMatchMapPath(t *testing.T) {
	analyzer := &http2FieldsAnalyzer{streams: make(map[string]http2FieldsStream)}
	proto := NewHTTP2Analyzer(nil, analyzer)
	c := newHTTP2TestConn(t)
	c.proto = proto
	c.conn.protocolAnalyzer[enums.ConnectionProtocolHTTP2] = proto
	c.conn.protocolMetrics[enums.ConnectionProtocolHTTP2] = proto.GenerateConnection(1, 1)

	client, server := newHTTP2Peer(), newHTTP2Peer()
	reqSide, respSide := newHTTP2RefSide(), newHTTP2RefSide()
	expected := make(map[string]*http2RefStream)

	client.preface()
	client.settings()
	server.settings()
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	sensitive := func(name, value string) hpack.HeaderField {
		return hpack.HeaderField{Name: name, Value: value, Sensitive: true}
	}
	type exchange struct {
		id          uint32
		path        string // the reported path (the key of the stream)
		req         []hpack.HeaderField
		reqTrailers []hpack.HeaderField
		resp        []hpack.HeaderField
		respTrail   []hpack.HeaderField
		reqBody     int
	}
	exchanges := []exchange{
		{id: 1, path: "/pkg.Svc/A", reqBody: 5,
			req: []hpack.HeaderField{hf(":method", "POST"), hf(":scheme", "http"), hf(":path", "/pkg.Svc/A?x=1&y=2"),
				hf(":authority", "svc-a:8080"), hf("content-type", "application/grpc"), hf("te", "trailers"),
				hf("sw8", "1-dHJhY2U=-c2Vn-3-c2Vydmlj-aW5zdA==-L2E=-YWRkcg=="), hf("x-request-id", "r-1")},
			resp:      []hpack.HeaderField{hf(":status", "200"), hf("content-type", "application/grpc")},
			respTrail: []hpack.HeaderField{hf("grpc-status", "0"), hf("grpc-message", "")}},
		// repeated fields: indexed from the dynamic table; the second block of each side starts with a
		// dynamic table size update (set below), which evicts entries
		{id: 3, path: "/pkg.Svc/B", reqBody: 0,
			req: []hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/pkg.Svc/B"),
				hf(":authority", "svc-a:8080"), hf("b3", "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1"),
				hf("b3", "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1-05e3ac9a4f6e3b90"),
				sensitive("authorization", "Bearer secret"), hf("x-b3-spanid", "0000000000000001"), hf("x-request-id", "r-3")},
			// the trailers replace a kept field of the request block
			reqTrailers: []hpack.HeaderField{hf("x-b3-spanid", "e457b5a2e4d86bd1"), hf("x-checksum", "abc")},
			resp:        []hpack.HeaderField{hf(":status", "404"), hf("content-type", "text/plain"), hf("content-length", "0")}},
		{id: 5, path: "/c", reqBody: 33,
			req: []hpack.HeaderField{hf(":method", "PUT"), hf(":scheme", "http"), hf(":path", "/c?q"),
				hf(":authority", "svc-c"), hf("x-b3-traceid", "463ac35c9f6413ad48485a3953bb6124"),
				hf("x-b3-spanid", "a2fb4a1d1a96d312"), hf("x-request-id", "r-5"), hf("x-request-id", "r-5b")},
			resp: []hpack.HeaderField{hf(":status", "201"), hf("location", "/c/1"), hf("content-type", "text/plain")}},
		{id: 7, path: "/pkg.Svc/D", reqBody: 1,
			req: []hpack.HeaderField{hf(":method", "POST"), hf(":scheme", "http"), hf(":path", "/pkg.Svc/D?trace=1"),
				hf(":authority", "svc-a:8080"), hf("content-type", "application/grpc"), hf("te", "trailers"),
				hf("sw8", "1-dHJhY2U=-c2Vn-4-c2Vydmlj-aW5zdA==-L2E=-YWRkcg=="), hf("x-request-id", "r-7")},
			resp:      []hpack.HeaderField{hf(":status", "200"), hf("content-type", "application/grpc")},
			respTrail: []hpack.HeaderField{hf("grpc-status", "14"), hf("grpc-message", "unavailable")}},
		{id: 9, path: "/host-only", reqBody: 0,
			req: []hpack.HeaderField{hf(":method", "DELETE"), hf(":scheme", "http"), hf(":path", "/host-only"),
				hf(":host", "legacy-host"), hf("x-request-id", "r-9")},
			resp: []hpack.HeaderField{hf(":status", "204")}},
	}
	run := func(batch []exchange) {
		for _, e := range batch {
			switch e.id {
			case 3:
				// a dynamic table size update starts the next block of each side, evicting entries
				client.enc.SetMaxDynamicTableSize(256)
				server.enc.SetMaxDynamicTableSize(256)
			case 9:
				client.enc.SetMaxDynamicTableSize(4096)
				server.enc.SetMaxDynamicTableSize(4096)
			}
			exp := &http2RefStream{req: map[string]string{}, resp: map[string]string{}}
			expected[e.path] = exp

			block := client.encode(e.req...)
			reqSide.apply(t, exp, true, block)
			endStream := e.reqBody == 0 && e.reqTrailers == nil
			exp.reqHeaderSize += writeSplitBlock(client, e.id, endStream, block, len(block)/3, 2*len(block)/3)
			if e.reqBody > 0 {
				client.data(e.id, e.reqTrailers == nil, bytes.Repeat([]byte("q"), e.reqBody))
			}
			if e.reqTrailers != nil {
				tblock := client.encode(e.reqTrailers...)
				reqSide.apply(t, exp, true, tblock)
				exp.reqHeaderSize += writeSplitBlock(client, e.id, true, tblock, 2)
			}
		}
		// every request first, then the responses in reverse order: the streams interleave
		c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
		for i := len(batch) - 1; i >= 0; i-- {
			e := batch[i]
			exp := expected[e.path]
			block := server.encode(e.resp...)
			respSide.apply(t, exp, false, block)
			exp.respHeaderSize += writeSplitBlock(server, e.id, e.respTrail == nil, block, 1)
			if e.respTrail != nil {
				server.data(e.id, false, []byte("payload"))
				tblock := server.encode(e.respTrail...)
				respSide.apply(t, exp, false, tblock)
				exp.respHeaderSize += writeSplitBlock(server, e.id, true, tblock, len(tblock)/2)
			}
		}
		c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
		c.analyze()

		for _, e := range batch {
			exp, got := expected[e.path], analyzer.streams[e.path]
			if want, kept := http2RefKept(exp.req), http2KeptHeaders(&got.req); !reflect.DeepEqual(want, kept) {
				t.Fatalf("stream %d request: got %v, the map path gives %v", e.id, kept, want)
			}
			if want, kept := http2RefKept(exp.resp), http2KeptHeaders(&got.resp); !reflect.DeepEqual(want, kept) {
				t.Fatalf("stream %d response: got %v, the map path gives %v", e.id, kept, want)
			}
			if got.req.Empty() != (len(exp.req) == 0) || got.resp.Empty() != (len(exp.resp) == 0) {
				t.Fatalf("stream %d: emptiness differs", e.id)
			}
			if got.req.Get("x-request-id") != "" {
				t.Fatalf("stream %d: a field no analyzer reads must not be kept", e.id)
			}
			if got.status != exp.status || got.reqHeaderBytes != exp.reqHeaderSize || got.respHeaderBytes != exp.respHeaderSize ||
				got.reqBody != int64(e.reqBody) {
				t.Fatalf("stream %d: got status %d header bytes %d/%d body %d, expected %d %d/%d %d", e.id, got.status,
					got.reqHeaderBytes, got.respHeaderBytes, got.reqBody, exp.status, exp.reqHeaderSize, exp.respHeaderSize, e.reqBody)
			}
		}
	}
	run(exchanges[:4])
	run(exchanges[4:])

	m := c.metrics()
	if m.DecodeErrors != 0 || m.FramingErrors != 0 || len(m.Streams) != 0 || len(analyzer.streams) != len(exchanges) {
		t.Fatalf("decodeErr=%d framingErr=%d open=%d reported=%d", m.DecodeErrors, m.FramingErrors, len(m.Streams), len(analyzer.streams))
	}
}

// TestHTTP2DecodeHeaderBlockLikeDecodeFull: decoding through the emit function leaves the decoder in the
// state DecodeFull leaves it in, also for a block that fails (a truncated block, an invalid index)
func TestHTTP2DecodeHeaderBlockLikeDecodeFull(t *testing.T) {
	p := newHTTP2Peer()
	good1 := p.encode(requestFields("/one")...)
	p.enc.SetMaxDynamicTableSize(100)
	good2 := p.encode(requestFields("/two")...)
	good3 := p.encode(requestFields("/two")...)
	blocks := [][]byte{good1, good2[:len(good2)-1], {0xbf, 0x7f}, good3}

	ref := newHTTP2RefSide().dec
	dec := hpack.NewDecoder(http2DefaultHeaderTableSize, nil)
	dec.SetAllowedMaxDynamicTableSize(http2MaxAllowedHeaderTableSize)
	h := &HTTP2Headers{}
	var all map[string]string
	dec.SetEmitFunc(func(f hpack.HeaderField) {
		h.emit(f)
		all[f.Name] = f.Value
	})
	for i, block := range blocks {
		fields, refErr := ref.DecodeFull(block)
		h.reset()
		all = make(map[string]string)
		err := http2DecodeHeaderBlock(dec, block)
		if (err == nil) != (refErr == nil) {
			t.Fatalf("block %d: error %v, DecodeFull error %v", i, err, refErr)
		}
		if err != nil {
			continue
		}
		want := http2RefParseHeaders(fields)
		if !reflect.DeepEqual(want, all) || !reflect.DeepEqual(http2RefKept(want), http2KeptHeaders(h)) {
			t.Fatalf("block %d: got %v (kept %v), DecodeFull gives %v", i, all, h, want)
		}
	}
}

// TestHTTP2HeadersKeepTracingHeaders: every header AnalyzeTracingContext reads is kept
func TestHTTP2HeadersKeepTracingHeaders(t *testing.T) {
	read := make(map[string]bool)
	for _, sw8 := range []string{"", "x"} {
		_, _ = tracing.AnalyzeTracingContext(func(key string) string {
			read[key] = true
			if key == tracing.HeaderSW8 {
				return sw8
			}
			// an unparsable b3 and a trace id lead on to every other header
			return "x"
		})
	}
	if len(read) != 4 {
		t.Fatalf("unexpected headers read: %v", read)
	}
	for name := range read {
		h := &HTTP2Headers{}
		h.emit(hf(name, "v"))
		if h.Get(name) != "v" {
			t.Fatalf("header %s is not kept", name)
		}
	}
}
