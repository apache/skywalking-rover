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

// Every legal HPACK (RFC 7541) representation and every header related HTTP/2 framing (RFC 9113) the parser
// may meet, fed as hand made byte streams: the decoded request / response must come out as the peer sent it,
// and the HPACK decoders must stay in sync (no decode error, no framing error, no desync).

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	hpIn  = enums.SocketDataDirectionIngress
	hpOut = enums.SocketDataDirectionEgress
)

// ---- raw HPACK encoding (RFC 7541 5, 6) ----------------------------------------------------------------------

// hpInt encodes an integer with an n bit prefix behind the pattern bits of first
func hpInt(first byte, prefix uint, v uint64) []byte {
	limit := uint64(1)<<prefix - 1
	if v < limit {
		return []byte{first | byte(v)}
	}
	out := []byte{first | byte(limit)}
	v -= limit
	for v >= 128 {
		out = append(out, byte(v%128)|0x80)
		v /= 128
	}
	return append(out, byte(v))
}

// hpStr encodes a string literal, Huffman coded or raw
func hpStr(s string, huffman bool) []byte {
	if huffman {
		return hpack.AppendHuffmanString(hpInt(0x80, 7, hpack.HuffmanEncodeLength(s)), s)
	}
	return append(hpInt(0, 7, uint64(len(s))), s...)
}

// the literal representations: their pattern and prefix (RFC 7541 6.2)
type hpKind struct {
	pattern byte
	prefix  uint
}

var (
	hpIncremental = hpKind{0x40, 6}
	hpWithout     = hpKind{0x00, 4}
	hpNever       = hpKind{0x10, 4}
)

func hpIndexed(i uint64) []byte { return hpInt(0x80, 7, i) }

// hpLit is a literal field: with an indexed name when nameIndex is above 0, a new name otherwise
func hpLit(kind hpKind, nameIndex uint64, name, value string, huffman bool) []byte {
	var out []byte
	if nameIndex > 0 {
		out = hpInt(kind.pattern, kind.prefix, nameIndex)
	} else {
		out = append([]byte{kind.pattern}, hpStr(name, huffman)...)
	}
	return append(out, hpStr(value, huffman)...)
}

func hpSizeUpdate(v uint64) []byte { return hpInt(0x20, 5, v) }

func hpBlock(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// static table indexes used below (RFC 7541 Appendix A)
const (
	stAuthority = 1
	stGet       = 2
	stPost      = 3
	stPath      = 4
	stHTTP      = 6
	stStatus200 = 8
	stStatus    = 8 // name ":status"
	stAuthz     = 23
	stCType     = 31
	stHost      = 38
)

// ---- framing helpers -------------------------------------------------------------------------------------------

// writeBlock writes a header block as HEADERS plus CONTINUATION frames of at most frag bytes each (0: one frame)
func writeBlock(f *http2.Framer, stream uint32, endStream bool, block []byte, frag int, pad uint8, prio bool) {
	first := block
	if frag > 0 && len(first) > frag {
		first = block[:frag]
	}
	p := http2.HeadersFrameParam{StreamID: stream, BlockFragment: first, EndStream: endStream,
		EndHeaders: len(first) == len(block), PadLength: pad}
	if prio {
		p.Priority = http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 200}
	}
	if err := f.WriteHeaders(p); err != nil {
		panic(err)
	}
	for rest := block[len(first):]; len(rest) > 0; {
		n := len(rest)
		if frag > 0 && n > frag {
			n = frag
		}
		if err := f.WriteContinuation(stream, n == len(rest), rest[:n]); err != nil {
			panic(err)
		}
		rest = rest[n:]
	}
}

// feedSplit delivers the bytes as socket calls of random sizes (1..maxCall), each in random BPF chunks
func (c *http2TestConn) feedSplit(d enums.SocketDataDirection, data []byte, rnd *rand.Rand, maxCall int) {
	for len(data) > 0 {
		n := 1 + rnd.Intn(maxCall)
		if n > len(data) {
			n = len(data)
		}
		c.feed(d, data[:n], 1+rnd.Intn(n))
		data = data[n:]
	}
}

// feedLarge delivers the bytes as one socket call in chunks that fit an event buffer
func (c *http2TestConn) feedLarge(d enums.SocketDataDirection, data []byte) {
	c.feed(d, data, 16384)
}

// expectClean fails when the parser met an error, desynced, or left a stream or a header block open
func (c *http2TestConn) expectClean(t *testing.T) {
	t.Helper()
	m := c.metrics()
	if m.DecodeErrors != 0 || m.FramingErrors != 0 || m.headerDesync[hpIn] || m.headerDesync[hpOut] {
		t.Fatalf("parser not clean: decodeErr=%d framingErr=%d desync=%v/%v", m.DecodeErrors, m.FramingErrors,
			m.headerDesync[hpIn], m.headerDesync[hpOut])
	}
	if len(m.pendingHeaders) != 0 {
		t.Fatalf("header blocks left pending: %d", len(m.pendingHeaders))
	}
}

func (c *http2TestConn) expectStreams(t *testing.T, want ...string) {
	t.Helper()
	got := make([]string, 0, len(c.analyzer.streams))
	for _, s := range c.analyzer.streams {
		got = append(got, fmt.Sprintf("%s %s %d", s.req[":method"], s.req[":path"], s.status))
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("streams:\n got  %q\n want %q", got, want)
	}
}

func h2Start(c *http2TestConn, client, server *http2Peer, clientSettings, serverSettings []http2.Setting) {
	client.preface()
	client.settings(clientSettings...)
	c.feed(hpIn, client.take(), 0)
	server.settings(serverSettings...)
	_ = server.framer.WriteSettingsAck()
	c.feed(hpOut, server.take(), 0)
	_ = client.framer.WriteSettingsAck()
	c.feed(hpIn, client.take(), 0)
}

// ---- 1. HPACK representations ----------------------------------------------------------------------------------

// TestHPACKRepresentations: indexed fields, literals with incremental indexing (indexed / new name), without
// indexing and never indexed, Huffman and raw strings, and a :path taken from the dynamic table
func TestHPACKRepresentations(t *testing.T) {
	for _, huffman := range []bool{false, true} {
		t.Run(fmt.Sprintf("huffman=%v", huffman), func(t *testing.T) {
			c := newHTTP2TestConn(t)
			client, server := newHTTP2Peer(), newHTTP2Peer()
			h2Start(c, client, server, nil, nil)

			// stream 1 inserts (newest first after the block): sw8 [62], x-custom [63], :path [64]
			req1 := hpBlock(
				hpIndexed(stGet), hpIndexed(stHTTP),
				hpLit(hpIncremental, stPath, "", "/a/b?x=1&y=2", huffman),
				hpLit(hpWithout, stAuthority, "", "svc.local:8080", huffman),
				hpLit(hpIncremental, 0, "x-custom", "v1", huffman),
				hpLit(hpNever, stAuthz, "", "Bearer secret", huffman),
				hpLit(hpNever, 0, "cookie2", "c=1", huffman),
				hpLit(hpWithout, 0, "x-noidx", "nv", huffman),
				hpLit(hpIncremental, 0, "sw8", "1-abc-def", huffman),
			)
			writeBlock(client.framer, 1, true, req1, 0, 0, false)
			// stream 3: everything but :authority from the tables
			req2 := hpBlock(hpIndexed(stGet), hpIndexed(stHTTP), hpIndexed(64), hpIndexed(63), hpIndexed(62),
				hpLit(hpWithout, stAuthority, "", "svc.local:8080", huffman))
			writeBlock(client.framer, 3, true, req2, 0, 0, false)
			c.feed(hpIn, client.take(), 0)

			writeBlock(server.framer, 1, true, hpBlock(hpIndexed(stStatus200), hpLit(hpIncremental, stCType, "", "text/plain", huffman)), 0, 0, false)
			writeBlock(server.framer, 3, true, hpBlock(hpLit(hpIncremental, stStatus, "", "503", huffman), hpIndexed(63)), 0, 0, false)
			c.feed(hpOut, server.take(), 0)
			c.analyze()

			c.expectClean(t)
			c.expectStreams(t, "GET /a/b 200", "GET /a/b 503")
			for i, s := range c.analyzer.streams {
				if s.req[":authority"] != "svc.local:8080" || s.req["sw8"] != "1-abc-def" {
					t.Fatalf("stream %d request fields: %v", i, s.req)
				}
			}
			in := c.blocks[hpIn]
			if len(in) != 2 || in[0]["authorization"] != "Bearer secret" || in[0]["cookie2"] != "c=1" || in[0]["x-noidx"] != "nv" ||
				in[1]["x-custom"] != "v1" || in[1][":path"] != "/a/b?x=1&y=2" {
				t.Fatalf("request blocks: %v", in)
			}
			if out := c.blocks[hpOut]; len(out) != 2 || out[1]["content-type"] != "text/plain" {
				t.Fatalf("response blocks: %v", out)
			}
		})
	}
}

// ---- dynamic table size updates --------------------------------------------------------------------------------

func TestHPACKDynamicTableSizeUpdates(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)

	// stream 1: update at the block start (to 4096), inserts x-big (237 bytes) then :path /p ([62], 39 bytes)
	writeBlock(client.framer, 1, true, hpBlock(hpSizeUpdate(4096), hpIndexed(stGet), hpIndexed(stHTTP),
		hpLit(hpIncremental, 0, "x-big", strings.Repeat("z", 200), false), hpLit(hpIncremental, stPath, "", "/p", false)), 0, 0, false)
	// stream 3: shrink to 100 (x-big, 237 bytes, is evicted, :path /p is kept), then back to 4096: two updates
	// while the table still holds an entry (RFC 7541 4.2, the smallest then the final size)
	writeBlock(client.framer, 3, true, hpBlock(hpSizeUpdate(100), hpSizeUpdate(4096), hpIndexed(stGet), hpIndexed(stHTTP),
		hpIndexed(62)), 0, 0, false)
	// stream 5: update to 0 (evicts all), then to 4096, then a new entry
	writeBlock(client.framer, 5, true, hpBlock(hpSizeUpdate(0), hpSizeUpdate(4096), hpIndexed(stGet), hpIndexed(stHTTP),
		hpLit(hpIncremental, stPath, "", "/after-zero", true)), 0, 0, false)
	// stream 7: the entry of stream 5 is the only one
	writeBlock(client.framer, 7, true, hpBlock(hpIndexed(stGet), hpIndexed(stHTTP), hpIndexed(62)), 0, 0, false)
	c.feed(hpIn, client.take(), 0)
	for _, id := range []uint32{1, 3, 5, 7} {
		writeBlock(server.framer, id, true, hpBlock(hpIndexed(stStatus200)), 0, 0, false)
	}
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "GET /p 200", "GET /p 200", "GET /after-zero 200", "GET /after-zero 200")
}

// TestHPACKLeadingSizeUpdatesDecoder shows what http2ApplyLeadingSizeUpdates works around: hpack.Decoder alone
// refuses the second of two updates while the table holds an entry
func TestHPACKLeadingSizeUpdatesDecoder(t *testing.T) {
	prime := hpBlock(hpLit(hpIncremental, 0, "k", "v", false))
	two := hpBlock(hpSizeUpdate(100), hpSizeUpdate(4096), hpIndexed(62))

	plain := hpack.NewDecoder(4096, nil)
	if _, err := plain.DecodeFull(prime); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.DecodeFull(two); err == nil {
		t.Fatalf("hpack.Decoder accepted two leading updates with a non-empty table (the workaround may be dropped)")
	}

	var got []hpack.HeaderField
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) { got = append(got, f) })
	for _, b := range [][]byte{prime, two} {
		if err := http2DecodeHeaderBlock(dec, b); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	if len(got) != 2 || got[1].Name != "k" || got[1].Value != "v" {
		t.Fatalf("fields: %v", got)
	}
	// a single update and an update that is not at the start are left to the decoder as they are
	if b := hpBlock(hpSizeUpdate(10)); &http2ApplyLeadingSizeUpdates(dec, b)[0] != &b[0] {
		t.Fatalf("a single update must not be touched")
	}
	if err := http2DecodeHeaderBlock(dec, hpBlock(hpIndexed(stGet), hpSizeUpdate(10))); err == nil {
		t.Fatalf("an update behind a field must stay an error")
	}
}

// TestHPACKSmallTableEviction: the server announces a small SETTINGS_HEADER_TABLE_SIZE (and 0 in a second
// connection): the client encoder shrinks its table with an update and evicts constantly
func TestHPACKSmallTableEviction(t *testing.T) {
	for _, size := range []uint32{0, 64, 128, 300, 65536} {
		t.Run(fmt.Sprintf("table=%d", size), func(t *testing.T) {
			c := newHTTP2TestConn(t)
			client, server := newHTTP2Peer(), newHTTP2Peer()
			h2Start(c, client, server, nil, []http2.Setting{{ID: http2.SettingHeaderTableSize, Val: size}})
			client.enc.SetMaxDynamicTableSizeLimit(size)
			client.enc.SetMaxDynamicTableSize(size)
			rnd := rand.New(rand.NewSource(int64(size)))
			var want []string
			for i := 0; i < 60; i++ {
				id := uint32(2*i + 1)
				path := fmt.Sprintf("/svc/%d", rnd.Intn(7))
				client.headers(id, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", path), hf(":authority", "a"),
					hf("x-request-id", fmt.Sprintf("r-%d-%s", i, strings.Repeat("x", rnd.Intn(40)))))
				server.headers(id, true, hf(":status", "200"), hf("x-trace", fmt.Sprint(rnd.Intn(5))))
				want = append(want, "GET "+path+" 200")
			}
			c.feedSplit(hpIn, client.take(), rnd, 300)
			c.feedSplit(hpOut, server.take(), rnd, 300)
			c.analyze()
			c.expectClean(t)
			c.expectStreams(t, want...)
		})
	}
}

// ---- integers, large values, many headers ---------------------------------------------------------------------

func TestHPACKLargeIntegersValuesAndManyHeaders(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)

	// 100 entries of 37 bytes: the oldest has index 161, a two byte index after the 7 bit prefix
	var fill [][]byte
	fill = append(fill, hpIndexed(stGet), hpIndexed(stHTTP), hpLit(hpIncremental, stPath, "", "/first", false))
	for i := 0; i < 100; i++ {
		fill = append(fill, hpLit(hpIncremental, 0, fmt.Sprintf("h%03d", i), "v", false))
	}
	writeBlock(client.framer, 1, true, hpBlock(fill...), 0, 0, false)
	writeBlock(client.framer, 3, true, hpBlock(hpIndexed(stGet), hpIndexed(stHTTP), hpIndexed(162), hpIndexed(161), hpIndexed(62)), 0, 0, false)

	// a 70000 byte value (3 byte length continuation) in CONTINUATION frames of the default size, raw and Huffman
	big := strings.Repeat("0123456789abcdef", 70000/16)
	writeBlock(client.framer, 5, true, hpBlock(hpIndexed(stGet), hpIndexed(stHTTP), hpLit(hpWithout, stPath, "", "/big", false),
		hpLit(hpWithout, 0, "x-big", big, false), hpLit(hpWithout, 0, "x-big-h", big, true)), 16384, 0, false)

	// 2000 header fields in one block
	many := [][]byte{hpIndexed(stGet), hpIndexed(stHTTP), hpLit(hpWithout, stPath, "", "/many", true)}
	for i := 0; i < 2000; i++ {
		many = append(many, hpLit(hpWithout, 0, fmt.Sprintf("x-m-%d", i), fmt.Sprint(i), i%2 == 0))
	}
	writeBlock(client.framer, 7, true, hpBlock(many...), 16384, 0, false)
	// a field name of 200 bytes from a long literal and a value whose length is exactly the prefix limit (127)
	writeBlock(client.framer, 9, true, hpBlock(hpIndexed(stGet), hpIndexed(stHTTP), hpLit(hpWithout, stPath, "", "/"+strings.Repeat("p", 126), false),
		hpLit(hpIncremental, 0, strings.Repeat("n", 200), "v", false)), 0, 0, false)
	c.feedLarge(hpIn, client.take())
	for _, id := range []uint32{1, 3, 5, 7, 9} {
		writeBlock(server.framer, id, true, hpBlock(hpIndexed(stStatus200)), 0, 0, false)
	}
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "GET /first 200", "GET /first 200", "GET /big 200", "GET /many 200", "GET /"+strings.Repeat("p", 126)+" 200")
	in := c.blocks[hpIn]
	if in[1]["h000"] != "v" || in[1]["h099"] != "v" || in[2]["x-big"] != big || in[2]["x-big-h"] != big ||
		len(in[3]) != 2003 || in[3]["x-m-1999"] != "1999" {
		t.Fatalf("decoded blocks are wrong")
	}
}

// ---- 2. SETTINGS -----------------------------------------------------------------------------------------------

// TestHTTP2SettingsMaxFrameSize: frames above 16KB once the receiver announced a bigger SETTINGS_MAX_FRAME_SIZE:
// one HEADERS frame of 60KB and DATA frames of 200KB
func TestHTTP2SettingsMaxFrameSize(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, []http2.Setting{{ID: http2.SettingMaxFrameSize, Val: 1 << 20}},
		[]http2.Setting{{ID: http2.SettingMaxFrameSize, Val: 1 << 20}, {ID: http2.SettingHeaderTableSize, Val: 8192}})
	block := client.encode(hf(":method", "POST"), hf(":scheme", "http"), hf(":path", "/large"), hf(":authority", "a"),
		hf("x-pad", strings.Repeat("q", 60000)))
	writeBlock(client.framer, 1, false, block, 0, 0, false)
	client.data(1, true, bytes.Repeat([]byte("a"), 200000))
	c.feedLarge(hpIn, client.take())
	server.headers(1, false, hf(":status", "200"), hf("x-pad", strings.Repeat("r", 40000)))
	server.data(1, true, bytes.Repeat([]byte("b"), 300000))
	c.feedLarge(hpOut, server.take())
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "POST /large 200")
	if m := c.metrics(); m.maxFrameSize[hpIn] != 1<<20 || m.maxFrameSize[hpOut] != 1<<20 {
		t.Fatalf("max frame sizes: %v", m.maxFrameSize)
	}
	if s := c.analyzer.streams[0]; s.reqBody != 200000 || s.respBody != 300000 {
		t.Fatalf("bodies: %d %d", s.reqBody, s.respBody)
	}
}

// ---- 3. HEADERS flags and layout -------------------------------------------------------------------------------

// TestHTTP2HeaderBlockLayouts: PADDED and PRIORITY, an empty HEADERS fragment, CONTINUATION frames of one byte,
// END_STREAM on a HEADERS frame that continues, every frame in a socket call of its own, many frames in one call,
// and the whole exchange cut at random byte positions (calls and BPF chunks)
func TestHTTP2HeaderBlockLayouts(t *testing.T) {
	build := func() (in, out []byte, want []string) {
		client, server := newHTTP2Peer(), newHTTP2Peer()
		client.preface()
		client.settings()
		server.settings()
		_ = server.framer.WriteSettingsAck()
		for i := 0; i < 12; i++ {
			id := uint32(2*i + 1)
			path := fmt.Sprintf("/layout/%d?q=%d", i%3, i)
			block := client.encode(hf(":method", "GET"), hf(":scheme", "http"), hf(":path", path), hf(":authority", "svc"),
				hf("x-n", strings.Repeat("n", i*10)))
			switch i % 4 {
			case 0:
				writeBlock(client.framer, id, true, block, 0, 255, true)
			case 1:
				writeBlock(client.framer, id, true, block, 1, 0, false)
			case 2:
				// an empty first fragment, the block in the CONTINUATION frames
				_ = client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndStream: true, PadLength: 3})
				for rest := block; len(rest) > 0; {
					n := min(7, len(rest))
					_ = client.framer.WriteContinuation(id, n == len(rest), rest[:n])
					rest = rest[n:]
				}
			default:
				writeBlock(client.framer, id, true, block, 5, 1, true)
			}
			rblock := server.encode(hf(":status", "204"), hf("x-r", fmt.Sprint(i)))
			writeBlock(server.framer, id, true, rblock, 2*(i%3), uint8(i), i%2 == 0)
			want = append(want, fmt.Sprintf("GET /layout/%d 204", i%3))
		}
		return client.take(), server.take(), want
	}
	in, out, want := build()
	for seed := int64(0); seed < 40; seed++ {
		rnd := rand.New(rand.NewSource(seed))
		c := newHTTP2TestConn(t)
		maxCall := []int{1, 3, 9, 64, 4096}[seed%5]
		// the requests first, then the responses, both in random calls
		c.feedSplit(hpIn, in, rnd, maxCall)
		if seed%2 == 0 {
			c.analyze()
		}
		c.feedSplit(hpOut, out, rnd, maxCall)
		c.analyze()
		c.expectClean(t)
		c.expectStreams(t, want...)
	}
}

// ---- 4. trailers and informational responses -------------------------------------------------------------------

func TestHTTP2TrailersAndInformational(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)

	// 100-continue: request headers, 100, body, final response with trailers in CONTINUATION frames
	client.headers(1, false, hf(":method", "PUT"), hf(":scheme", "http"), hf(":path", "/upload"), hf(":authority", "a"), hf("expect", "100-continue"))
	c.feed(hpIn, client.take(), 0)
	server.headers(1, false, hf(":status", "100"))
	c.feed(hpOut, server.take(), 0)
	client.data(1, false, bytes.Repeat([]byte("u"), 500))
	// request trailers
	client.headers(1, true, hf("x-checksum", "abc"))
	c.feed(hpIn, client.take(), 0)
	server.headers(1, false, hf(":status", "201"), hf("content-type", "text/plain"))
	server.data(1, false, []byte("created"))
	writeBlock(server.framer, 1, true, server.encode(hf("grpc-status", "0"), hf("x-trailer", strings.Repeat("t", 100))), 10, 0, false)
	c.feed(hpOut, server.take(), 0)

	// 103 Early Hints twice, then a trailers-only response (HEADERS with END_STREAM)
	client.headers(3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/page"), hf(":authority", "a"))
	c.feed(hpIn, client.take(), 0)
	server.headers(3, false, hf(":status", "103"), hf("link", "</style.css>; rel=preload"))
	server.headers(3, false, hf(":status", "103"), hf("link", "</app.js>; rel=preload"))
	server.headers(3, true, hf(":status", "404"), hf("grpc-status", "5"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "PUT /upload 201", "GET /page 404")
	if s := c.analyzer.streams[0]; s.reqBody != 500 || s.respBody != 7 {
		t.Fatalf("bodies: %d %d", s.reqBody, s.respBody)
	}
	if n := len(c.blocks[hpOut]); n != 6 {
		t.Fatalf("response blocks: %d", n)
	}
}

// ---- 5. stream and frame variety -------------------------------------------------------------------------------

// TestHTTP2PushPromiseKeepsTableInSync: a PUSH_PROMISE header block (alone, PADDED, and in CONTINUATION frames)
// inserts entries into the dynamic table of the server direction that the following responses refer to
func TestHTTP2PushPromiseKeepsTableInSync(t *testing.T) {
	for _, variant := range []string{"plain", "padded", "continuation"} {
		t.Run(variant, func(t *testing.T) {
			c := newHTTP2TestConn(t)
			client, server := newHTTP2Peer(), newHTTP2Peer()
			h2Start(c, client, server, []http2.Setting{{ID: http2.SettingEnablePush, Val: 1}}, nil)
			client.headers(1, false, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/index.html"), hf(":authority", "a"))
			client.data(1, true, nil)
			c.feed(hpIn, client.take(), 0)

			promise := server.encode(hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/style.css"), hf(":authority", "a"),
				hf("x-push-tag", "pushed-"+variant))
			param := http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: promise, EndHeaders: true}
			if variant == "padded" {
				param.PadLength = 17
			}
			if variant == "continuation" {
				param.BlockFragment, param.EndHeaders = promise[:4], false
			}
			if err := server.framer.WritePushPromise(param); err != nil {
				t.Fatal(err)
			}
			if variant == "continuation" {
				_ = server.framer.WriteContinuation(1, false, promise[4:9])
				_ = server.framer.WriteContinuation(1, true, promise[9:])
			}
			// the responses reuse the entries of the promise (x-push-tag, :authority ...)
			server.headers(1, false, hf(":status", "200"), hf("x-push-tag", "pushed-"+variant))
			server.data(1, true, []byte("<html/>"))
			server.headers(2, false, hf(":status", "200"), hf("x-push-tag", "pushed-"+variant))
			server.data(2, true, []byte("body{}"))
			c.feed(hpOut, server.take(), 0)
			// a later request still decodes
			client.headers(3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/next"), hf(":authority", "a"))
			c.feed(hpIn, client.take(), 0)
			server.headers(3, true, hf(":status", "200"), hf("x-push-tag", "pushed-"+variant))
			c.feed(hpOut, server.take(), 0)
			c.analyze()
			c.expectClean(t)
			// the pushed stream has no request of its own and is not reported
			c.expectStreams(t, "GET /index.html 200", "GET /next 200")
			for _, b := range c.blocks[hpOut] {
				if b["x-push-tag"] != "pushed-"+variant {
					t.Fatalf("server blocks: %v", c.blocks[hpOut])
				}
			}
		})
	}
}

// TestHTTP2ResetDuringHeaderBlock: the server resets a stream while the client's header block of that stream is
// still in CONTINUATION frames: the block must still be decoded, later blocks refer to its entries
func TestHTTP2ResetDuringHeaderBlock(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)
	block := client.encode(hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/reset-me"), hf(":authority", "a"), hf("x-shared", "s1"))
	_ = client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:5], EndStream: true})
	c.feed(hpIn, client.take(), 0)
	_ = server.framer.WriteRSTStream(1, http2.ErrCodeRefusedStream)
	c.feed(hpOut, server.take(), 0)
	_ = client.framer.WriteContinuation(1, true, block[5:])
	c.feed(hpIn, client.take(), 0)
	// stream 3 refers to the entries stream 1 inserted
	client.headers(3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/reset-me"), hf(":authority", "a"), hf("x-shared", "s1"))
	c.feed(hpIn, client.take(), 0)
	server.headers(3, true, hf(":status", "200"))
	c.feed(hpOut, server.take(), 0)
	// the client cancels stream 5 after its whole block (the usual case)
	client.headers(5, false, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/cancel"), hf(":authority", "a"))
	_ = client.framer.WriteRSTStream(5, http2.ErrCodeCancel)
	client.headers(7, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/after"), hf(":authority", "a"), hf("x-shared", "s1"))
	c.feed(hpIn, client.take(), 0)
	server.headers(7, true, hf(":status", "200"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "GET /reset-me 200", "GET /after 200")
	if len(c.metrics().Streams) != 0 {
		t.Fatalf("streams left open: %d", len(c.metrics().Streams))
	}
}

// TestHTTP2ControlAndExtensionFrames: PING, WINDOW_UPDATE, PRIORITY, SETTINGS (ACK), GOAWAY and the extension
// frames real peers send (ALTSVC, ORIGIN, PRIORITY_UPDATE, GREASE types) in the calls that carry header blocks
func TestHTTP2ControlAndExtensionFrames(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.settings()
	_ = client.framer.WriteRawFrame(0x2a, 0, 0, []byte("grease"))
	_ = client.framer.WriteRawFrame(0x10, 0, 0, []byte{0, 0, 0, 1, 'u', '=', '1'})
	for i := 0; i < 5; i++ {
		id := uint32(2*i + 1)
		_ = client.framer.WritePing(false, [8]byte{byte(i)})
		_ = client.framer.WriteWindowUpdate(0, 65535)
		_ = client.framer.WritePriority(id, http2.PriorityParam{Weight: 10})
		_ = client.framer.WriteRawFrame(0x0b, 0, id, nil)
		client.headers(id, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":path", "/ctl"), hf(":authority", "a"))
		_ = client.framer.WriteRawFrame(0x10, 0, 0, []byte{0, 0, 0, byte(id), 'u', '=', '0'})
		_ = client.framer.WriteDataPadded(id, true, []byte("body"), make([]byte, 20))
	}
	c.feed(hpIn, client.take(), 0)
	server.settings()
	_ = server.framer.WriteSettingsAck()
	_ = server.framer.WriteRawFrame(0x0a, 0, 0, append([]byte{0, 4}, []byte("a.ioh2=\":443\"")...))
	_ = server.framer.WriteRawFrame(0x0c, 0, 0, append([]byte{0, 13}, []byte("http://a.test")...))
	for i := 0; i < 5; i++ {
		id := uint32(2*i + 1)
		_ = server.framer.WritePing(true, [8]byte{byte(i)})
		_ = server.framer.WriteWindowUpdate(id, 100)
		server.headers(id, false, hf(":status", "200"))
		_ = server.framer.WriteRawFrame(0xe4, 0xff, id, []byte{1, 2, 3})
		server.data(id, true, []byte("ok"))
	}
	_ = server.framer.WriteGoAway(9, http2.ErrCodeNo, []byte("bye"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "POST /ctl 200", "POST /ctl 200", "POST /ctl 200", "POST /ctl 200", "POST /ctl 200")
	if s := c.analyzer.streams[0]; s.reqBody != 4 || s.respBody != 2 {
		t.Fatalf("bodies: %d %d", s.reqBody, s.respBody)
	}
}

// TestHTTP2UnknownFrameTypeLimitation documents what is left: a frame type that is neither defined nor a known
// extension is taken as lost framing (the rest of its socket call is dropped), never as a frame to step over
func TestHTTP2UnknownFrameTypeLimitation(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)
	_ = client.framer.WriteRawFrame(0xfe, 0, 0, []byte{1})
	c.feed(hpIn, client.take(), 0)
	client.headers(1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/x"), hf(":authority", "a"))
	c.feed(hpIn, client.take(), 0)
	server.headers(1, true, hf(":status", "200"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	if m := c.metrics(); m.FramingErrors != 1 {
		t.Fatalf("framing errors: %d", m.FramingErrors)
	}
	t.Logf("unknown type 0xfe: framing errors=%d, header desync=%v, streams=%d", c.metrics().FramingErrors,
		c.metrics().headerDesync[hpIn], len(c.analyzer.streams))
}

// ---- 7. pseudo headers and what is extracted -------------------------------------------------------------------

func TestHTTP2PseudoHeaderVariants(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)
	reqs := [][]hpack.HeaderField{
		{hf(":method", "CONNECT"), hf(":authority", "proxy.test:443")},
		{hf(":method", "CONNECT"), hf(":protocol", "websocket"), hf(":scheme", "http"), hf(":path", "/chat?room=1"), hf(":authority", "ws")},
		{hf(":method", "OPTIONS"), hf(":scheme", "http"), hf(":path", "*"), hf(":authority", "a")},
		{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/q?a=1?b=2"), hf("host", "legacy.test")},
		{hf(":method", "DELETE"), hf(":scheme", "http"), hf(":path", "/d"), hf(":authority", "auth.test"), hf("host", "ignored.test")},
		{hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/"), hf(":authority", "a"),
			hpack.HeaderField{Name: "authorization", Value: "secret", Sensitive: true}},
	}
	for i, r := range reqs {
		client.headers(uint32(2*i+1), true, r...)
		server.headers(uint32(2*i+1), true, hf(":status", fmt.Sprint(200+i)))
	}
	c.feed(hpIn, client.take(), 0)
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	c.expectStreams(t, "CONNECT  200", "CONNECT /chat 201", "OPTIONS * 202", "GET /q 203", "DELETE /d 204", "GET / 205")
	host := func(i int) string {
		s := c.analyzer.streams[i]
		if v := s.req[":authority"]; v != "" {
			return v
		}
		return s.req[":host"]
	}
	if host(0) != "proxy.test:443" || host(3) != "legacy.test" || host(4) != "auth.test" {
		t.Fatalf("hosts: %q %q %q", host(0), host(3), host(4))
	}
}

// TestHTTP2HeaderSizeIsWireSize: the header size reported is the bytes of the HEADERS and CONTINUATION frames,
// frame headers, padding and priority included
func TestHTTP2HeaderSizeIsWireSize(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	h2Start(c, client, server, nil, nil)
	block := client.encode(hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/size"), hf(":authority", "a"), hf("x", strings.Repeat("v", 50)))
	writeBlock(client.framer, 1, true, block, 20, 9, true)
	frames := client.take()
	c.feed(hpIn, frames, 0)
	server.headers(1, true, hf(":status", "200"))
	c.feed(hpOut, server.take(), 0)
	c.analyze()
	c.expectClean(t)
	if s := c.analyzer.streams[0]; s.reqHeaderBytes != int64(len(frames)) {
		t.Fatalf("header bytes %d, frames %d", s.reqHeaderBytes, len(frames))
	}
}
