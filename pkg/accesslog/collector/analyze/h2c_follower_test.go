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

package analyze

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The follower of the frames on the BPF side (skip_h2c_data_payload) uploads a call that lies wholly inside the
// payload of a DATA frame without the PADDED flag without its content. These tests pin down what the parser makes
// of hand cut calls around such payloads: the body sizes it reports, why a padded payload is never skipped, how
// it resynchronizes past skipped calls it cannot place, and a padded frame cut by the upload limit. The kernel
// side of the same follower is in h2c_follower_kernel_test.go.

// h2cUploadChunkLimit is SOCKET_UPLOAD_CHUNK_LIMIT of bpf/include/socket_data.h, the chunks of one call; a chunk
// is buffer.MaxEventBufferSize bytes (SOCKET_UPLOAD_CHUNK_SIZE)
const h2cUploadChunkLimit = 6

// uploadsWith builds the events BPF sends for the script as upload_socket_data_buf does: a call in chunks with
// their sequence, each flagged with whether data is left behind it, the last one (or the one at the chunk limit)
// finished, nothing past the limit; every chunk carries the fields of its call. With drop, the dropped calls are
// not uploaded; a call skip tells is one event without content (payload_skipped), which still becomes the
// previous data id of the next upload.
func (s *h2cScript) uploadsWith(base uint64, drop bool, skip func(call int) bool) (result []h2cEvent, skipped int) {
	var lastUploaded uint64
	for i, c := range s.calls {
		dataID := uint64(c.id + 1)
		if drop && c.dropped {
			continue
		}
		template := h2cDataEvent(c, dataID, lastUploaded, base)
		lastUploaded = dataID
		if skip != nil && skip(i) {
			template.DataLen, template.Buffer, template.PayloadSkipped0 = 0, nil, 1
			result = append(result, h2cEvent{call: i, event: template})
			skipped++
			continue
		}
		for sent, index := 0, 0; sent < len(c.data) && index < h2cUploadChunkLimit; index++ {
			size := min(len(c.data)-sent, buffer.MaxEventBufferSize)
			chunk := *template
			chunk.Sequence0, chunk.DataLen, chunk.HaveReduce, chunk.Finished = uint16(index), uint16(size), 0, 0
			if len(c.data)-sent > buffer.MaxEventBufferSize {
				chunk.HaveReduce = 1
			}
			if sent+size == len(c.data) || index == h2cUploadChunkLimit-1 {
				chunk.Finished = 1
			}
			chunk.Buffer = append([]byte(nil), c.data[sent:sent+size]...)
			result = append(result, h2cEvent{call: i, event: &chunk})
			sent += size
		}
	}
	return result, skipped
}

// h2cSkipUploads is uploadsWith with the calls h2cSkippable marks skipped when skip is on
func h2cSkipUploads(s *h2cScript, base uint64, drop, skip bool) (sent []h2cEvent, skipped int) {
	skippable := h2cSkippable(s)
	return s.uploadsWith(base, drop, func(call int) bool { return skip && skippable[call] })
}

// h2cScriptUploads is h2cSkipUploads with the skipped calls chosen by hand
func h2cScriptUploads(s *h2cScript, base uint64, skip map[int]bool) []h2cEvent {
	sent, _ := s.uploadsWith(base, false, func(call int) bool { return skip[call] })
	return sent
}

// h2cDirection writes the frames of one direction and cuts them into socket calls of chosen sizes
type h2cDirection struct {
	s       *h2cScript
	d       enums.SocketDataDirection
	pending []byte
}

func (w *h2cDirection) frames(frames ...[]byte) *h2cDirection {
	for _, f := range frames {
		w.pending = append(w.pending, f...)
	}
	return w
}

// calls cuts the pending bytes into calls of the sizes, and the rest into one more call
func (w *h2cDirection) calls(sizes ...int) {
	for _, size := range sizes {
		w.s.call(w.d, w.pending[:size], false)
		w.pending = w.pending[size:]
	}
	if len(w.pending) > 0 {
		w.s.call(w.d, w.pending, false)
		w.pending = nil
	}
}

// h2cSkipSession is a server side connection whose two directions the scripts write by hand
type h2cSkipSession struct {
	s              *h2cScript
	in, out        *h2cDirection
	client, server *h2cEndpoint
}

func newH2CSkipSession() *h2cSkipSession {
	s := &h2cScript{}
	session := &h2cSkipSession{s: s, client: newH2CEndpoint(), server: newH2CEndpoint(),
		in: &h2cDirection{s: s, d: enums.SocketDataDirectionIngress}, out: &h2cDirection{s: s, d: enums.SocketDataDirectionEgress}}
	session.in.frames([]byte(http2.ClientPreface), session.client.settings()).calls()
	session.out.frames(session.server.settings()).calls()
	return session
}

func (x *h2cSkipSession) respond(stream uint32, body int) {
	x.out.frames(x.server.headers(stream, false, h2cResponse()...), x.server.data(stream, true, body)).calls()
}

// h2cSkipScripts are hand cut reads around DATA payloads, built fresh for every run
var h2cSkipScripts = []struct {
	name string
	// minSkipped is the least number of calls the oracle must skip, so a script cannot test nothing
	minSkipped int
	build      func() *h2cScript
}{
	{
		// a DATA frame whose header is in call A behind a HEADERS frame, whose middle is call B, and whose tail is
		// in call C together with the header and the start of the next DATA frame, whose rest is call D; then the
		// same frames read as Go's x/net framer reads them, the header and the payload apart
		name: "split frame", minSkipped: 3,
		build: func() *h2cScript {
			x := newH2CSkipSession()
			x.in.frames(x.client.headers(1, false, h2cRequest("/split")...), x.client.data(1, false, h2cFrameSize),
				x.client.data(1, true, 5000))
			headers := len(x.in.pending) - 2*9 - h2cFrameSize - 5000
			x.in.calls(headers+9+100, 16000, h2cFrameSize-100-16000+9+50)
			x.respond(1, 100)
			x.in.frames(x.client.headers(3, false, h2cRequest("/framer")...)).calls()
			x.in.frames(x.client.data(3, false, h2cFrameSize)).calls(9)
			x.in.frames(x.client.data(3, true, 700)).calls(9)
			x.respond(3, 200)
			return x.s
		},
	},
	{
		// payloads read in many calls in a row, two streams one after the other, while the responses go out in
		// between
		name: "skipped in a row", minSkipped: 2 * 16,
		build: func() *h2cScript {
			x := newH2CSkipSession()
			for _, stream := range []uint32{1, 3} {
				x.in.frames(x.client.headers(stream, false, h2cRequest(fmt.Sprintf("/row/%d", stream))...)).calls()
				x.in.frames(x.client.data(stream, true, 16*4096)).calls(9, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096,
					4096, 4096, 4096, 4096, 4096, 4096, 4096)
				x.respond(stream, 1000)
			}
			return x.s
		},
	},
	{
		// DATA of a stream that was reset arrives late: the parser discards it without a stream. The payload is
		// read in several calls, skipped, and the request behind it must still be reported.
		name: "unknown stream", minSkipped: 6,
		build: func() *h2cScript {
			x := newH2CSkipSession()
			x.in.frames(x.client.headers(1, false, h2cRequest("/reset")...), x.client.rstStream(1)).calls()
			x.in.frames(x.client.data(1, false, 30000)).calls(9, 10000, 10000)
			x.in.frames(x.client.data(9, true, 20000)).calls(9, 5000, 5000, 5000)
			x.in.frames(x.client.headers(3, false, h2cRequest("/after-reset")...), x.client.data(3, true, 3000)).calls(30)
			x.respond(3, 64)
			return x.s
		},
	},
	{
		// a DATA frame of 256KB whose header is read with its first 130000 bytes in a call BPF truncates at the
		// upload limit, then calls inside its payload, then its tail with the next stream's frames. The payload
		// runs on behind the truncated call, so the discard counts the bytes BPF did not upload of it and carries
		// on in the next call.
		name: "truncated then skipped", minSkipped: 5,
		build: func() *h2cScript {
			x := newH2CSkipSession()
			x.in.frames(x.client.headers(1, false, h2cRequest("/truncated")...)).calls()
			x.in.frames(x.client.data(1, true, h2cResponseBody), x.client.headers(3, false, h2cRequest("/behind")...),
				x.client.data(3, true, 2000)).calls(9+130000, 20000, 20000, 20000, 20000, 20000)
			x.respond(1, 10)
			x.respond(3, 20)
			// and one whose payload ends inside the bytes the truncated call did not upload, which is completed at
			// the truncation and resynchronized at the next call
			x.in.frames(x.client.headers(5, false, h2cRequest("/truncated-inside")...)).calls()
			x.in.frames(x.client.data(5, true, 125000)).calls()
			x.in.frames(x.client.headers(7, true, h2cRequest("/after-truncation")...)).calls()
			x.respond(5, 30)
			x.respond(7, 40)
			return x.s
		},
	},
	{
		// a DATA payload that ends exactly where a call BPF truncated at the upload limit ends: the frame is
		// complete and the next call starts on a frame boundary. Once with the header in a call of its own and
		// the payload in the truncated call, which BPF skips instead when it skips, and once with the header in
		// the truncated call.
		name: "truncated exact end", minSkipped: 1,
		build: func() *h2cScript {
			x := newH2CSkipSession()
			x.in.frames(x.client.headers(1, false, h2cRequest("/exact-own-header")...)).calls()
			x.in.frames(x.client.data(1, true, 130000)).calls(9)
			x.in.frames(x.client.headers(3, true, h2cRequest("/exact-behind")...)).calls()
			x.respond(1, 10)
			x.respond(3, 20)
			x.in.frames(x.client.headers(5, false, h2cRequest("/exact-shared-header")...)).calls()
			x.in.frames(x.client.data(5, true, 130000)).calls()
			x.in.frames(x.client.headers(7, true, h2cRequest("/exact-after")...)).calls()
			x.respond(5, 30)
			x.respond(7, 40)
			return x.s
		},
	},
	{
		// a PADDED DATA frame whose data part is uploaded in full while its padding runs into the bytes the call
		// did not upload: the data part is in the body, and the parser resynchronizes at the next call. Never
		// skipped, the frame is padded; the plain frame of the next stream is.
		name: "padded truncated", minSkipped: 1,
		build: func() *h2cScript {
			x := newH2CSkipSession()
			x.in.frames(x.client.headers(1, false, h2cRequest("/padded-truncated")...)).calls()
			_ = x.client.framer.WriteDataPadded(1, true, bytes.Repeat([]byte{'p'}, 122800), make([]byte, 255))
			x.in.frames(x.client.take()).calls()
			x.in.frames(x.client.headers(3, false, h2cRequest("/padded-behind")...)).calls()
			x.in.frames(x.client.data(3, true, 3000)).calls(9)
			x.respond(1, 10)
			x.respond(3, 20)
			return x.s
		},
	},
	{
		// PADDED DATA frames are never skipped: the parser reads their pad length. The plain frame beside them is.
		name: "padded", minSkipped: 2,
		build: func() *h2cScript {
			x := newH2CSkipSession()
			x.in.frames(x.client.headers(1, false, h2cRequest("/padded")...)).calls()
			_ = x.client.framer.WriteDataPadded(1, false, bytes.Repeat([]byte{'p'}, 12000), make([]byte, 200))
			x.in.frames(x.client.take()).calls(9, 4000, 4000, 4000)
			_ = x.client.framer.WriteDataPadded(1, false, bytes.Repeat([]byte{'p'}, 5000), make([]byte, 0))
			x.in.frames(x.client.take()).calls(9, 1, 2000)
			x.in.frames(x.client.data(1, true, 9000)).calls(9, 4500)
			x.respond(1, 100)
			return x.s
		},
	},
}

// TestH2CSkipHandScriptsKeepTheLogs runs the hand cut scripts with the skipping off and on, with frequent and rare
// analysis passes, and requires the same access logs and kernel logs
func TestH2CSkipHandScriptsKeepTheLogs(t *testing.T) {
	withH2CSkipDataPayload(t)
	for _, script := range h2cSkipScripts {
		for _, every := range []int{1, 3, 1000000} {
			t.Run(fmt.Sprintf("%s/analyzeEvery=%d", script.name, every), func(t *testing.T) {
				base := bpfNow()
				baselineEvents, _ := h2cSkipUploads(script.build(), base, false, false)
				skippedEvents, skipped := h2cSkipUploads(script.build(), base, false, true)
				if skipped < script.minSkipped {
					t.Fatalf("the oracle skipped %d calls, expected at least %d", skipped, script.minSkipped)
				}
				baseline := h2cAnalyze(t, baselineEvents, every)
				result := h2cAnalyze(t, skippedEvents, every)
				if len(baseline.protocolLogs) == 0 {
					t.Fatalf("no access log: the comparison checks nothing")
				}
				assertSameProtos(t, "protocol logs", baseline.protocolLogs, result.protocolLogs)
				if len(baseline.protocolKernels) != len(result.protocolKernels) {
					t.Fatalf("kernel logs of protocol logs: baseline %d, skipped %d", len(baseline.protocolKernels), len(result.protocolKernels))
				}
				for i := range baseline.protocolKernels {
					assertSameProtos(t, fmt.Sprintf("kernel logs of protocol log %d", i), baseline.protocolKernels[i], result.protocolKernels[i])
				}
				assertSameProtos(t, "kernel logs without a protocol", baseline.kernelLogs, result.kernelLogs)
				if baseline.l4Totals() != result.l4Totals() {
					t.Fatalf("L4 totals differ: baseline %+v, skipped %+v", baseline.l4Totals(), result.l4Totals())
				}
				if script.name != "truncated then skipped" && script.name != "padded truncated" {
					assertNoParserErrors(t, result)
				}
			})
		}
	}
}

// TestH2CSkipDataPayloadSizes checks the sizes the skipped scripts report against the bodies they sent, so the
// equivalence above cannot hold with both runs wrong
func TestH2CSkipDataPayloadSizes(t *testing.T) {
	withH2CSkipDataPayload(t)
	expected := map[string][]string{
		"split frame":      {"/split body=21384 status=200 resp=100", "/framer body=17084 status=200 resp=200"},
		"skipped in a row": {"/row/1 body=65536 status=200 resp=1000", "/row/3 body=65536 status=200 resp=1000"},
		"unknown stream":   {"/after-reset body=3000 status=200 resp=64"},
		"truncated then skipped": {"/truncated body=262144 status=200 resp=10", "/behind body=2000 status=200 resp=20",
			"/truncated-inside body=125000 status=200 resp=30", "/after-truncation body=0 status=200 resp=40"},
		"padded": {"/padded body=26000 status=200 resp=100"},
		"truncated exact end": {"/exact-own-header body=130000 status=200 resp=10", "/exact-behind body=0 status=200 resp=20",
			"/exact-shared-header body=130000 status=200 resp=30", "/exact-after body=0 status=200 resp=40"},
		"padded truncated": {"/padded-truncated body=122800 status=200 resp=10", "/padded-behind body=3000 status=200 resp=20"},
	}
	for _, script := range h2cSkipScripts {
		want, ok := expected[script.name]
		if !ok {
			t.Fatalf("no expected sizes for %s", script.name)
		}
		t.Run(script.name, func(t *testing.T) {
			sent, _ := h2cSkipUploads(script.build(), bpfNow(), false, true)
			if got := h2cLogSummary(h2cAnalyze(t, sent, 1000000), false); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("access logs %v, expected %v", got, want)
			}
		})
	}
}

// TestH2CSkipPaddedPayloadMustNotBeSkipped shows why the BPF side never skips the payload of a PADDED DATA frame:
// the parser reads its first byte, the pad length, and without it the frame cannot be read. Skipping the payload
// calls of the padded frame, which the oracle refuses, loses the body.
func TestH2CSkipPaddedPayloadMustNotBeSkipped(t *testing.T) {
	withH2CSkipDataPayload(t)
	x := newH2CSkipSession()
	x.in.frames(x.client.headers(1, false, h2cRequest("/padded")...)).calls()
	_ = x.client.framer.WriteDataPadded(1, true, bytes.Repeat([]byte{'p'}, 12000), make([]byte, 200))
	x.in.frames(x.client.take()).calls(9, 6000)
	x.respond(1, 100)
	for i, skippable := range h2cSkippable(x.s) {
		if skippable {
			t.Fatalf("the oracle skips call %d of a padded frame", i)
		}
	}
	base := bpfNow()
	good := h2cAnalyze(t, h2cScriptUploads(x.s, base, nil), 1000000)
	// a frame-blind skipping of the two payload calls
	bad := h2cAnalyze(t, h2cScriptUploads(x.s, base, map[int]bool{4: true, 5: true}), 1000000)
	if fmt.Sprint(h2cLogSummary(good, false)) != "[/padded body=12000 status=200 resp=100]" {
		t.Fatalf("access log without the skipping: %v", h2cLogSummary(good, false))
	}
	if fmt.Sprint(h2cLogSummary(bad, false)) == fmt.Sprint(h2cLogSummary(good, false)) && bad.metrics.FramingErrors == 0 {
		t.Fatalf("skipping a padded payload must not go unnoticed")
	}
	t.Logf("with the padded payload skipped: %v, framing errors %d", h2cLogSummary(bad, false), bad.metrics.FramingErrors)
}

// TestH2CSkipResynchronizesPastSkippedCalls loses the call with the header of a DATA frame, so the parser meets
// the calls BPF skipped inside its payload at a point it takes for a frame boundary: it must not read a frame
// header across them, drop them as one framing error together with the call it could not parse, and report the
// stream behind them. The same calls uploaded with their bytes are mis-parsed the same way at worst, so only the
// stream behind is required.
func TestH2CSkipResynchronizesPastSkippedCalls(t *testing.T) {
	withH2CSkipDataPayload(t)
	x := newH2CSkipSession()
	x.in.frames(x.client.headers(1, false, h2cRequest("/lost")...)).calls()
	x.in.frames(x.client.data(1, true, 12000)).calls(9, 4000, 4000)
	x.in.frames(x.client.headers(3, true, h2cRequest("/behind")...)).calls()
	x.respond(3, 50)
	sent, skipped := h2cSkipUploads(x.s, bpfNow(), false, true)
	if skipped != 3 {
		t.Fatalf("expected the 3 payload calls skipped, got %d", skipped)
	}
	// the DATA header call is lost, and with it the frame boundary
	headerCall := 3
	kept := sent[:0]
	for _, e := range sent {
		if e.call == headerCall && e.event.PayloadSkipped0 == 0 {
			continue
		}
		kept = append(kept, e)
	}
	// the previous data ids still name the lost call, as BPF uploaded it: the parser gives it up at once
	defer protocols.SetHTTP2GapWaitDuration(protocols.SetHTTP2GapWaitDuration(0))
	result := h2cAnalyze(t, kept, 1000000)
	summary := h2cLogSummary(result, false)
	if len(summary) != 1 || summary[0] != "/behind body=0 status=200 resp=50" {
		t.Fatalf("the stream behind the skipped calls is lost: %v, %+v", summary, result.metrics)
	}
	if result.metrics.FramingErrors != 1 {
		t.Fatalf("the skipped calls must be dropped with the first one as one framing error, got %d", result.metrics.FramingErrors)
	}
}

// TestH2CPaddedTruncatedKeepsTheData is the padded frame whose padding alone runs into the bytes a truncated call
// did not upload, with the skipping off: its data part is still reported
func TestH2CPaddedTruncatedKeepsTheData(t *testing.T) {
	for _, script := range h2cSkipScripts {
		if script.name != "padded truncated" {
			continue
		}
		sent, _ := h2cSkipUploads(script.build(), bpfNow(), false, false)
		want := "[/padded-truncated body=122800 status=200 resp=10 /padded-behind body=3000 status=200 resp=20]"
		if got := fmt.Sprint(h2cLogSummary(h2cAnalyze(t, sent, 1000000), false)); got != want {
			t.Fatalf("access logs %v, expected %v", got, want)
		}
	}
}
