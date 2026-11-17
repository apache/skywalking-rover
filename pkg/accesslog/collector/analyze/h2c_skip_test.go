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
	"strings"
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"golang.org/x/net/http2"
)

// With access_log.protocol_analyze.skip_h2c_data_payload on, the BPF side uploads a socket call of a
// cleartext HTTP/2 connection that lies wholly inside the payload of a DATA frame without the PADDED flag
// as one event without content: data_len 0, the size of the call as total_size, payload_skipped set, and
// the function name, the L4 counters, the times and the ports of the call as every event carries them
// (skywalking-rover/bpf/accesslog/syscalls/h2c.h). The agent builds its kernel logs from these events, so
// the skipped calls must still give theirs. These tests drive the agent's HTTP/2 analyzer with the same
// socket calls with and without the skipping and require the same access logs and kernel logs.

// h2cTailSkippable is, for every call, how many of its first bytes BPF uploads when it cuts the rest of
// the call: the offset in the call where the payload of a DATA frame without the PADDED flag starts whose
// header ends inside the call and that runs to the end of the call or beyond; 0 when the end of the call
// may not be cut. The first call of a direction is never cut.
func h2cTailSkippable(s *h2cScript) []int {
	result := make([]int, len(s.calls))
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		var stream []byte
		var offsets, indexes []int
		for i, c := range s.calls {
			if c.direction == d {
				offsets, indexes = append(offsets, len(stream)), append(indexes, i)
				stream = append(stream, c.data...)
			}
		}
		at := 0
		if bytes.HasPrefix(stream, []byte(http2.ClientPreface)) {
			at = len(http2.ClientPreface)
		}
		type data struct{ from, to int }
		var payloads []data
		for at+9 <= len(stream) {
			length := int(stream[at])<<16 | int(stream[at+1])<<8 | int(stream[at+2])
			if http2.FrameType(stream[at+3]) == http2.FrameData && !http2.Flags(stream[at+4]).Has(http2.FlagDataPadded) &&
				length > 0 {
				payloads = append(payloads, data{at + 9, at + 9 + length})
			}
			at += 9 + length
		}
		for k, i := range indexes {
			from, to := offsets[k], offsets[k]+len(s.calls[i].data)
			for _, p := range payloads {
				if k > 0 && from < p.from && p.from < to && p.to >= to {
					result[i] = p.from - from
				}
			}
		}
	}
	return result
}

// h2cSkippable marks the calls that lie wholly inside the payload of a DATA frame without the PADDED
// flag; the first call of a direction is never skipped
func h2cSkippable(s *h2cScript) []bool {
	result := make([]bool, len(s.calls))
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		var stream []byte
		var offsets, indexes []int
		for i, c := range s.calls {
			if c.direction == d {
				offsets, indexes = append(offsets, len(stream)), append(indexes, i)
				stream = append(stream, c.data...)
			}
		}
		type payload struct{ from, to int }
		var payloads []payload
		at := 0
		if bytes.HasPrefix(stream, []byte(http2.ClientPreface)) {
			at = len(http2.ClientPreface)
		}
		for at+9 <= len(stream) {
			length := int(stream[at])<<16 | int(stream[at+1])<<8 | int(stream[at+2])
			if http2.FrameType(stream[at+3]) == http2.FrameData && !http2.Flags(stream[at+4]).Has(http2.FlagDataPadded) {
				payloads = append(payloads, payload{at + 9, at + 9 + length})
			}
			at += 9 + length
		}
		for k, i := range indexes {
			from, to := offsets[k], offsets[k]+len(s.calls[i].data)
			for _, p := range payloads {
				if k > 0 && to > from && p.from <= from && to <= p.to {
					result[i] = true
				}
			}
		}
	}
	return result
}

// skipUploads is uploads with the skipping: a skipped call is its event without the content, which still
// becomes the previous data id of the next upload
func (s *h2cScript) skipUploads(base uint64, drop, skip bool) (result []h2cEvent, skipped int) {
	skippable := h2cSkippable(s)
	var lastUploaded uint64
	for i, c := range s.calls {
		dataID := uint64(c.id + 1)
		if drop && c.dropped {
			continue
		}
		e := h2cDataEvent(c, dataID, lastUploaded, base)
		if skip && skippable[i] {
			e.DataLen, e.Buffer, e.PayloadSkipped0 = 0, nil, 1
			skipped++
		}
		result = append(result, h2cEvent{call: i, event: e})
		lastUploaded = dataID
	}
	return result, skipped
}

// h2cSkipSplitScript reads DATA frames on the server side in pieces: a header behind a HEADERS frame with
// the start of its payload, the middle on its own, the tail with the next frame's header; then frames
// read header and payload apart, and a PADDED frame, whose payload is never skipped
func h2cSkipSplitScript() *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, append([]byte(http2.ClientPreface), client.settings()...), false)
	s.call(out, server.settings(), false)
	headers := client.headers(1, false, h2cRequest("/split")...)
	stream := append(append(headers, client.data(1, false, h2cFrameSize)...), client.data(1, true, 5000)...)
	for _, size := range []int{len(headers) + 9 + 100, 16000, h2cFrameSize - 100 - 16000 + 9 + 50} {
		s.call(in, stream[:size], false)
		stream = stream[size:]
	}
	s.call(in, stream, false)
	s.call(out, append(server.headers(1, false, h2cResponse()...), server.data(1, true, 100)...), false)

	s.splitRead(in, client.headers(3, false, h2cRequest("/framer")...), false)
	frame := client.data(3, false, h2cFrameSize)
	s.call(in, frame[:9], false)
	for at := 9; at < len(frame); at += 4096 {
		s.call(in, frame[at:min(at+4096, len(frame))], false)
	}
	_ = client.framer.WriteDataPadded(3, true, bytes.Repeat([]byte{'p'}, 6000), make([]byte, 30))
	s.splitRead(in, client.take(), false)
	s.call(out, append(server.headers(3, false, h2cResponse()...), server.data(3, true, 200)...), false)
	return s
}

// TestH2CSkipDataPayloadKeepsTheLogs runs the server and client side of the measured workload and the
// split reads with the skipping off and on, with the dropping off and on, with and without the kernel log
// merge, and requires the same access logs, kernel logs of each access log, kernel logs without a
// protocol and L4 totals: the skipped calls keep their kernel logs.
func TestH2CSkipDataPayloadKeepsTheLogs(t *testing.T) {
	withH2CSkipDataPayload(t)
	scripts := []struct {
		name       string
		build      func() *h2cScript
		streams    int
		minSkipped int
	}{
		{"server", h2cServerScript, 3, 3},
		{"client", func() *h2cScript { return h2cClientScript(false) }, 2, 20},
		{"split", h2cSkipSplitScript, 2, 5},
	}
	for _, s := range scripts {
		for _, drop := range []bool{false, true} {
			for _, merge := range []bool{true, false} {
				for _, every := range []int{1, 7, 1000000} {
					t.Run(fmt.Sprintf("%s/drop=%t/merge=%t/analyzeEvery=%d", s.name, drop, merge, every), func(t *testing.T) {
						common.SetMergeKernelLogs(merge)
						defer common.SetMergeKernelLogs(false)
						base := bpfNow()
						baselineEvents, _ := s.build().skipUploads(base, drop, false)
						skippedEvents, skipped := s.build().skipUploads(base, drop, true)
						if skipped < s.minSkipped {
							t.Fatalf("%d calls skipped, expected at least %d", skipped, s.minSkipped)
						}
						baseline := h2cAnalyze(t, baselineEvents, every)
						result := h2cAnalyze(t, skippedEvents, every)
						if len(baseline.protocolLogs) != s.streams {
							t.Fatalf("expected %d access logs, got %d", s.streams, len(baseline.protocolLogs))
						}
						assertSameLogs(t, baseline, result)
						if fmt.Sprint(baseline.reportedIDs) != fmt.Sprint(result.reportedIDs) {
							t.Fatalf("the kernel logs come from other calls:\nbaseline %v\nskipped  %v", baseline.reportedIDs, result.reportedIDs)
						}
						t.Logf("%d of %d calls skipped: %v", skipped, len(skippedEvents), h2cLogSummary(result, false))
					})
				}
			}
		}
	}
}

// TestH2CHeaderSizesAreTheHeaders checks the sizes against the frames that were sent: the header sizes
// are the HEADERS frames alone. HandleWholeStream combines the header and body buffers of a stream into
// its log, and that combination once appended onto the request header buffer in place, which then
// reported the size of the whole stream as the size of the request headers.
func TestH2CHeaderSizesAreTheHeaders(t *testing.T) {
	reqHeaders := len(newH2CEndpoint().headers(1, false, h2cRequest("/split")...))
	respHeaders := len(newH2CEndpoint().headers(1, false, h2cResponse()...))
	events, _ := h2cSkipSplitScript().skipUploads(bpfNow(), false, false)
	result := h2cAnalyze(t, events, 1000000)
	got := h2cLogSummary(result, true)
	want := fmt.Sprintf("POST /split req=%d/%d status=200 resp=%d/100", reqHeaders, h2cFrameSize+5000, respHeaders)
	if len(got) == 0 || !strings.HasSuffix(got[0], want[len("POST"):]) {
		t.Fatalf("access log %v, expected %s", got, want)
	}
}
