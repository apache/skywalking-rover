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
	"fmt"
	"sort"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// The runs on the kernel (common/h2c_sum.h, h2c_sum_call in syscalls/h2c.h): real Go h2c endpoints
// with bodies of 256KB both ways, where Go's client reads every response DATA frame as a 4096 byte read of the header
// and the start of the payload and a read of the rest, Go's server reads every request DATA frame as a 9 byte header
// and the payload, and the client writes the request bodies a frame per call.

// h2cSplitRecords is what the endpoints of a run sent per direction: positional uploads (full events among them), the
// summaries, the positional uploads that carried a run, and the runs whose last frame was open or that started behind
// a head
type h2cSplitRecords struct {
	positional, full, summaries, runs, open, headed int
}

func (r h2cSplitRecords) String() string {
	return fmt.Sprintf("%d positional (%d full events) + %d summaries; %d runs (%d open, %d behind a head)", r.positional,
		r.full, r.summaries, r.runs, r.open, r.headed)
}

// h2cSplitSide is the client or the server side of a run: its records by direction (the requests and the responses),
// and what the agent reported of it: per protocol log the sizes of its bodies, its status and its kernel logs
type h2cSplitSide struct {
	request, response h2cSplitRecords
	logs              []string
	metrics           map[string]int
}

// h2cSplitReport runs the connections of one side through the agent with their summaries
func h2cSplitReport(t *testing.T, run *h2cKernelRun, summaries []*events.H2CSummary, client bool) h2cSplitSide {
	t.Helper()
	side := h2cSplitSide{metrics: map[string]int{}}
	for _, conn := range run.conns {
		if conn.client != client {
			continue
		}
		// the client writes the requests, the server reads them
		request := enums.SocketDataDirectionIngress
		if client {
			request = enums.SocketDataDirectionEgress
		}
		records := func(d enums.SocketDataDirection) *h2cSplitRecords {
			if d == request {
				return &side.request
			}
			return &side.response
		}
		var mine []*events.H2CSummary
		for _, s := range summaries {
			if s.LocalPort == conn.port {
				mine = append(mine, s)
				records(s.Direction0).summaries++
			}
		}
		for d, evs := range conn.events {
			for _, e := range evs {
				if e.Sequence0 != 0 {
					continue
				}
				r := records(enums.SocketDataDirection(d))
				r.positional++
				if e.PayloadSkipped0 == 0 && (e.HaveReduce != 1 || e.DataLen > 16) {
					r.full++
				}
				if e.SumStream != 0 {
					r.runs++
				}
				if h2cRunOpen(e) {
					r.open++
				}
				if e.SumFrames&0x8000 != 0 {
					r.headed++
				}
			}
		}
		out := analyzeSummaryConn(t, conn, mine)
		side.metrics[out.metrics]++
		for i, b := range out.protocolLogs {
			var l v3.AccessLogProtocolLogs
			if err := proto.Unmarshal(b, &l); err != nil {
				t.Fatal(err)
			}
			h := l.GetHttp()
			side.logs = append(side.logs, fmt.Sprintf("%s %s req=%d resp=%d status=%d kernels=%d", h.GetRequest().GetMethod(),
				h.GetRequest().GetPath(), h.GetRequest().GetSizeOfBodyBytes(), h.GetResponse().GetSizeOfBodyBytes(),
				h.GetResponse().GetStatusCode(), len(out.protocolKernels[i])))
		}
	}
	sort.Strings(side.logs)
	return side
}

// h2cSplitFrames is the DATA frames of the direction a call read with the start of their payload and whose rest
// other calls read, from the bytes the endpoint really read
func h2cSplitFrames(t *testing.T, conn *h2cKernelConn, d enums.SocketDataDirection) int {
	t.Helper()
	stream := conn.real[d]
	var ends []int
	at := 0
	for _, size := range conn.calls[d] {
		at += size
		ends = append(ends, at)
	}
	callEnd := func(offset int) int {
		i := sort.SearchInts(ends, offset+1)
		if i == len(ends) {
			return len(stream)
		}
		return ends[i]
	}
	starts, _ := h2cWalkFrames(t, stream, conn.preface(d))
	split := 0
	for _, start := range starts {
		if http2.FrameType(stream[start+3]) != http2.FrameData {
			continue
		}
		length := int(stream[start])<<16 | int(stream[start+1])<<8 | int(stream[start+2])
		end := callEnd(start)
		if start+9 < end && start+9+length > end {
			split++
		}
	}
	return split
}

// TestH2CRunsSplitKernel runs real Go h2c endpoints with request and response bodies of 256KB, one stream at a
// time and 8 at once, and checks:
//   - drop off (a call is one upload, so the calls line up with the recorded bytes): BPF does what the model of the
//     summaries (h2cSummarize, held to today's output by TestH2CRunsSplitLikeToday and TestH2CSummaryRealCalls)
//     predicts from the recorded calls, upload by upload, with the same summarized bytes, runs, open runs (and the
//     rest of their open frame) and heads in front of them; every summarized call is in a summary and its bytes in a
//     gap, the map is empty after the traffic; the client read response DATA frames split across calls, and those
//     reads and the request bodies of both sides go into runs, the client's behind a head;
//   - with the production switches (drop on): the agent reports every request on both sides, with the same bodies
//     and statuses, without a framing error, gap, late or dropped stream;
//
// and reports the records per request of each side and direction.
func TestH2CRunsSplitKernel(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const requests, body = 48, 256 * 1024
	for _, streams := range []int{1, 8} {
		traffic := func(run *h2cKernelRun) { goH2CDownloads(t, run, requests, streams, body, body) }
		t.Run(fmt.Sprintf("streams=%d", streams), func(t *testing.T) {
			// BPF against the model, drop off
			runModel, sumsModel, stats := withAccessLogSummary(t, false, true, traffic)
			if stats.summaryCalls == 0 || stats.summaryBytes != stats.gapBytes {
				t.Fatalf("%d calls in summaries; %d bytes in summaries, %d in gaps", stats.summaryCalls,
					stats.summaryBytes, stats.gapBytes)
			}
			h2cSumConserved(t, runModel, sumsModel)
			if stats.left != 0 {
				t.Fatalf("the summary map holds %d entries after the traffic", stats.left)
			}
			compared := 0
			for _, conn := range runModel.conns {
				if h2cRunsLikeModel(t, conn, sumsModel, h2cSummaryOptions{}) {
					compared++
				}
			}
			if compared == 0 {
				t.Fatalf("no connection compared with the model")
			}
			client := h2cSplitReport(t, runModel, sumsModel, true)
			server := h2cSplitReport(t, runModel, sumsModel, false)
			t.Logf("drop off: %d of %d connections compared with the model; client %v / %v, server %v / %v",
				compared, len(runModel.conns), client.request, client.response, server.request, server.response)
			// the split run calls: Go's client reads a response DATA frame header with the start of its payload in
			// one call and the rest in another, so the run of the frames behind starts behind the summarized rest of
			// that frame (its head). The traffic must have had that shape, and the runs must have been made of it.
			split := 0
			for _, conn := range runModel.conns {
				if conn.client {
					split += h2cSplitFrames(t, conn, enums.SocketDataDirectionIngress)
				}
			}
			if split == 0 {
				t.Fatalf("the client read no response DATA frame split across calls: the test checks nothing")
			}
			if client.response.runs == 0 || client.response.headed == 0 {
				t.Fatalf("the client's response reads (%d frames split across calls) went into no run behind a head: %v",
					split, client.response)
			}
			// (only with 8 streams at once: one stream at a time makes a run of a request only when its
			// frames happen to come in the right shape, which depends on the timing of the reads)
			if streams == 8 && (client.request.runs == 0 || server.request.runs == 0) {
				t.Fatalf("no run of the requests: client %v, server %v", client.request, server.request)
			}
			// (no check of the open runs: a run whose last frame goes on into the next call needs a frame header
			// read with the start of its payload by a call BPF summarizes whole, which these readers do not make;
			// the model comparison above checks the open runs upload by upload whenever there are any)

			// the production switches
			withH2CSummaryTimes(t)
			run, sums, _ := withAccessLogSummary(t, true, true, traffic)
			client = h2cSplitReport(t, run, sums, true)
			server = h2cSplitReport(t, run, sums, false)
			for name, side := range map[string]h2cSplitSide{"client": client, "server": server} {
				if len(side.logs) != requests || len(side.metrics) != 1 || side.metrics["framing=0 gaps=0 decode=0 dropped=0 late=0"] == 0 {
					t.Fatalf("%s: %d protocol logs of %d requests, %v", name, len(side.logs), requests, side.metrics)
				}
				for _, l := range side.logs {
					if want := fmt.Sprintf("req=%d resp=%d status=200", body, body); !strings.Contains(l, want) {
						t.Fatalf("%s: %s", name, l)
					}
				}
				t.Logf("%s per request: requests %.2f records (%v), responses %.2f records (%v)", name,
					float64(side.request.positional+side.request.summaries)/requests, side.request,
					float64(side.response.positional+side.response.summaries)/requests, side.response)
			}
		})
	}
}
