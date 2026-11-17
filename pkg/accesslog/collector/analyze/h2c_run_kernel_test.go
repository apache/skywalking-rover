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
	"context"
	"crypto/tls"
	"fmt"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// The runs of whole DATA frames on the kernel (h2c_sum_call in skywalking-rover/bpf/accesslog/syscalls/h2c.h):
// real Go h2c endpoints, the server writing responses of 256KB, which Go's server writes a DATA frame per call.

// goH2CDownloads runs `requests` POSTs of reqBody bytes over one h2c connection, with up to `streams` of them in
// flight at once, each answered with respBody bytes; every request completes
func goH2CDownloads(t *testing.T, run *h2cKernelRun, requests, streams, reqBody, respBody int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte{'r'}, respBody)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		server := &http2.Server{MaxConcurrentStreams: 256}
		server.ServeConn(run.record(raw, "server", false), &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write(payload)
			}),
		})
	}()
	transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return run.record(raw, "client", true), nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	sem := make(chan struct{}, streams)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/d/%d", listener.Addr(), i),
				bytes.NewReader(bytes.Repeat([]byte{'q'}, reqBody)))
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("request %d: %v", i, err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}(i)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
}

// h2cPositional is what a positional upload of a direction carries, to compare BPF with the model
type h2cPositional struct {
	size, before uint64
	stream       uint32
	frames       uint16
	// the rest of the open last frame of the run in front, 0 without one
	open uint32
}

// h2cPositionals is the positional uploads of the events (one per call: the first chunk), in their order
func h2cPositionals(evs []*events.SocketDataUploadEvent) []h2cPositional {
	var result []h2cPositional
	for _, e := range evs {
		if e.Sequence0 == 0 {
			p := h2cPositional{e.TotalSize0, uint64(e.SumBefore), e.SumStream, e.SumFrames, 0}
			p.open = e.SummaryRunOpenRest()
			result = append(result, p)
		}
	}
	return result
}

// TestH2CRunsKernel runs real Go h2c endpoints whose server writes responses of 256KB a DATA frame per call, one
// stream at a time and 8 at once, with the summaries off and on (the production switches), and checks with them on:
//   - BPF does what the model of the summaries (h2cSummarize, which TestH2CRunsLikeToday and
//     TestH2CSummaryRealCalls hold to today's output) predicts from the recorded calls: the same positional
//     uploads of each direction, with the same summarised bytes and runs in front of them, and the same
//     summarised calls (drop off, so a call is one upload); the uploads and the summaries account for every
//     recorded call and byte exactly once;
//   - every summarised byte is in a summary and in a gap, BPF's map is empty after the traffic;
//   - the agent reports every request, with its sizes and status, without a framing error, a gap, a late or a
//     dropped stream, and with as many kernel logs as with the summaries off;
//
// and reports the records per stream of the server's responses either way.
func TestH2CRunsKernel(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const requests, reqBody, respBody = 48, 1024, 256 * 1024
	for _, streams := range []int{1, 8} {
		traffic := func(run *h2cKernelRun) { goH2CDownloads(t, run, requests, streams, reqBody, respBody) }
		t.Run(fmt.Sprintf("streams=%d", streams), func(t *testing.T) {
			// BPF against the model, drop off
			runModel, sumsModel, _ := withAccessLogSummary(t, false, true, traffic)
			if h2cRunUploads(runModel) == 0 {
				t.Fatalf("no call was summarised into a run")
			}
			h2cSumConserved(t, runModel, sumsModel)
			compared := 0
			for _, conn := range runModel.conns {
				if h2cRunsLikeModel(t, conn, sumsModel, h2cSummaryOptions{}) {
					compared++
				}
			}
			if compared == 0 {
				t.Fatalf("no connection compared with the model")
			}

			// the production switches: drop on, off and on
			withH2CSummaryTimes(t)
			runOff, _, _ := withAccessLogSummary(t, true, false, traffic)
			runOn, sums, on := withAccessLogSummary(t, true, true, traffic)
			if on.summaryCalls == 0 || on.summaryBytes != on.gapBytes {
				t.Fatalf("%d calls in summaries; %d bytes in summaries, %d in gaps", on.summaryCalls, on.summaryBytes,
					on.gapBytes)
			}
			if on.left != 0 {
				t.Fatalf("the summary map holds %d entries after the traffic", on.left)
			}
			offLogs, offRecords := h2cRunsServerReport(t, runOff, nil)
			onLogs, onRecords := h2cRunsServerReport(t, runOn, sums)
			if offLogs.protocolLogs != requests || onLogs.protocolLogs != requests {
				t.Fatalf("%d protocol logs with the summaries off, %d on, %d requests", offLogs.protocolLogs,
					onLogs.protocolLogs, requests)
			}
			if fmt.Sprint(offLogs.kernelsPerLog) != fmt.Sprint(onLogs.kernelsPerLog) {
				t.Fatalf("kernel logs per protocol log: %v off, %v on", offLogs.kernelsPerLog, onLogs.kernelsPerLog)
			}
			t.Logf("server responses (egress), per stream: %.2f records with the summaries off (%d full events), "+
				"%.2f with them on (%d positional of which %d full events, %d summaries); %d calls summarised into %d "+
				"runs", float64(offRecords.total())/requests, offRecords.full,
				float64(onRecords.total())/requests, onRecords.positional, onRecords.full, onRecords.summaries,
				on.summaryCalls, onRecords.runs)
		})
	}
}

// h2cRunsLikeModel compares, for each direction of the connection, the positional uploads of BPF with those the
// model of the summaries makes of the recorded calls, and the calls BPF summarised with those the model
// summarises; false when the recording and the uploads do not line up (a write the kernel split), not compared
func h2cRunsLikeModel(t *testing.T, conn *h2cKernelConn, summaries []*events.H2CSummary, o h2cSummaryOptions) bool {
	t.Helper()
	s := &h2cScript{}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		offset := 0
		for _, size := range conn.calls[d] {
			s.calls = append(s.calls, h2cCall{direction: d, data: conn.real[d][offset : offset+size], at: len(s.calls), id: len(s.calls)})
			offset += size
		}
	}
	evs := s.h2cCutUploads(bpfNow(), false)
	deliveries, _ := h2cSummarize(s, evs, o)
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		var modelEvents []*events.SocketDataUploadEvent
		for _, dl := range deliveries {
			if dl.event != nil && dl.event.Direction0 == d {
				modelEvents = append(modelEvents, dl.event)
			}
		}
		model, got := h2cPositionals(modelEvents), h2cPositionals(conn.events[d])
		summarised := 0
		for _, sum := range summaries {
			if sum.LocalPort == conn.port && sum.Direction0 == d {
				summarised += int(sum.Calls)
			}
		}
		if len(got)+summarised != len(conn.calls[d]) {
			t.Logf("%s %s: %d calls recorded, %d positional + %d summarised: not compared", conn.name, directionName(d),
				len(conn.calls[d]), len(got), summarised)
			return false
		}
		if fmt.Sprint(model) != fmt.Sprint(got) {
			for i := range got {
				if i >= len(model) || model[i] != got[i] {
					t.Fatalf("%s %s: positional upload %d of %d: BPF %+v, model %+v", conn.name, directionName(d), i,
						len(got), got[i], model[min(i, len(model)-1)])
				}
			}
			t.Fatalf("%s %s: %d positional uploads by BPF, %d by the model", conn.name, directionName(d), len(got), len(model))
		}
	}
	return true
}

// h2cRunsLogs is what the agent reported of the server connections of a run
type h2cRunsLogs struct {
	protocolLogs  int
	kernelsPerLog []int
}

// h2cRunsRecords is what the server sent of its responses (egress): positional uploads (full events among them),
// summaries, and the runs the positional uploads carried
type h2cRunsRecords struct {
	positional, full, summaries, runs int
}

func (r h2cRunsRecords) total() int {
	return r.positional + r.summaries
}

// h2cRunsServerReport runs the server connections of the run through the agent and checks every protocol log: the
// sizes and status of the traffic of goH2CDownloads, no framing error, gap, late or dropped stream
func h2cRunsServerReport(t *testing.T, run *h2cKernelRun, summaries []*events.H2CSummary) (h2cRunsLogs, h2cRunsRecords) {
	t.Helper()
	var logs h2cRunsLogs
	var records h2cRunsRecords
	for _, conn := range run.conns {
		if conn.client {
			continue
		}
		var mine []*events.H2CSummary
		for _, s := range summaries {
			if s.LocalPort == conn.port {
				mine = append(mine, s)
				if s.Direction0 == enums.SocketDataDirectionEgress {
					records.summaries++
				}
			}
		}
		for _, e := range conn.events[enums.SocketDataDirectionEgress] {
			if e.Sequence0 != 0 {
				continue
			}
			records.positional++
			if e.PayloadSkipped0 == 0 && !(e.HaveReduce == 1 && e.DataLen <= 16) {
				records.full++
			}
			if e.SumStream != 0 {
				records.runs++
			}
		}
		out := analyzeSummaryConn(t, conn, mine)
		if out.metrics != "framing=0 gaps=0 decode=0 dropped=0 late=0" {
			t.Fatalf("%s: %s", conn.name, out.metrics)
		}
		for i, b := range out.protocolLogs {
			var l v3.AccessLogProtocolLogs
			if err := proto.Unmarshal(b, &l); err != nil {
				t.Fatal(err)
			}
			h := l.GetHttp()
			if h.GetRequest().GetSizeOfBodyBytes() != 1024 || h.GetResponse().GetSizeOfBodyBytes() != 256*1024 ||
				h.GetResponse().GetStatusCode() != 200 {
				t.Fatalf("%s: protocol log %d: %v", conn.name, i, h)
			}
			logs.kernelsPerLog = append(logs.kernelsPerLog, len(out.protocolKernels[i]))
		}
		logs.protocolLogs += len(out.protocolLogs)
	}
	sort.Ints(logs.kernelsPerLog)
	return logs, records
}
