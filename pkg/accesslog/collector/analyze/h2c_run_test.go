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
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The runs of whole DATA frames (h2c_sum_call in skywalking-rover/bpf/accesslog/syscalls/h2c.h): a writer that
// writes each DATA frame of a response with one call (Go's server, for a large body) makes calls that BPF cuts
// behind their 9 byte header, one record each. With the summaries, consecutive such calls of one stream in the
// direction of the responses are summarised header and all, and the next positional upload of the direction
// carries them as a run of frames of the stream. The tests below model it (h2cSummarize) over scripts of that
// shape and require today's protocol logs and kernel logs, byte for byte, through events and through records.

// h2cWholeFramesScript is the server side of responses written a frame per call: one stream after the other,
// three streams interleaved frame by frame, a response whose first frame goes out with its HEADERS (the rest of
// that frame in a call of its own), one that ends with an empty DATA frame with END_STREAM, one that ends with
// trailers, control frames of the server between the frames of a run, and a request body sent the same way
// (the direction of the requests has no runs)
func h2cWholeFramesScript() *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, []byte(http2.ClientPreface), false)
	s.splitRead(in, client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20}), false)
	_ = server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: h2cFrameSize})
	s.call(out, server.take(), false)
	s.call(out, server.settingsAck(), true)
	s.splitRead(in, client.settingsAck(), true)
	frames := func(id uint32, n int, last bool, size int) {
		for f := 0; f < n; f++ {
			s.call(out, server.data(id, last && f == n-1, size), false)
			if f%5 == 4 {
				s.splitRead(in, client.windowUpdate(0, 5*h2cFrameSize), true)
			}
		}
	}

	// one after the other, 16 frames each, the last with END_STREAM
	for _, id := range []uint32{1, 3} {
		s.splitRead(in, client.headers(id, true, h2cRequest(fmt.Sprintf("/seq/%d", id))...), false)
		s.call(out, server.headers(id, false, h2cResponse()...), false)
		frames(id, 16, true, h2cFrameSize)
	}
	// interleaved frame by frame: no run of one stream follows another directly
	ids := []uint32{5, 7, 9}
	for _, id := range ids {
		s.splitRead(in, client.headers(id, true, h2cRequest(fmt.Sprintf("/rr/%d", id))...), false)
		s.call(out, server.headers(id, false, h2cResponse()...), false)
	}
	for f := 0; f < 4; f++ {
		for _, id := range ids {
			s.call(out, server.data(id, f == 3, h2cFrameSize), false)
		}
	}
	// two frames of one stream, two of the next, by turns
	for _, id := range []uint32{11, 13} {
		s.splitRead(in, client.headers(id, true, h2cRequest(fmt.Sprintf("/pairs/%d", id))...), false)
		s.call(out, server.headers(id, false, h2cResponse()...), false)
	}
	for f := 0; f < 3; f++ {
		frames(11, 2, f == 2, h2cFrameSize)
		frames(13, 2, f == 2, h2cFrameSize)
	}
	// the first frame with the HEADERS, its rest alone, then whole frames, a PING answered in the middle
	s.splitRead(in, client.headers(15, true, h2cRequest("/first")...), false)
	first := append(server.headers(15, false, h2cResponse()...), server.data(15, false, h2cFrameSize)...)
	s.call(out, first[:4096], false)
	s.call(out, first[4096:], false)
	frames(15, 3, false, h2cFrameSize)
	s.splitRead(in, client.ping(false), true)
	s.call(out, server.ping(true), true)
	frames(15, 4, false, 1000)
	s.call(out, server.data(15, true, 0), false)
	// trailers end the stream
	s.splitRead(in, client.headers(17, true, h2cRequest("/trailers")...), false)
	s.call(out, server.headers(17, false, h2cResponse()...), false)
	frames(17, 6, false, h2cFrameSize)
	s.call(out, server.headers(17, true, h2cTrailers()...), false)
	// a request body sent a frame per call: the direction of the requests has no runs
	s.call(in, client.headers(19, false, h2cRequest("/upload")...), false)
	for f := 0; f < 5; f++ {
		s.call(in, client.data(19, f == 4, h2cFrameSize), false)
	}
	s.call(out, server.headers(19, false, h2cResponse()...), false)
	frames(19, 3, true, 500)
	return s
}

// h2cTrailers is a trailer block
func h2cTrailers() []hpack.HeaderField {
	return []hpack.HeaderField{{Name: "grpc-status", Value: "0"}}
}

// TestH2CRunsLikeToday is the equivalence of the runs with today's uploads over the whole frames script: as
// events and as the records of per-CPU batches (the record keeps its run behind its cut bytes), with the drop of
// BPF off and on, a wall clock minute in the middle, the flushes early, late or never, a map of 1 entry, and
// analysis passes after every delivery, every 7 or at the end. It reports what the runs save.
func TestH2CRunsLikeToday(t *testing.T) {
	withH2CSkipDataPayload(t)
	withH2CSummaryTimes(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	variants := map[string]h2cSummaryOptions{
		"plain":         {},
		"flush-3":       {flushEvery: 3},
		"flush-17-late": {flushEvery: 17, lateFlush: true},
		"capacity-1":    {capacity: 1, flushEvery: 5},
	}
	for _, drop := range []bool{false, true} {
		for _, minute := range []bool{false, true} {
			s := h2cWholeFramesScript()
			base := bpfNow()
			if minute {
				base = h2cMinuteBase(len(s.calls))
			}
			evs := s.h2cCutUploads(base, drop)
			for _, every := range []int{1, 7, 1 << 30} {
				today := h2cSumRun(t, h2cTodayDeliveries(evs), every)
				for name, o := range variants {
					deliveries, stats := h2cSummarize(s, evs, o)
					t.Run(fmt.Sprintf("drop=%t/minute=%t/every=%d/%s", drop, minute, every, name), func(t *testing.T) {
						if stats.runCalls == 0 || stats.runs == 0 {
							t.Fatalf("no run: %+v", stats)
						}
						assertSameMessages(t, today, h2cSumRun(t, deliveries, every), true)
						assertSameMessages(t, today, h2cSumRunRecords(t, deliveries, every), true)
					})
					if every == 1 && name == "plain" && !minute {
						t.Logf("drop=%t: %d uploads today; with the summaries %d positional + %d summaries, %d calls "+
							"summarised of which %d whole frames in %d runs", drop, len(evs), stats.positional,
							stats.summaries, stats.summarised, stats.runCalls, stats.runs)
					}
				}
			}
		}
	}
}

// h2cSumRunRecords is h2cSumRun with every positional event BPF batches handed over as the record of a batch of
// its own (the reader's splitter, events.SplitH2CBatch), the rest as events
func h2cSumRunRecords(t *testing.T, deliveries []h2cSumDelivery, every int) *h2cRecordOutput {
	t.Helper()
	run := newH2CRecordRunner(t, events.SplitH2CBatch)
	for i, d := range deliveries {
		switch {
		case d.summary != nil:
			s := *d.summary
			run.agentPartition.Consume(&s)
		case h2cBatchable(d.event) && (d.event.SumStream == 0 || d.event.DataLen <= 10) &&
			!(h2cRunOpen(d.event) && d.event.PayloadSkipped0 == 1):
			// (BPF sends a skipped call that carries an open run as an event: a record has no room for its rest)
			run.deliver(i, h2cDelivery{call: d.call, sample: encodeH2CBatch([]*events.SocketDataUploadEvent{d.event})})
		default:
			run.deliver(i, h2cDelivery{call: d.call, event: d.event})
		}
		if every > 0 && i%every == every-1 {
			run.analyze()
		}
	}
	run.analyze()
	return run.finish()
}

// TestH2CRunUnknownStream is a run of a stream the parser does not know (its request was never seen): the
// frames are stepped over as today, the stream's summary goes as a kernel log of its own (a summary no stream
// takes, as for the payload of such a stream), and the frames behind the run are parsed
func TestH2CRunUnknownStream(t *testing.T) {
	withH2CSkipDataPayload(t)
	withH2CSummaryTimes(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, []byte(http2.ClientPreface), false)
	s.splitRead(in, client.settings(), false)
	s.call(out, server.settings(), false)
	s.splitRead(in, client.headers(3, true, h2cRequest("/known")...), false)
	// stream 1 was never opened: its frames go to no stream
	for f := 0; f < 5; f++ {
		s.call(out, server.data(1, false, h2cFrameSize), false)
	}
	s.call(out, server.headers(3, false, h2cResponse()...), false)
	for f := 0; f < 4; f++ {
		s.call(out, server.data(3, f == 3, h2cFrameSize), false)
	}
	evs := s.h2cCutUploads(bpfNow(), false)
	today := h2cSumRunReleased(t, h2cTodayDeliveries(evs))
	deliveries, stats := h2cSummarize(s, evs, h2cSummaryOptions{})
	if stats.runs != 2 {
		t.Fatalf("%d runs, expected the one of each stream: %+v", stats.runs, stats)
	}
	summarised := h2cSumRunReleased(t, deliveries)
	assertSameMessages(t, today, summarised, false)
	if len(today.protocolLogs) != 1 {
		t.Fatalf("%d protocol logs", len(today.protocolLogs))
	}
	if extra := len(summarised.kernelLogs) - len(today.kernelLogs); extra != 1 {
		t.Fatalf("%d kernel logs, %d today: the summary of the unknown stream must go on its own", len(summarised.kernelLogs),
			len(today.kernelLogs))
	}
}

// h2cSumRunReleased is h2cSumRun with an analysis pass after every delivery and the connection released at the
// end (closed): the summaries no stream took go on their own
func h2cSumRunReleased(t *testing.T, deliveries []h2cSumDelivery) *h2cRecordOutput {
	t.Helper()
	run := newH2CRecordRunner(t, events.SplitH2CBatch)
	for _, d := range deliveries {
		if d.summary != nil {
			c := *d.summary
			run.agentPartition.Consume(&c)
		} else if e := copyAdmittedEvent(d.event); e != nil {
			run.agentPartition.Consume(e)
		}
		run.analyze()
	}
	run.conn.Metrics(enums.ConnectionProtocolHTTP2).(*protocols.HTTP2Metrics).ReleasePendingData()
	return run.finish()
}

// h2cBufioReads cuts the bytes of a direction into the reads Go's HTTP/2 client makes of them: its framer reads each
// frame header and payload with io.ReadFull through a bufio.Reader of 4096 bytes, which fills its buffer with one read
// when it is empty and the reader wants less than its size, and hands a larger want to one read of the connection.
// short(i) is how many bytes the i-th read of the connection for a larger want returns fewer than wanted (the socket
// did not have them yet), capFill(j) the most bytes the j-th filling read returns (0: no cap).
func h2cBufioReads(stream []byte, short func(i int) int, capFill func(j int) int) [][]byte {
	var reads [][]byte
	p, buffered, direct, fills := 0, 0, 0, 0
	readFull := func(n int) {
		for n > 0 && p+buffered <= len(stream) {
			if buffered > 0 {
				take := min(n, buffered)
				buffered -= take
				n -= take
				continue
			}
			if n >= 4096 {
				r := n - min(short(direct), n-1)
				direct++
				reads = append(reads, stream[p:p+r])
				p += r
				n -= r
				continue
			}
			r := min(4096, len(stream)-p)
			if c := capFill(fills); c > 0 {
				r = min(r, c)
			}
			fills++
			if r == 0 {
				return
			}
			reads = append(reads, stream[p:p+r])
			p += r
			buffered = r
		}
	}
	for at := 0; at+9 <= len(stream); {
		length := int(stream[at])<<16 | int(stream[at+1])<<8 | int(stream[at+2])
		readFull(9)
		readFull(length)
		at += 9 + length
	}
	return reads
}

// h2cSplitRunsScript is the client side of h2c requests with bodies and responses of 6 DATA frames each: the request
// bodies written a frame per call, some frames as their header with the start of the payload and the rest, some as a
// lone header and the payload; the responses (of two streams one after the other, and of two interleaved frame by
// frame) read as Go's client reads them (h2cBufioReads), with reads of the connection that return fewer bytes than
// wanted (a filling read behind them then carries the rest of a payload, the next frame header and the start of its
// payload) and filling reads that return less than a buffer. The direction of the requests and the frames whose
// payload goes on in other calls take the runs of the split frames. With frameSize above 64KB the rest of an
// open frame takes more than the 16 bits of a first frame offset.
func h2cSplitRunsScript(frameSize int) *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(out, append([]byte(http2.ClientPreface), client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})...), false)
	_ = server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: uint32(frameSize)})
	s.call(in, server.take(), false)
	s.call(in, server.settingsAck(), true)
	if frameSize > h2cFrameSize {
		// the frames of the server may be as large
		s.call(out, append(client.settings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: uint32(frameSize)}), client.settingsAck()...), false)
	} else {
		s.call(out, client.settingsAck(), true)
	}
	const frames = 6
	ids := []uint32{1, 3, 5, 7}
	for k, id := range ids {
		s.call(out, client.headers(id, false, h2cRequest(fmt.Sprintf("/split/%d", id))...), false)
		for f := 0; f < frames; f++ {
			frame := client.data(id, f == frames-1, frameSize)
			switch {
			case f == 3 && k == 3 && frameSize <= h2cFrameSize:
				// the rest of the frame written with a WINDOW_UPDATE: a positional upload behind the open frame (only with
				// frames the events of the model carry in whole, below 64KB)
				s.call(out, frame[:9+100], false)
				s.call(out, append(append([]byte(nil), frame[9+100:]...), client.windowUpdate(0, 1<<16)...), false)
			case f%3 == 1:
				s.call(out, frame[:9+100], false)
				s.call(out, frame[9+100:], false)
			case f%3 == 2 && k%2 == 1:
				s.call(out, frame[:9], false)
				s.call(out, frame[9:5000], false)
				s.call(out, frame[5000:], false)
			default:
				s.call(out, frame, false)
			}
			if f == 2 && k == 2 {
				s.call(out, client.windowUpdate(0, 1<<20), true)
			}
		}
	}
	var response []byte
	for _, id := range ids[:2] {
		response = append(response, server.headers(id, false, h2cResponse()...)...)
		for f := 0; f < frames; f++ {
			response = append(response, server.data(id, f == frames-1, frameSize)...)
		}
	}
	for _, id := range ids[2:] {
		response = append(response, server.headers(id, false, h2cResponse()...)...)
	}
	for f := 0; f < frames; f++ {
		for _, id := range ids[2:] {
			response = append(response, server.data(id, f == frames-1, frameSize)...)
		}
	}
	reads := h2cBufioReads(response, func(i int) int {
		switch i % 4 {
		case 1:
			return 3000
		case 2:
			return 7000
		}
		return 0
	}, func(j int) int {
		if j%7 == 6 {
			return 2000
		}
		return 0
	})
	for _, r := range reads {
		s.call(in, r, false)
	}
	return s
}

// TestH2CRunsSplitLikeToday is the equivalence of the runs of split frames (frames whose payload goes on in other
// calls, calls that start with the rest of the open frame of a run, the direction of the requests) with today's
// uploads, over the client calls of h2cSplitRunsScript and the server calls of h2cLongBodiesScript, as events and as
// the records of per-CPU batches, the drop of BPF off and on, the flushes early, late or
// never, a map of 1 entry (calls inside an open frame uploaded on their own), and analysis passes after every
// delivery, every 7 or at the end.
func TestH2CRunsSplitLikeToday(t *testing.T) {
	withH2CSkipDataPayload(t)
	withH2CSummaryTimes(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	variants := map[string]h2cSummaryOptions{
		"plain":         {},
		"flush-3":       {flushEvery: 3},
		"flush-17-late": {flushEvery: 17, lateFlush: true},
		"capacity-1":    {capacity: 1, flushEvery: 5},
		"refuse-3":      {refuseEvery: 3},
	}
	maxOpen := 0
	for _, script := range []h2cRecordScript{
		{"client-split", func() *h2cScript { return h2cSplitRunsScript(h2cFrameSize) }},
		{"client-split-large", func() *h2cScript { return h2cSplitRunsScript(100000) }},
		{"server-long", h2cLongBodiesScript},
	} {
		for _, drop := range []bool{false, true} {
			s := script.build()
			evs := s.h2cCutUploads(bpfNow(), drop)
			for _, every := range []int{1, 7, 1 << 30} {
				today := h2cSumRun(t, h2cTodayDeliveries(evs), every)
				for name, o := range variants {
					deliveries, stats := h2cSummarize(s, evs, o)
					maxOpen = max(maxOpen, stats.maxOpen)
					t.Run(fmt.Sprintf("%s/drop=%t/every=%d/%s", script.name, drop, every, name), func(t *testing.T) {
						if stats.runSplit == 0 || h2cRequestRuns(s, deliveries) == 0 {
							t.Fatalf("no split run or no run of the requests: %+v", stats)
						}
						if strings.HasPrefix(script.name, "client-split") && name == "plain" && (stats.openRuns == 0 || stats.headRuns == 0) {
							t.Fatalf("no open run or no run behind a head: %+v", stats)
						}
						assertSameMessages(t, today, h2cSumRun(t, deliveries, every), true)
						assertSameMessages(t, today, h2cSumRunRecords(t, deliveries, every), true)
					})
					if every == 1 && (name == "plain" || name == "ext-off") {
						t.Logf("%s drop=%t %s: %d uploads today; with the summaries %d positional + %d summaries, %d calls "+
							"summarised of which %d run calls (%d split) in %d runs (%d open, %d behind a head, %d of the requests)",
							script.name, drop, name, len(evs), stats.positional, stats.summaries, stats.summarised, stats.runCalls,
							stats.runSplit, stats.runs, stats.openRuns, stats.headRuns, h2cRequestRuns(s, deliveries))
					}
				}
			}
		}
	}
	if maxOpen <= 0xffff {
		t.Fatalf("no open frame with a rest above 16 bits: %d", maxOpen)
	}
}

// h2cRequestRuns is the positional events of the deliveries that carry a run in the direction of the requests (the
// one the client connection preface came in)
func h2cRequestRuns(s *h2cScript, deliveries []h2cSumDelivery) int {
	var request enums.SocketDataDirection
	for _, c := range s.calls {
		if bytes.HasPrefix(c.data, []byte(http2.ClientPreface)) {
			request = c.direction
			break
		}
	}
	n := 0
	for _, d := range deliveries {
		if d.event != nil && d.event.Direction0 == request && d.event.SumStream != 0 {
			n++
		}
	}
	return n
}
