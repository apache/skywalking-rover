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
	"sort"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// The summaries of the skipped h2c DATA payload (summarize_h2c_payload, bpf/accesslog/common/h2c_sum.h). These
// tests model what BPF does with the calls of a script with the summaries on (h2cSummarize): a call that lies
// wholly inside the payload of a DATA frame whose header it knows is added to the summary of its stream and
// direction instead of being uploaded, the next positional upload of the direction carries the summarized
// bytes, the previous data id of an upload names the previous positional upload; the summary of a stream goes
// with the last payload call of a frame with END_STREAM (which is uploaded as before), at a wall clock minute,
// at the epoch flushes of the user space, and at the end (the close). Then they run the uploads of today and
// those through the agent's partition and HTTP/2 analyzer and require the same protocol logs with the same
// kernel logs, byte for byte (in any order: a stream that waits for its summaries is reported later).

// h2cPayloadCall is what BPF knows of a call wholly inside a DATA payload: the stream of the frame (known when
// the whole header of the frame was in one call), whether the frame has END_STREAM and the call ends it
type h2cPayloadCall struct {
	stream    uint32
	known     bool
	endStream bool
	endsFrame bool
}

// h2cPayloadCalls is h2cPayloadCall for every call of the script that lies wholly inside a DATA payload
func h2cPayloadCalls(s *h2cScript) map[int]h2cPayloadCall {
	result := make(map[int]h2cPayloadCall)
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		var stream []byte
		var offsets, indexes []int
		for i, c := range s.calls {
			if c.direction == d {
				offsets, indexes = append(offsets, len(stream)), append(indexes, i)
				stream = append(stream, c.data...)
			}
		}
		callOf := func(at int) int {
			for k := len(offsets) - 1; k >= 0; k-- {
				if offsets[k] <= at {
					return k
				}
			}
			return -1
		}
		at := 0
		if bytes.HasPrefix(stream, []byte(http2.ClientPreface)) {
			at = len(http2.ClientPreface)
		}
		type frame struct {
			from, to int
			call     h2cPayloadCall
		}
		var frames []frame
		for at+9 <= len(stream) {
			length := int(stream[at])<<16 | int(stream[at+1])<<8 | int(stream[at+2])
			flags := http2.Flags(stream[at+4])
			if http2.FrameType(stream[at+3]) == http2.FrameData && !flags.Has(http2.FlagDataPadded) {
				id := (uint32(stream[at+5])<<24 | uint32(stream[at+6])<<16 | uint32(stream[at+7])<<8 | uint32(stream[at+8])) & 0x7fffffff
				frames = append(frames, frame{from: at + 9, to: at + 9 + length, call: h2cPayloadCall{
					stream: id, known: callOf(at) == callOf(at+8), endStream: flags.Has(http2.FlagDataEndStream)}})
			}
			at += 9 + length
		}
		for k, i := range indexes {
			from, to := offsets[k], offsets[k]+len(s.calls[i].data)
			for _, f := range frames {
				if k > 0 && to > from && f.from <= from && to <= f.to {
					c := f.call
					c.endsFrame = to == f.to
					result[i] = c
				}
			}
		}
	}
	return result
}

// h2cRunCall is what BPF knows of a call a run may take (h2c_sum_walked and h2c_sum_call in
// syscalls/h2c.h): the stream of the one DATA frame header that starts in it, the lead (the bytes in front of that
// header: the rest of the payload of the frame the call starts in, 0 when it starts with the header) and the rest of
// the frame's payload behind the call (0: the payload ends with the call)
type h2cRunCall struct {
	stream     uint32
	lead, rest int
}

// h2cRunCalls is h2cRunCall for every call of the script (but the first of its direction) in
// which exactly one frame header starts, a whole DATA frame header without END_STREAM or PADDED of a stream, at its
// start or behind the rest of a DATA payload without PADDED the call starts in, whose payload runs to the end of the
// call or beyond, in either direction once the client preface was seen
func h2cRunCalls(s *h2cScript) map[int]h2cRunCall { //nolint:funlen // a model of the BPF logic, kept in one piece to follow the C code step by step
	result := make(map[int]h2cRunCall)
	seen := false
	for _, c := range s.calls {
		if bytes.HasPrefix(c.data, []byte(http2.ClientPreface)) {
			seen = true
			break
		}
	}
	if !seen {
		return result
	}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		var stream []byte
		var offsets, indexes []int
		for i, c := range s.calls {
			if c.direction == d {
				offsets, indexes = append(offsets, len(stream)), append(indexes, i)
				stream = append(stream, c.data...)
			}
		}
		type frame struct {
			at, length int
		}
		var frames []frame
		at := 0
		if bytes.HasPrefix(stream, []byte(http2.ClientPreface)) {
			at = len(http2.ClientPreface)
		}
		for at+9 <= len(stream) {
			length := int(stream[at])<<16 | int(stream[at+1])<<8 | int(stream[at+2])
			frames = append(frames, frame{at, length})
			at += 9 + length
		}
		for k, i := range indexes {
			from, to := offsets[k], offsets[k]+len(s.calls[i].data)
			if k == 0 || to <= from {
				continue
			}
			var starts []int
			for n, f := range frames {
				if f.at >= from && f.at < to {
					starts = append(starts, n)
				}
			}
			if len(starts) != 1 {
				continue
			}
			n := starts[0]
			f := frames[n]
			h := stream[f.at:]
			if f.at+9 > to {
				continue
			}
			flags := http2.Flags(h[4])
			id := (uint32(h[5])<<24 | uint32(h[6])<<16 | uint32(h[7])<<8 | uint32(h[8])) & 0x7fffffff
			end := f.at + 9 + f.length
			if http2.FrameType(h[3]) != http2.FrameData || id == 0 || flags.Has(http2.FlagDataEndStream) ||
				flags.Has(http2.FlagDataPadded) || end < to {
				continue
			}
			lead := f.at - from
			if lead > 0 {
				// the call starts in the payload of the frame in front, a DATA frame without PADDED
				if n == 0 {
					continue
				}
				p := frames[n-1]
				ph := stream[p.at:]
				if http2.FrameType(ph[3]) != http2.FrameData || http2.Flags(ph[4]).Has(http2.FlagDataPadded) || p.at+9 > from {
					continue
				}
			}
			result[i] = h2cRunCall{stream: id, lead: lead, rest: end - to}
		}
	}
	return result
}

// h2cRunOpen tells whether the event carries a run whose last frame is open behind it (H2C_SUM_RUN_OPEN)
func h2cRunOpen(e *events.SocketDataUploadEvent) bool {
	return e.SumStream&(1<<31) != 0
}

// h2cSummaryOptions shapes the model
type h2cSummaryOptions struct {
	// refuseEvery makes every that many calls BPF would summarize find no entry (an overflow: uploaded on their own)
	refuseEvery int
	// flushEvery flips the epoch and drains the entries of the old one after every that many positional
	// uploads (0: never)
	flushEvery int
	// lateFlush hands the drained summaries over at the end instead of when they are drained
	lateFlush bool
	// capacity is the entries the map holds (0: no limit): a call that would need another one is uploaded as
	// before (the overflow)
	capacity int
	// endEarly hands the summaries BPF sends at the end of a stream over before the uploads of the calls in
	// front of them (another CPU's batch delivered first)
	endEarly bool
}

// h2cSumDelivery is a positional event or a summary, in the order the reader hands them over
type h2cSumDelivery struct {
	call    int
	event   *events.SocketDataUploadEvent
	summary *events.H2CSummary
}

type h2cSumModelStats struct {
	summarized, overflow, positional, summaries int
	// the summarized calls that were whole frames of a run, and the positional uploads that carried a run
	runCalls, runs int
	// the run calls of a frame that stayed open or that started with the rest of one, and the runs
	// whose last frame was open
	runSplit, openRuns, headRuns int
	// the largest rest of an open frame a positional upload carried
	maxOpen int
}

type h2cSumKey struct {
	stream    uint32
	direction enums.SocketDataDirection
	epoch     uint8
}

// h2cSummarize is what BPF uploads of today's uploads (evs, in the order of their calls) with the summaries on
func h2cSummarize(s *h2cScript, evs []h2cEvent, o h2cSummaryOptions) ([]h2cSumDelivery, h2cSumModelStats) { //nolint:funlen // a model of the BPF logic, kept in one piece to follow the C code step by step
	calls := h2cPayloadCalls(s)
	runCalls := h2cRunCalls(s)
	var result, late []h2cSumDelivery
	var stats h2cSumModelStats
	entries := make(map[h2cSumKey]*events.H2CSummary)
	var order []h2cSumKey
	var pending [3]uint32
	// the run each direction summarizes (h2c_sum_call): its stream, 0 when none, and its frames
	var runStream [3]uint32
	var runFrames [3]uint16
	// the rest of the payload of the open last frame of the run of each direction, 0 when none, and
	// whether the run starts behind a head (summarized payload of the frame in front of it)
	var runOpen [3]int
	var runHead [3]bool
	var epoch uint8
	var lastPositional uint64
	send := func(k h2cSumKey, reason uint8, call int, to *[]h2cSumDelivery) {
		v := entries[k]
		if v == nil {
			return
		}
		delete(entries, k)
		v.Reason = reason
		stats.summaries++
		*to = append(*to, h2cSumDelivery{call: call, summary: v})
	}
	// add adds the call to the summary of the stream in its direction, false when the map has no room for it
	tries := 0
	add := func(stream uint32, call int, ev *events.SocketDataUploadEvent) bool {
		d := ev.Direction0
		tries++
		if o.refuseEvery > 0 && tries%o.refuseEvery == 0 {
			stats.overflow++
			return false
		}
		k := h2cSumKey{stream, d, epoch}
		minute := h2cMinute(ev.StartTime0)
		v := entries[k]
		if v != nil && v.Minute != minute {
			send(k, events.SummaryReasonRekey, call, &result)
			v = nil
		}
		if v == nil && (o.capacity == 0 || len(entries) < o.capacity) {
			v = &events.H2CSummary{ConnectionID: ev.ConnectionID, RandomID: ev.RandomID, StreamID: stream,
				Direction0: d, Epoch: epoch, StartTime0: ev.StartTime0, FirstDataID0: ev.DataID0, Minute: minute,
				LocalPort: ev.LocalPort, RemotePort: ev.RemotePort, FunctionName: uint8(ev.FunctionName),
				SSL: uint8(ev.SSL)}
			entries[k] = v
			order = append(order, k)
		}
		if v == nil {
			stats.overflow++
			return false
		}
		// (the latest end: the merge of the details keeps the latest, BPF too)
		v.EndTime0, v.LastDataID0 = max(v.EndTime0, ev.EndTime0), ev.DataID0
		v.Bytes += ev.TotalSize0
		v.L4TotalPackageSize += ev.L4TotalPackageSize
		v.L4PackageCount += ev.L4PackageCount
		v.Calls++
		pending[d] += uint32(ev.TotalSize0)
		stats.summarized++
		return true
	}
	for _, e := range evs {
		ev := e.event
		d := ev.Direction0
		// a call that carries a DATA frame header, at its start or behind the rest of the open
		// frame of the run of its stream, joins the run; the frame stays open while its payload goes on
		// (a run that starts behind summarized payload of the frame in front of it starts behind a head)
		if rc, ok := runCalls[e.call]; ok && ev.PayloadSkipped0 == 0 && ev.Sequence0 == 0 &&
			(runStream[d] == rc.stream || (runStream[d] == 0 && rc.lead == 0)) &&
			rc.lead == runOpen[d] && uint64(pending[d])+ev.TotalSize0 <= 0xffffff && runFrames[d] < 0x7fff {
			head := runStream[d] == 0 && pending[d] > 0
			if !add(rc.stream, e.call, ev) {
				goto positional
			}
			runHead[d] = runHead[d] || head
			runStream[d] = rc.stream
			runFrames[d]++
			runOpen[d] = rc.rest
			stats.runCalls++
			if rc.lead != 0 || rc.rest != 0 {
				stats.runSplit++
			}
			continue
		}
		if c, ok := calls[e.call]; ok && ev.PayloadSkipped0 == 1 && c.known {
			if c.endsFrame && c.endStream {
				// the last payload call of the stream's direction: uploaded as before, its summaries go now
				var sent []h2cSumDelivery
				for _, ep := range []uint8{0, 1} {
					send(h2cSumKey{c.stream, d, ep}, events.SummaryReasonEndStream, e.call, &sent)
				}
				if o.endEarly {
					// in front of everything not delivered yet of the direction
					result = append(sent, result...)
				} else {
					result = append(result, sent...)
				}
			} else if runStream[d] == 0 && add(c.stream, e.call, ev) {
				continue
			} else if runStream[d] == c.stream && runOpen[d] > 0 &&
				uint64(pending[d])+ev.TotalSize0 <= 0xffffff && add(c.stream, e.call, ev) {
				// inside the open last frame of the run
				runOpen[d] -= int(ev.TotalSize0)
				continue
			}
		}
	positional:
		positional := ev.Detach()
		if data := ev.BufferData(); data != nil {
			positional.Buffer = append([]byte(nil), data...)
		}
		positional.SumBefore, pending[d] = pending[d], 0
		positional.SumStream, positional.SumFrames, runStream[d], runFrames[d] = runStream[d], runFrames[d], 0, 0
		if runHead[d] {
			positional.SumFrames |= 0x8000
			stats.headRuns++
		}
		runHead[d] = false
		if positional.SumStream != 0 {
			stats.runs++
			if open := runOpen[d]; open > 0 {
				// the rest of the open frame from the start of the call: the lower 16 bits as its first frame offset, the
				// upper 8 in the upper byte of the summarized bytes
				positional.SumStream |= 1 << 31
				positional.H2CFrames0, positional.FirstFrameOff = 1, uint16(open)
				positional.SumBefore |= uint32(open>>16) << 24
				if uint64(open) >= ev.TotalSize0 {
					positional.H2CFrames0 |= 2
				}
				stats.openRuns++
				stats.maxOpen = max(stats.maxOpen, open)
			}
		}
		runOpen[d] = 0
		positional.PrevDataID0, lastPositional = lastPositional, ev.DataID0
		result = append(result, h2cSumDelivery{call: e.call, event: positional})
		stats.positional++
		if o.flushEvery > 0 && stats.positional%o.flushEvery == 0 {
			old := epoch
			epoch ^= 1
			to := &result
			if o.lateFlush {
				to = &late
			}
			for _, k := range order {
				if k.epoch == old {
					send(k, events.SummaryReasonFlush, e.call, to)
				}
			}
		}
	}
	// the close: the user space drains what is left
	last := 0
	if len(evs) > 0 {
		last = evs[len(evs)-1].call
	}
	for _, k := range order {
		send(k, events.SummaryReasonCloseDrain, last, &late)
	}
	return append(result, late...), stats
}

// h2cMinute is the wall clock minute of a BPF time, as BPF computes it (h2c_sum_minute)
func h2cMinute(t uint64) uint32 {
	return uint32((uint64(host.BootTime.UnixNano()) + t) / 60000000000)
}

// h2cSumRun runs the deliveries through the agent's partition and HTTP/2 analyzer, an analysis pass every
// `every` deliveries and at the end
func h2cSumRun(t *testing.T, deliveries []h2cSumDelivery, every int) *h2cRecordOutput {
	t.Helper()
	run := newH2CRecordRunner(t, events.SplitH2CBatch)
	for i, d := range deliveries {
		if d.summary != nil {
			s := *d.summary
			run.agentPartition.Consume(&s)
		} else if e := copyAdmittedEvent(d.event); e != nil {
			run.agentPartition.Consume(e)
		}
		if every > 0 && i%every == every-1 {
			run.analyze()
		}
	}
	run.analyze()
	return run.finish()
}

// h2cTodayDeliveries is today's uploads as deliveries
func h2cTodayDeliveries(evs []h2cEvent) []h2cSumDelivery {
	result := make([]h2cSumDelivery, 0, len(evs))
	for _, e := range evs {
		result = append(result, h2cSumDelivery{call: e.call, event: e.event})
	}
	return result
}

// sortedProtocolOutput is the protocol logs of a run with their kernel logs, sorted
func sortedProtocolOutput(o *h2cRecordOutput) []string {
	result := make([]string, 0, len(o.protocolLogs))
	for i := range o.protocolLogs {
		var b bytes.Buffer
		b.Write(o.protocolLogs[i])
		for _, k := range o.protocolKernels[i] {
			b.WriteString("|")
			b.Write(k)
		}
		fmt.Fprintf(&b, "|%v|", o.protocolTransfers[i])
		b.Write(o.protocolEncoded[i])
		result = append(result, b.String())
	}
	sort.Strings(result)
	return result
}

func sortedBytes(list [][]byte) []string {
	result := make([]string, 0, len(list))
	for _, b := range list {
		result = append(result, string(b))
	}
	sort.Strings(result)
	return result
}

// assertSameMessages requires the same protocol logs with the same kernel logs, and with completeKernels the
// same kernel logs without a protocol as well
func assertSameMessages(t *testing.T, today, summarized *h2cRecordOutput, completeKernels bool) {
	t.Helper()
	if len(today.protocolLogs) == 0 {
		t.Fatalf("no protocol log")
	}
	a, b := sortedProtocolOutput(today), sortedProtocolOutput(summarized)
	if len(a) != len(b) {
		t.Fatalf("%d protocol logs today, %d with the summaries", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("protocol log %d differs:\ntoday:      %q\nsummarized: %q", i, a[i], b[i])
		}
	}
	if today.metrics != summarized.metrics {
		t.Fatalf("parser metrics: today %s, summarized %s", today.metrics, summarized.metrics)
	}
	if completeKernels {
		ka, kb := sortedBytes(today.kernelLogs), sortedBytes(summarized.kernelLogs)
		if fmt.Sprint(ka) != fmt.Sprint(kb) {
			t.Fatalf("kernel logs without a protocol differ: today %d, summarized %d", len(ka), len(kb))
		}
	}
}

// withH2CSummaryTimes makes the waits of the summaries long for the test, so nothing is reported early
func withH2CSummaryTimes(t *testing.T) {
	w, o := protocols.SetHTTP2SummaryTimes(time.Hour, time.Hour)
	t.Cleanup(func() { protocols.SetHTTP2SummaryTimes(w, o) })
}

// h2cSummaryScripts are the scripts with completed streams (no reset stream with a payload)
var h2cSummaryScripts = []h2cRecordScript{
	{"server", h2cServerScript},
	{"client", func() *h2cScript { return h2cClientScript(false) }},
	{"client-inside", func() *h2cScript { return h2cClientScript(true) }},
	{"split", h2cSkipSplitScript},
	{"many-streams", func() *h2cScript { return h2cManyStreamsScript(20) }},
	{"cut", h2cCutScript},
	{"long-bodies", h2cLongBodiesScript},
}

// h2cLongBodiesScript is the server side of 24 streams whose request bodies of 64KB are read the way Go's
// server reads them (a 9 byte header, then the payload in reads of 5000 bytes), interleaved frame by frame, and
// whose responses of 64KB are written as Go writes them (a frame header with the start of its payload, then
// the rest in writes of 4096 bytes)
func h2cLongBodiesScript() *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, append([]byte(http2.ClientPreface), client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})...), false)
	_ = server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: h2cFrameSize})
	s.call(out, server.take(), false)
	s.call(out, server.settingsAck(), true)
	s.call(in, client.settingsAck(), true)
	var ids []uint32
	for i := 0; i < 24; i++ {
		ids = append(ids, uint32(2*i+1))
	}
	for _, id := range ids {
		s.call(in, client.headers(id, false, h2cRequest(fmt.Sprintf("/long/%d", id))...), false)
	}
	readPayload := func(d enums.SocketDataDirection, frame []byte, header, step int) {
		s.call(d, frame[:header], false)
		for at := header; at < len(frame); at += step {
			end := at + step
			if end > len(frame) {
				end = len(frame)
			}
			s.call(d, frame[at:end], false)
		}
	}
	for f := 0; f < 4; f++ {
		for _, id := range ids {
			readPayload(in, client.data(id, f == 3, h2cFrameSize), 9, 5000)
		}
	}
	for _, id := range ids {
		s.call(out, server.headers(id, false, h2cResponse()...), false)
	}
	for f := 0; f < 4; f++ {
		for k, id := range ids {
			readPayload(out, server.data(id, f == 3, h2cFrameSize), 9+100, 4096)
			if k%6 == 5 {
				s.call(in, client.windowUpdate(0, 6*h2cFrameSize), true)
			}
		}
	}
	return s
}

// h2cMinuteBase is a base time for a script of n calls whose calls cross a wall clock minute in the middle
func h2cMinuteBase(n int) uint64 {
	boot := uint64(host.BootTime.UnixNano())
	now := bpfNow()
	minute := (boot+now)/60000000000 + 1
	return minute*60000000000 - boot - uint64(n/2)*1000
}

// TestH2CSummariesLikeToday is the equivalence of the summaries with today's uploads over the scripts
// (interleaved streams, more than 16 of them, END_STREAM, calls across frames and streams, long bodies across
// several flushes), with the dropping of BPF off and on, the flushes early, late or never, the summaries of an
// ended stream before or behind its calls, a map of 1 or 3 entries (the overflow), a wall clock minute in the
// middle, and analysis passes after every delivery, every 7 or at the end.
func TestH2CSummariesLikeToday(t *testing.T) {
	withH2CSkipDataPayload(t)
	withH2CSummaryTimes(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	type variant struct {
		name string
		o    h2cSummaryOptions
	}
	variants := []variant{
		{"plain", h2cSummaryOptions{}},
		{"flush-3", h2cSummaryOptions{flushEvery: 3}},
		{"flush-17-late", h2cSummaryOptions{flushEvery: 17, lateFlush: true}},
		{"end-early", h2cSummaryOptions{endEarly: true, flushEvery: 11}},
		{"capacity-1", h2cSummaryOptions{capacity: 1, flushEvery: 5}},
		{"capacity-3", h2cSummaryOptions{capacity: 3}},
	}
	var total h2cSumModelStats
	var records, recordsToday int
	// (and the responses written a frame per call, the runs, h2c_run_test.go: not among the scripts the golden
	// output of h2c_golden_test.go pins)
	scripts := append(append([]h2cRecordScript(nil), h2cSummaryScripts...), h2cRecordScript{"whole-frames", h2cWholeFramesScript})
	for _, script := range scripts {
		for _, drop := range []bool{false, true} {
			for _, minute := range []bool{false, true} {
				s := script.build()
				base := bpfNow()
				if minute {
					base = h2cMinuteBase(len(s.calls))
				}
				evs := s.h2cCutUploads(base, drop)
				for _, every := range []int{1, 7, 1 << 30} {
					today := h2cSumRun(t, h2cTodayDeliveries(evs), every)
					for _, v := range variants {
						deliveries, stats := h2cSummarize(s, evs, v.o)
						name := fmt.Sprintf("%s/drop=%t/minute=%t/every=%d/%s", script.name, drop, minute, every, v.name)
						t.Run(name, func(t *testing.T) {
							summarized := h2cSumRun(t, deliveries, every)
							assertSameMessages(t, today, summarized, true)
							if summarized.inUse != today.inUse || summarized.inflight != today.inflight {
								t.Fatalf("held: today %d events %d bytes, summarized %d events %d bytes", today.inUse,
									today.inflight, summarized.inUse, summarized.inflight)
							}
						})
						if every == 1 && v.name == "plain" {
							total.summarized += stats.summarized
							total.runCalls += stats.runCalls
							total.runs += stats.runs
							total.overflow += stats.overflow
							total.summaries += stats.summaries
							records += stats.positional + stats.summaries
							recordsToday += len(evs)
						}
					}
				}
			}
		}
	}
	t.Logf("calls summarized %d (%d whole frames in %d runs), summaries %d; deliveries %d with the summaries, %d today",
		total.summarized, total.runCalls, total.runs, total.summaries, records, recordsToday)
	if total.summarized == 0 || total.summaries == 0 {
		t.Fatalf("nothing was summarized")
	}
}

// TestH2CSummariesReset is a stream whose request body is summarized and that the client resets before it
// ends: no protocol log (as today), and every summary of it goes as a kernel log of its own
func TestH2CSummariesReset(t *testing.T) {
	withH2CSkipDataPayload(t)
	withH2CSummaryTimes(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, append([]byte(http2.ClientPreface), client.settings()...), false)
	s.call(out, server.settings(), false)
	s.call(in, client.headers(1, false, h2cRequest("/reset")...), false)
	s.call(in, client.headers(3, false, h2cRequest("/kept")...), false)
	for f := 0; f < 3; f++ {
		for _, id := range []uint32{1, 3} {
			frame := client.data(id, id == 3 && f == 2, h2cFrameSize)
			s.call(in, frame[:9], false)
			for at := 9; at < len(frame); at += 4000 {
				end := min(at+4000, len(frame))
				s.call(in, frame[at:end], false)
			}
		}
	}
	s.call(in, client.rstStream(1), false)
	s.call(out, append(server.headers(3, false, h2cResponse()...), server.data(3, true, 100)...), false)
	evs := s.h2cCutUploads(bpfNow(), false)
	today := h2cSumRun(t, h2cTodayDeliveries(evs), 1)
	deliveries, stats := h2cSummarize(s, evs, h2cSummaryOptions{flushEvery: 4})
	summarized := h2cSumRun(t, deliveries, 1)
	assertSameMessages(t, today, summarized, false)
	if len(today.protocolLogs) != 1 {
		t.Fatalf("%d protocol logs", len(today.protocolLogs))
	}
	// the reset stream's summaries go on their own: today its calls are not reported at all
	extra := len(summarized.kernelLogs) - len(today.kernelLogs)
	if extra <= 0 {
		t.Fatalf("the summaries of the reset stream were not sent: %d kernel logs, %d today", len(summarized.kernelLogs),
			len(today.kernelLogs))
	}
	t.Logf("%d calls summarized in %d summaries, %d kernel logs of the reset stream's summaries", stats.summarized,
		stats.summaries, extra)
}

// TestH2CSummariesUnfinished is the close of a connection with a stream in the middle of its body: the
// summaries the user space drains at the close have no stream to go to, and are sent as kernel logs of their
// own (one per summary instead of one per call); the finished streams are reported as today
func TestH2CSummariesUnfinished(t *testing.T) {
	withH2CSkipDataPayload(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	w, o := protocols.SetHTTP2SummaryTimes(time.Millisecond, time.Millisecond)
	defer protocols.SetHTTP2SummaryTimes(w, o)
	s := h2cLongBodiesScript()
	// the connection closes in the middle of the response bodies
	s.calls = s.calls[:len(s.calls)*3/4]
	evs := s.h2cCutUploads(bpfNow(), false)
	deliveries, stats := h2cSummarize(s, evs, h2cSummaryOptions{flushEvery: 9})
	run := newH2CRecordRunner(t, events.SplitH2CBatch)
	for _, d := range deliveries {
		if d.summary != nil {
			run.agentPartition.Consume(d.summary)
		} else if e := copyAdmittedEvent(d.event); e != nil {
			run.agentPartition.Consume(e)
		}
	}
	run.analyze()
	time.Sleep(5 * time.Millisecond)
	run.analyze()
	// the connection goes (closed, removed by the partition)
	m := run.conn.Metrics(enums.ConnectionProtocolHTTP2).(*protocols.HTTP2Metrics)
	m.ReleasePendingData()
	out := run.finish()
	if len(out.kernelLogs) == 0 {
		t.Fatalf("the summaries of the unfinished streams were not sent")
	}
	if m.PendingDataLength() != 0 {
		t.Fatalf("%d pending after the release", m.PendingDataLength())
	}
	t.Logf("%d summaries, %d kernel logs without a protocol, %d protocol logs", stats.summaries, len(out.kernelLogs),
		len(out.protocolLogs))
}

// TestH2CSummariesLoss loses a positional upload in the middle (a lost perf sample): the parser goes on
// through its gap handling, every summary is still taken (by a stream or on its own) and nothing is held
func TestH2CSummariesLoss(t *testing.T) {
	withH2CSkipDataPayload(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	old := protocols.SetHTTP2GapWaitDuration(0)
	defer protocols.SetHTTP2GapWaitDuration(old)
	w, o := protocols.SetHTTP2SummaryTimes(0, 0)
	defer protocols.SetHTTP2SummaryTimes(w, o)
	inUse0, _, _, _ := buffer.MemoryStats() //nolint:dogsled // only the events in use are compared
	for _, script := range h2cSummaryScripts {
		s := script.build()
		evs := s.h2cCutUploads(bpfNow(), false)
		deliveries, _ := h2cSummarize(s, evs, h2cSummaryOptions{flushEvery: 5})
		today := h2cTodayDeliveries(evs)
		for _, at := range []int{len(deliveries) / 3, len(deliveries) / 2} {
			if deliveries[at].event == nil {
				continue
			}
			call := deliveries[at].call
			lose := func(list []h2cSumDelivery) []h2cSumDelivery {
				var result []h2cSumDelivery
				for _, d := range list {
					if d.event == nil || d.call != call {
						result = append(result, d)
					}
				}
				return result
			}
			run := func(list []h2cSumDelivery) *h2cRecordOutput {
				r := newH2CRecordRunner(t, events.SplitH2CBatch)
				for i, d := range list {
					if d.summary != nil {
						c := *d.summary
						r.agentPartition.Consume(&c)
					} else if e := copyAdmittedEvent(d.event); e != nil {
						r.agentPartition.Consume(e)
					}
					if i%5 == 4 {
						r.analyze()
					}
				}
				r.analyze()
				r.analyze()
				r.conn.Metrics(enums.ConnectionProtocolHTTP2).(*protocols.HTTP2Metrics).ReleasePendingData()
				return r.finish()
			}
			was, got := run(lose(today)), run(lose(deliveries))
			t.Logf("%s lost call %d: today %d protocol logs %d kernel logs (%s); summarized %d protocol logs %d kernel logs (%s)",
				script.name, call, len(was.protocolLogs), len(was.kernelLogs), was.metrics, len(got.protocolLogs),
				len(got.kernelLogs), got.metrics)
			if len(got.protocolLogs) != len(was.protocolLogs) {
				t.Errorf("%s lost call %d: %d protocol logs, %d today", script.name, call, len(got.protocolLogs), len(was.protocolLogs))
			}
		}
	}
	if inUse, _, _, _ := buffer.MemoryStats(); inUse != inUse0 {
		t.Fatalf("events in use %d after the runs, %d before", inUse, inUse0)
	}
}
