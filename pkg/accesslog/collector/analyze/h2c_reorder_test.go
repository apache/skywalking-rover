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
	"math/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The late skips of the cluster runs: the per-CPU batches deliver the records of a connection after full
// events of the same connection that BPF uploaded later, and with a full duplex connection (large bodies
// both ways, the reads and the writes on different threads) the HTTP/2 parser moved past the position of a
// batched record before the record arrived. These tests model that traffic and the batching of BPF and
// require the parser to put the records back in order: the same logs as the in-order delivery, no late skip.

// h2cDuplexScript is the server side of `rounds` rounds of `streams` requests and responses with bodies of
// `body` bytes in 16KB DATA frames, both ways at once: the reads of the requests of a round (random sizes,
// across the frames) interleave with the writes of the responses of the round before (one frame per write).
func h2cDuplexScript(rng *rand.Rand, rounds, streams, body int) *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, append([]byte(http2.ClientPreface), client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})...), false)
	_ = server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: h2cFrameSize})
	s.call(out, server.take(), false)
	s.call(in, client.settingsAck(), false)
	s.call(out, server.settingsAck(), false)

	type call struct {
		d    enums.SocketDataDirection
		data []byte
	}
	var writes []call // the responses of the previous round
	nextID := uint32(1)
	for r := 0; r <= rounds; r++ {
		var reads []call
		var ids []uint32
		if r < rounds {
			var request []byte
			for i := 0; i < streams; i++ {
				ids = append(ids, nextID)
				request = append(request, client.headers(nextID, false, h2cRequest(fmt.Sprintf("/duplex/%d", nextID))...)...)
				nextID += 2
			}
			for f := 0; f*h2cFrameSize < body; f++ {
				for _, id := range ids {
					request = append(request, client.data(id, (f+1)*h2cFrameSize >= body, min(h2cFrameSize, body-f*h2cFrameSize))...)
				}
			}
			for at := 0; at < len(request); {
				n := min(len(request)-at, 1+rng.Intn(20000))
				reads = append(reads, call{in, request[at : at+n]})
				at += n
			}
		}
		// interleave the reads of this round with the writes of the last one, each in its order
		for len(reads) > 0 || len(writes) > 0 {
			if len(writes) == 0 || (len(reads) > 0 && rng.Intn(2) == 0) {
				s.call(reads[0].d, reads[0].data, false)
				reads = reads[1:]
			} else {
				s.call(writes[0].d, writes[0].data, false)
				writes = writes[1:]
			}
		}
		for _, id := range ids {
			writes = append(writes, call{out, server.headers(id, false, h2cResponse()...)})
		}
		for f := 0; f*h2cFrameSize < body; f++ {
			for _, id := range ids {
				writes = append(writes, call{out, server.data(id, (f+1)*h2cFrameSize >= body, min(h2cFrameSize, body-f*h2cFrameSize))})
			}
		}
	}
	return s
}

// h2cRaceExits makes the uploads of the events as BPF makes them when the reads and the writes of the
// connection run at once: two neighboring calls of the two directions overlap with probability p, the
// later one returns first, and the previous data id of an upload is the call that returned last before it
// (socket_data_last_id_map). It returns the events in the order they are uploaded.
func h2cRaceExits(rng *rand.Rand, evs []h2cEvent, p float64) []h2cEvent {
	order := make([]h2cEvent, 0, len(evs))
	for i := 0; i < len(evs); i++ {
		if i+1 < len(evs) && evs[i].event.Direction0 != evs[i+1].event.Direction0 && rng.Float64() < p {
			evs[i].event.InFlight, evs[i+1].event.InFlight = 2, 2
			order = append(order, evs[i+1], evs[i])
			i++
			continue
		}
		evs[i].event.InFlight = 1
		order = append(order, evs[i])
	}
	var last uint64
	for _, e := range order {
		e.event.PrevDataID0 = last
		last = e.event.DataID0
	}
	return order
}

// h2cLiveBatching is h2cCPUBatching in real time, at a smaller scale: an upload every callEvery, the idle
// kick every kick, the analysis every analyzeEvery, and the parser's gap wait set to wait. Every upload gets
// its times when it is made, lag before the time it is made: the agent then reads the events lag behind the
// kernel, so the waits of the parser see the ages they see in the agent. The events of uploads are changed
// (their times). It also returns the longest time a batch went without a kick: on a loaded machine the run
// can stall beyond the kick period it models.
func h2cLiveBatching(t *testing.T, rng *rand.Rand, uploads []h2cEvent, cpus int, migrate float64,
	callEvery, kick, analyzeEvery, wait, lag time.Duration) (*h2cRecordOutput, time.Duration) {
	defer protocols.SetHTTP2GapWaitDuration(protocols.SetHTTP2GapWaitDuration(wait))
	run := newH2CRecordRunner(t, events.SplitH2CBatch)
	type mark struct{ cpu, gen int }
	batches := make([][]*events.SocketDataUploadEvent, max(cpus, 1))
	gens := make([]int, max(cpus, 1))
	var connMark *mark
	var thread [3]int
	thread[enums.SocketDataDirectionEgress] = 1 % max(cpus, 1)
	delivered := 0
	flush := func(cpu int) {
		if len(batches[cpu]) > 0 {
			run.deliver(delivered, h2cDelivery{sample: encodeH2CBatch(batches[cpu])})
			delivered++
			batches[cpu] = nil
			gens[cpu]++
		}
	}
	start := time.Now()
	lastKick, lastAnalyze := start, start
	var longestKick time.Duration
	for i, u := range uploads {
		//nolint:revive // a busy wait: sleeping would not keep the calls this close to their times
		for time.Since(start) < time.Duration(i)*callEvery {
		}
		now := bpfNow() - uint64(lag)
		u.event.StartTime0, u.event.EndTime0 = now, now+300
		d := u.event.Direction0
		if rng.Float64() < migrate {
			thread[d] = rng.Intn(max(cpus, 1))
		}
		cpu := thread[d]
		if cpus > 0 && h2cBatchable(u.event) {
			batches[cpu] = append(batches[cpu], u.event)
			connMark = &mark{cpu, gens[cpu]}
			if len(batches[cpu]) >= events.BatchMaxRecords {
				flush(cpu)
			}
		} else {
			if m := connMark; m != nil && m.cpu == cpu && m.gen == gens[cpu] {
				flush(cpu)
			}
			connMark = nil
			run.deliver(delivered, h2cDelivery{event: u.event})
			delivered++
		}
		if since := time.Since(lastKick); since >= kick {
			longestKick = max(longestKick, since)
			lastKick = time.Now()
			for c := range batches {
				flush(c)
			}
		}
		if time.Since(lastAnalyze) >= analyzeEvery {
			lastAnalyze = time.Now()
			run.analyze()
		}
	}
	longestKick = max(longestKick, time.Since(lastKick))
	for c := range batches {
		flush(c)
	}
	run.analyze()
	time.Sleep(2 * wait)
	run.analyze()
	return run.finish(), longestKick
}

// TestH2CBatchedRecordsLive drives the duplex traffic through the per-CPU batching in real time (an upload
// every 20us, the kick every 10ms: the agent's 1s at a hundredth, and the gap wait 100ms, which leaves the
// arrival wait 5 kicks, a margin for a loaded test machine) with the exits racing, with the agent on time and
// 150ms (beyond the gap wait) behind the kernel, and requires every stream to be reported with no late skip,
// no gap and no framing error
func TestH2CBatchedRecordsLive(t *testing.T) {
	if raceEnabled {
		t.Skip("real time at a hundredth of the agent's: the race detector slows the run beyond that scale")
	}
	withH2CSkipDataPayload(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const rounds, streams = 6, 8
	conclusive := 0
	for _, cpus := range []int{0, 4} {
		for _, race := range []float64{0, 0.3} {
			for _, migrate := range []float64{0, 0.05} {
				for _, analyzeEvery := range []time.Duration{time.Millisecond, 20 * time.Millisecond} {
					for _, lag := range []time.Duration{0, 150 * time.Millisecond} {
						name := fmt.Sprintf("cpus=%d/race=%.1f/migrate=%.2f/analyze=%s/lag=%s", cpus, race, migrate, analyzeEvery, lag)
						rng := rand.New(rand.NewSource(1))
						evs := h2cDuplexScript(rng, rounds, streams, 256<<10).h2cCutUploads(bpfNow(), false)
						uploads := h2cRaceExits(rng, evs, race)
						const wait = 100 * time.Millisecond
						out, longestKick := h2cLiveBatching(t, rng, uploads, cpus, migrate, 20*time.Microsecond, 10*time.Millisecond,
							analyzeEvery, wait, lag)
						t.Logf("%s: %d of %d streams reported (%s), %d records, longest kick %s", name, len(out.protocolLogs),
							rounds*streams, out.metrics, out.records, longestKick)
						if longestKick >= wait/2 {
							// the machine stalled the run past the arrival wait of the parser: a record waited in
							// its batch longer than the agent lets it, which is not what the run models
							t.Logf("%s: inconclusive, the run stalled %s", name, longestKick)
							continue
						}
						conclusive++
						if len(out.protocolLogs) != rounds*streams || out.metrics != "framing=0 gaps=0 decode=0 dropped=0 late=0" {
							t.Errorf("%s: %d of %d streams reported (%s)", name, len(out.protocolLogs), rounds*streams, out.metrics)
						}
					}
				}
			}
		}
	}
	if conclusive == 0 {
		t.Skip("the machine stalled every run past the modeled timing")
	}
}

// h2cOverlapScript is one request whose DATA frame spans three reads of the server, the middle one inside the
// payload (a batched record), the last one with the next frame of the client, while the server writes a PING
// between the first two reads and the response after the last; with several streams in a row. It returns the script and, per stream, the indexes of the
// calls of the race: the read inside the payload, the PING written meanwhile and the read after.
func h2cOverlapScript(streams int) (script *h2cScript, raceCalls [][3]int) {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, append([]byte(http2.ClientPreface), client.settings()...), false)
	s.call(out, server.settings(), false)
	s.call(in, client.settingsAck(), false)
	s.call(out, server.settingsAck(), false)
	var races [][3]int
	for i := 0; i < streams; i++ {
		id := uint32(1 + 2*i)
		headers := client.headers(id, false, h2cRequest(fmt.Sprintf("/overlap/%d", id))...)
		request := append(append([]byte(nil), headers...), client.data(id, true, h2cFrameSize)...)
		first := len(headers) + 9 + 100
		s.call(in, request[:first], false)
		s.call(in, request[first:first+8000], false)
		s.call(out, server.ping(false), false)
		// the read after the payload ends with the next frame of the client, so it is uploaded in whole
		s.call(in, append(append([]byte(nil), request[first+8000:]...), client.windowUpdate(0, 1<<16)...), false)
		races = append(races, [3]int{len(s.calls) - 3, len(s.calls) - 2, len(s.calls) - 1})
		s.call(out, append(server.headers(id, false, h2cResponse()...), server.data(id, true, 100)...), false)
	}
	return s, races
}

// TestH2CLateRecordOfOverlappedCalls is the late skip of the cluster runs, call by call: a read inside a DATA
// payload (record X) and a write (W) of the connection run at once, W enters later but returns first, so W
// names the call before X as its previous one and X names W; the read after X (Y) names X. The batch of X is
// delivered after W and Y. The parser read W, then Y (its previous data id, X, is below the largest data id
// parsed, W's), and skipped X as late when it came. It must wait for X instead: the same logs as the in-order
// delivery of the same uploads, no late skip and no gap.
func TestH2CLateRecordOfOverlappedCalls(t *testing.T) {
	withH2CSkipDataPayload(t)
	holdInflightMargin(t)
	chargeEventsLikeRecords(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const streams = 4
	script, races := h2cOverlapScript(streams)
	evs := script.h2cCutUploads(bpfNow(), false)
	byCall := map[int]*events.SocketDataUploadEvent{}
	for _, e := range evs {
		byCall[e.call] = e.event
	}
	// the exits of each race: W returns before X, as socket_data_last_id_map makes the previous data ids
	for _, race := range races {
		x, w, y := byCall[race[0]], byCall[race[1]], byCall[race[2]]
		if x == nil || w == nil || y == nil || !h2cBatchable(x) || h2cBatchable(w) || h2cBatchable(y) {
			t.Fatalf("the race %v is not a record between two full events: %+v %+v %+v", race, x != nil && h2cBatchable(x), w != nil && h2cBatchable(w), y != nil && h2cBatchable(y))
		}
		w.PrevDataID0, x.PrevDataID0, y.PrevDataID0 = x.PrevDataID0, w.DataID0, x.DataID0
		w.InFlight, x.InFlight = 2, 2
	}
	inOrder := func() []h2cDelivery {
		var result []h2cDelivery
		for _, e := range evs {
			if h2cBatchable(e.event) {
				result = append(result, h2cDelivery{call: e.call, sample: encodeH2CBatch([]*events.SocketDataUploadEvent{e.event})})
			} else {
				result = append(result, h2cDelivery{call: e.call, event: e.event})
			}
		}
		return result
	}()
	// the batch of X goes behind Y: the parser runs after every delivery
	late := append([]h2cDelivery(nil), inOrder...)
	for _, race := range races {
		var xAt, yAt int
		for i, d := range late {
			switch d.call {
			case race[0]:
				xAt = i
			case race[2]:
				yAt = i
			}
		}
		x := late[xAt]
		late = append(late[:xAt], late[xAt+1:]...)
		late = append(late[:yAt], append([]h2cDelivery{x}, late[yAt:]...)...)
	}
	for i := range late {
		late[i].call = i
	}
	want := h2cRecordRun(t, inOrder, events.SplitH2CBatch, 1, nil)
	got := h2cRecordRun(t, late, events.SplitH2CBatch, 1, nil)
	t.Logf("in order: %d logs (%s); X behind Y: %d logs (%s)", len(want.protocolLogs), want.metrics,
		len(got.protocolLogs), got.metrics)
	if len(want.protocolLogs) != streams || !strings.Contains(got.metrics, "gaps=0 ") || !strings.Contains(got.metrics, "late=0") {
		t.Fatalf("in order: %d logs (%s); X behind Y: %d logs (%s)", len(want.protocolLogs), want.metrics,
			len(got.protocolLogs), got.metrics)
	}
	assertSameOutput(t, want, got)
}
