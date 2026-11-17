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
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// h2cSumKernelStats is what a run of the summaries on the kernel counts
type h2cSumKernelStats struct {
	perfEvents, batches, records, fullEvents int
	// the summaries by where they came from: a batch (BPF sent them) or a drain of the user space
	fromBPF, drained int
	summaryBytes     uint64
	summaryCalls     uint64
	gapBytes         uint64
	// the entries left in the map after the last flush
	left    int64
	elapsed time.Duration
}

// withAccessLogSummary is withAccessLogBatch with the summaries set to `summarize`: drop off (so the calls of a
// connection line up with the recorded ones), skip and batch on. The summaries BPF sends in its batches and
// the ones the user space drains (H2CSummaries, flushed every second during the traffic, and at the end for
// the closed connections) are collected with the events.
func withAccessLogSummary(t *testing.T, drop, summarize bool, traffic func(run *h2cKernelRun)) (*h2cKernelRun, //nolint:funlen // it loads the BPF, sets its switches, runs the traffic and reads the events in one place, all sharing the loader and the reader
	[]*aclevents.H2CSummary, h2cSumKernelStats) {
	t.Helper()
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	set := func(v *ebpf.Variable, value interface{}) {
		if err := v.Set(value); err != nil {
			t.Fatalf("set %v: %v", v, err)
		}
	}
	b := uint32(0)
	if summarize {
		b = 1
	}
	d := uint32(0)
	if drop {
		d = 1
	}
	set(loader.DropH2cUnusedFrame, d)
	defer set(loader.DropH2cUnusedFrame, uint32(0))
	set(loader.SkipH2cDataPayload, uint32(1))
	set(loader.BatchH2cRecords, uint32(1))
	set(loader.SummarizeH2cPayload, b)
	set(loader.BootTimeUnixNs, uint64(host.BootTime.UnixNano()))
	defer set(loader.SkipH2cDataPayload, uint32(0))
	defer set(loader.BatchH2cRecords, uint32(0))
	defer set(loader.SummarizeH2cPayload, uint32(0))
	if got := int(loader.H2cSumMap.KeySize()); got != aclevents.SummaryKeySize {
		t.Fatalf("summary key %d bytes, expected %d", got, aclevents.SummaryKeySize)
	}
	if got := int(loader.H2cSumMap.ValueSize()); got != aclevents.SummaryValueSize {
		t.Fatalf("summary value %d bytes, expected %d", got, aclevents.SummaryValueSize)
	}
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	h2cClearMap(t, loader.H2cSumMap)
	if err := loader.H2cSumEpochMap.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var summaries []*aclevents.H2CSummary
	var stats h2cSumKernelStats
	manager := NewH2CSummaries(loader.H2cSumMap, loader.H2cSumEpochMap, loader.ActiveConnectionMap,
		func(s *aclevents.H2CSummary) {
			mu.Lock()
			summaries = append(summaries, s)
			stats.drained++
			mu.Unlock()
		})

	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 64<<20)
	if err != nil {
		t.Fatalf("perf reader: %v", err)
	}
	var events []*aclevents.SocketDataUploadEvent
	var lost, received atomic.Uint64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			record, err := reader.Read()
			if err != nil {
				return
			}
			lost.Add(record.LostSamples)
			received.Add(1)
			if len(record.RawSample) == 0 {
				continue
			}
			stats.perfEvents++
			if aclevents.IsBatchRecord(record.RawSample) {
				stats.batches++
				n := aclevents.BatchRecordCount(record.RawSample)
				for i := 0; i < n; i++ {
					if s, ok := aclevents.DecodeBatchSummary(record.RawSample, i); ok {
						mu.Lock()
						summaries = append(summaries, s)
						stats.fromBPF++
						mu.Unlock()
						continue
					}
					e := &aclevents.SocketDataUploadEvent{}
					if aclevents.DecodeBatchRecordInto(e, record.RawSample, i, nil) {
						events = append(events, e)
						stats.records++
					}
				}
				continue
			}
			e := &aclevents.SocketDataUploadEvent{}
			e.ReadFrom(btf.NewReader(record.RawSample))
			events = append(events, e)
			stats.records++
			stats.fullEvents++
		}
	}()
	stopKick, err := common.StartH2CBatchKick(loader)
	if err != nil {
		t.Fatalf("start the kick: %v", err)
	}
	flushDone := make(chan struct{})
	stopFlush := make(chan struct{})
	if summarize {
		go func() {
			defer close(flushDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					manager.Flush()
				case <-stopFlush:
					return
				}
			}
		}()
	} else {
		close(flushDone)
	}
	run := &h2cKernelRun{skip: true}
	start := time.Now()
	traffic(run)
	stats.elapsed = time.Since(start)
	for {
		before := received.Load()
		time.Sleep(time.Second)
		if received.Load() == before {
			break
		}
	}
	close(stopFlush)
	<-flushDone
	if summarize {
		// the connections are closed: two flushes take whatever is left of either epoch
		manager.Flush()
		manager.Flush()
		var key [aclevents.SummaryKeySize]byte
		var value [aclevents.SummaryValueSize]byte
		iter := loader.H2cSumMap.Iterate()
		for iter.Next(&key, &value) {
			stats.left++
		}
	}
	stopKick()
	_ = reader.Close()
	<-readerDone
	if lost.Load() > 0 {
		t.Fatalf("summarize=%t: %d perf samples lost", summarize, lost.Load())
	}
	for _, s := range summaries {
		stats.summaryBytes += s.Bytes
		stats.summaryCalls += uint64(s.Calls)
	}
	for _, e := range events {
		if e.Sequence0 == 0 {
			stats.gapBytes += uint64(e.SummarizedBefore())
		}
	}
	for _, conn := range run.conns {
		for _, e := range events {
			if e.LocalPort == conn.port && e.Protocol0 == enums.ConnectionProtocolHTTP2 {
				conn.events[e.Direction0] = append(conn.events[e.Direction0], e)
			}
		}
		for d := range conn.events {
			ev := conn.events[d]
			sort.SliceStable(ev, func(i, j int) bool { return h2cUploadBefore(ev[i], ev[j]) })
		}
	}
	return run, summaries, stats
}

// h2cKernelScript is the calls of a recorded connection as a script (both directions, each in its order) with
// the events BPF uploaded for them (drop off: one call, one data id), in the order of their data ids: what
// h2cSummarize models the summaries over, from the calls of real Go endpoints with the real times and counters
func h2cKernelScript(conn *h2cKernelConn) (*h2cScript, []h2cEvent, bool) {
	s := &h2cScript{}
	var evs []h2cEvent
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		offset := 0
		first := len(s.calls)
		for _, size := range conn.calls[d] {
			s.calls = append(s.calls, h2cCall{direction: d, data: conn.real[d][offset : offset+size], at: len(s.calls), id: len(s.calls)})
			offset += size
		}
		call := -1
		var lastID uint64
		for _, e := range conn.events[d] {
			if call < 0 || e.DataID0 != lastID {
				call++
				lastID = e.DataID0
			}
			if first+call >= len(s.calls) {
				return nil, nil, false
			}
			// the connection of the runner of the tests (h2cSumRun)
			c := e.Detach()
			c.Buffer = append([]byte(nil), e.BufferData()...)
			c.ConnectionID, c.RandomID = 1, 1
			evs = append(evs, h2cEvent{call: first + call, event: c})
		}
		if call+1 != len(conn.calls[d]) {
			// a call of the recording that BPF did not see, or the other way round: not comparable
			return nil, nil, false
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return h2cUploadBefore(evs[i].event, evs[j].event) })
	return s, evs, true
}

// TestH2CSummaryRealCalls is the equivalence of the summaries with today's uploads over the calls of real
// Go h2c endpoints (8 streams at once, 256KB bodies both ways): today's run of BPF (skip and batch on) gives the
// calls with their real shapes, times and counters, the model of the summaries (h2cSummarize) turns them into
// what BPF uploads with the summaries on, and both go through the agent: the protocol logs and their kernel
// logs must be the same, byte for byte.
func TestH2CSummaryRealCalls(t *testing.T) {
	withH2CSkipDataPayload(t)
	withH2CSummaryTimes(t)
	requireBPF(t)
	holdInflightMargin(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	// many streams with 256KB both ways; and responses of 256KB a DATA frame per call (the runs, h2c_run_test.go),
	// one stream at a time and 8 at once
	var conns []*h2cKernelConn
	for _, traffic := range []func(run *h2cKernelRun){
		func(run *h2cKernelRun) { goH2CManyStreams(t, run, 48, 8, 256*1024) },
		func(run *h2cKernelRun) { goH2CDownloads(t, run, 24, 1, 1024, 256*1024) },
		func(run *h2cKernelRun) { goH2CDownloads(t, run, 48, 8, 1024, 256*1024) },
	} {
		run, _, _ := withAccessLogSummary(t, false, false, traffic)
		conns = append(conns, run.conns...)
	}
	compared, runs := 0, 0
	for _, conn := range conns {
		s, evs, ok := h2cKernelScript(conn)
		if !ok || len(evs) == 0 {
			t.Logf("%s: the recorded calls and the events do not line up, not compared", conn.name)
			continue
		}
		for _, o := range []h2cSummaryOptions{{}, {flushEvery: 7}, {flushEvery: 3, lateFlush: true}, {capacity: 2}} {
			deliveries, stats := h2cSummarize(s, evs, o)
			for _, every := range []int{1, 1 << 30} {
				today := h2cSumRun(t, h2cTodayDeliveries(evs), every)
				if len(today.protocolLogs) == 0 {
					continue
				}
				summarized := h2cSumRun(t, deliveries, every)
				t.Run(fmt.Sprintf("%s/%+v/every=%d", conn.name, o, every), func(t *testing.T) {
					assertSameMessages(t, today, summarized, false)
				})
				compared++
				if every == 1 && o == (h2cSummaryOptions{}) {
					runs += stats.runs
					t.Logf("%s: %d calls, %d summarized (%d whole frames in %d runs) in %d summaries, %d deliveries "+
						"instead of %d; %d protocol logs", conn.name, len(evs), stats.summarized, stats.runCalls, stats.runs,
						stats.summaries, stats.positional+stats.summaries, len(evs), len(today.protocolLogs))
				}
			}
		}
	}
	if compared == 0 {
		t.Fatalf("no connection compared")
	}
	if runs == 0 {
		t.Fatalf("no run in the calls of the real endpoints")
	}
}

// TestH2CSummaryKernel runs real Go h2c endpoints (8 streams at once, 256KB bodies both ways) with the
// summaries off and on, and checks with them on that every summarized byte is in a summary and in a gap of the
// parser, that the agent reports every request as with them off, that the summary map is empty after the
// traffic, and how many records each message costs either way.
func TestH2CSummaryKernel(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const requests, streams, body = 96, 8, 256 * 1024
	traffic := func(run *h2cKernelRun) { goH2CManyStreams(t, run, requests, streams, body) }
	// the production switches: drop and skip on, batch on
	_, _, off := withAccessLogSummary(t, true, false, traffic)
	run, summaries, on := withAccessLogSummary(t, true, true, traffic)

	// the bytes of every summary are in exactly one gap
	if on.summaryCalls == 0 {
		t.Fatalf("nothing was summarized")
	}
	if on.summaryBytes != on.gapBytes {
		t.Fatalf("%d bytes in the summaries, %d in the gaps in front of the positional events", on.summaryBytes, on.gapBytes)
	}
	if on.left != 0 {
		t.Fatalf("the summary map holds %d entries after the traffic", on.left)
	}

	// the agent reports the requests as with the summaries off
	withH2CSummaryTimes(t)
	completed, protocolLogs := 0, 0
	for _, conn := range run.conns {
		var mine []*aclevents.H2CSummary
		for _, s := range summaries {
			if s.LocalPort == conn.port {
				mine = append(mine, s)
			}
		}
		result := analyzeSummaryConn(t, conn, mine)
		protocolLogs += len(result.protocolLogs)
		if !conn.client {
			completed += len(result.protocolLogs)
		}
		t.Logf("%s: %d protocol logs, %d kernel logs without a protocol, %s", conn.name, len(result.protocolLogs),
			len(result.kernelLogs), result.metrics)
	}
	reasons := map[string]int{}
	for _, s := range summaries {
		reasons[h2cSumReasonNames[s.Reason]]++
	}
	messages := float64(requests * 2) // each request is a message on both sides
	t.Logf("summaries off: %d perf events, %d records (%d full events) in %v: %.1f records per message",
		off.perfEvents, off.records, off.fullEvents, off.elapsed, float64(off.records)/messages)
	t.Logf("summaries on: %d perf events, %d records (%d full events) + %d summaries in %v: %.1f records per message; "+
		"%d calls summarized in %d summaries (%d by BPF, %d drained: %v), map left %d",
		on.perfEvents, on.records, on.fullEvents, len(summaries), on.elapsed,
		float64(on.records+on.fromBPF)/messages, on.summaryCalls, len(summaries), on.fromBPF, on.drained, reasons, on.left)
	if completed == 0 {
		t.Fatalf("no request reported")
	}
}

// analyzeSummaryConn runs the events of a connection and its summaries through the agent: the summaries first
// (as the ones the user space drains may come before the events)
func analyzeSummaryConn(t *testing.T, conn *h2cKernelConn, summaries []*aclevents.H2CSummary) *h2cRecordOutput {
	t.Helper()
	var deliveries []h2cSumDelivery
	for _, s := range summaries {
		c := *s
		c.ConnectionID, c.RandomID = 1, 1
		deliveries = append(deliveries, h2cSumDelivery{summary: &c})
	}
	var evs []*aclevents.SocketDataUploadEvent
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		evs = append(evs, conn.events[d]...)
	}
	sort.SliceStable(evs, func(i, j int) bool { return h2cUploadBefore(evs[i], evs[j]) })
	for _, e := range evs {
		c := e.Detach()
		c.Buffer = append([]byte(nil), e.BufferData()...)
		c.ConnectionID, c.RandomID = 1, 1
		deliveries = append(deliveries, h2cSumDelivery{event: c})
	}
	return h2cSumRun(t, deliveries, 1<<30)
}

// TestH2CSummaryLiveMap runs the production pipeline live over real Go h2c traffic with the summaries on:
// the btf reader with the batch splitter, the agent's partition and HTTP/2 analyzer (analysis passes every
// 100ms), the epoch flush of the user space every second and the drains of the parser. Many streams open and
// end (12 connections at once, 8 streams each, 256KB both ways); the summary map is sampled while they run and
// after: it must be back to about 0 entries within the flush period once the traffic stops, by the deletes
// of BPF at the end of a stream, of the parser and of the flush, with no forced drain.
func TestH2CSummaryLiveMap(t *testing.T) { //nolint:funlen // one scenario whose steps share the loaded BPF and the state of the run
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		set   func(interface{}) error
		value interface{}
	}{
		{loader.DropH2cUnusedFrame.Set, uint32(1)}, {loader.SkipH2cDataPayload.Set, uint32(1)},
		{loader.BatchH2cRecords.Set, uint32(1)}, {loader.SummarizeH2cPayload.Set, uint32(1)},
		{loader.BootTimeUnixNs.Set, uint64(host.BootTime.UnixNano())},
	} {
		if err := v.set(v.value); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = loader.DropH2cUnusedFrame.Set(uint32(0)) }()
	defer func() { _ = loader.SkipH2cDataPayload.Set(uint32(0)) }()
	defer func() { _ = loader.BatchH2cRecords.Set(uint32(0)) }()
	defer func() { _ = loader.SummarizeH2cPayload.Set(uint32(0)) }()
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	h2cClearMap(t, loader.H2cSumMap)
	stopKick, err := common.StartH2CBatchKick(loader)
	if err != nil {
		t.Fatalf("start the kick: %v", err)
	}
	defer stopKick()

	runner := newH2CRecordRunner(t, aclevents.SplitH2CBatch)
	// the periodic pass looks closed connections up in the active connections of BPF
	runner.ctx.BPF = loader
	var consumeLock sync.Mutex
	consume := func(data interface{}) {
		consumeLock.Lock()
		runner.agentPartition.Consume(data)
		consumeLock.Unlock()
	}
	manager := NewH2CSummaries(loader.H2cSumMap, loader.H2cSumEpochMap, loader.ActiveConnectionMap,
		func(s *aclevents.H2CSummary) { consume(s) })
	SetH2CSummaries(manager)
	defer SetH2CSummaries(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)

	mapName := loader.SocketDataUploadQueue.String()
	btf.SetBatchSampleSplitter(mapName, aclevents.SplitH2CBatch)
	defer btf.SetBatchSampleSplitter(mapName, nil)
	linker := btf.NewLinker()
	linker.ReadEventAsyncWithBufferSize(loader.SocketDataUploadQueue, consume, 64<<20, 1, func() interface{} {
		if !buffer.AcquireEvent() {
			return nil
		}
		return aclevents.AcquireUploadEvent()
	})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runner.analyzeAll()
			case <-ctx.Done():
				return
			}
		}
	}()
	count := func() int {
		n := 0
		var key [aclevents.SummaryKeySize]byte
		var value [aclevents.SummaryValueSize]byte
		iter := loader.H2cSumMap.Iterate()
		for iter.Next(&key, &value) {
			n++
		}
		return n
	}
	var peak atomic.Int64
	sampling := make(chan struct{})
	go func() {
		for {
			select {
			case <-sampling:
				return
			case <-time.After(50 * time.Millisecond):
				if n := int64(count()); n > peak.Load() {
					peak.Store(n)
				}
			}
		}
	}()
	run := &h2cKernelRun{skip: true}
	var wg sync.WaitGroup
	for c := 0; c < 12; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			goH2CManyStreams(t, run, 64, 8, 256*1024)
		}()
	}
	wg.Wait()
	close(sampling)
	stopped := time.Now()
	after := []int{count()}
	for i := 0; i < 6; i++ {
		time.Sleep(500 * time.Millisecond)
		after = append(after, count())
	}
	_ = linker.Close()
	cancel()
	time.Sleep(200 * time.Millisecond)
	runner.analyzeAll()

	_, protocolLogs := h2cDrainQueue(runner.ctx.Queue)
	t.Logf("map entries: peak %d while the streams ran, then every 500ms after they stopped: %v; %d protocol logs",
		peak.Load(), after, len(protocolLogs))
	_ = stopped
	if peak.Load() == 0 {
		t.Fatalf("nothing was summarized: the summary map never held an entry")
	}
	if last := after[len(after)-1]; last > 2 {
		t.Fatalf("%d entries left in the summary map 3s after the traffic stopped", last)
	}
	if len(protocolLogs) == 0 {
		t.Fatalf("no protocol log")
	}
}

// h2cSumConserved checks, for every recorded connection of a run with the drop off (a call is one upload or a part
// of a summary), that what BPF delivered accounts for every recorded call of each direction exactly once: the calls
// uploaded (the first chunk of each) and the calls the summaries of the connection count add up to the recorded
// calls, and their sizes and the bytes of the summaries to the recorded bytes
func h2cSumConserved(t *testing.T, run *h2cKernelRun, summaries []*aclevents.H2CSummary) {
	t.Helper()
	for _, conn := range run.conns {
		for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
			var uploads, uploadBytes, sumCalls, sumBytes uint64
			for _, e := range conn.events[d] {
				if e.Sequence0 == 0 {
					uploads++
					uploadBytes += e.TotalSize0
				}
			}
			for _, s := range summaries {
				if s.LocalPort == conn.port && s.Direction0 == d {
					sumCalls += uint64(s.Calls)
					sumBytes += s.Bytes
				}
			}
			calls, bytes := uint64(len(conn.calls[d])), uint64(len(conn.real[d]))
			if uploads+sumCalls != calls || uploadBytes+sumBytes != bytes {
				t.Fatalf("%s %s: %d calls (%d bytes) recorded; %d uploaded (%d bytes) and %d in summaries (%d bytes)",
					conn.name, directionName(d), calls, bytes, uploads, uploadBytes, sumCalls, sumBytes)
			}
		}
	}
}

// h2cRunUploads is the positional uploads of the connections of a run that carry a run of whole DATA frames
func h2cRunUploads(run *h2cKernelRun) int {
	n := 0
	for _, conn := range run.conns {
		for d := range conn.events {
			for _, e := range conn.events[d] {
				if e.Sequence0 == 0 && e.SumStream != 0 {
					n++
				}
			}
		}
	}
	return n
}

// h2cSumReasonNames names the reasons of the summaries (aclevents.SummaryReason*)
var h2cSumReasonNames = [aclevents.SummaryReasons]string{"", "end_stream", "rst", "close", "rekey", "flush",
	"close_drain", "stale", "stream_drain"}
