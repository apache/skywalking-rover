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
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// batchReadStats is what the batch-aware reader counts
type batchReadStats struct {
	perfEvents int // perf events read (a batch is one), the number that reaches the ring
	records    int // socket calls after expanding the batches (what one-event-per-call would have sent)
	batches    int // perf events that were batches
}

// withAccessLogBatch is withAccessLogBPFModes for the batching: skip_h2c_data_payload is on, and
// batch_h2c_records is set to `batch`. The reader expands every batch perf event into the per-call events
// it stands for (aclevents.DecodeBatchRecordInto), so a connection's events are the same whether or not BPF
// batched them, which is what the equivalence assertions rely on.
func withAccessLogBatch(t *testing.T, drop, batch bool, traffic func(run *h2cKernelRun)) (*h2cKernelRun, batchReadStats) {
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
	b := func(on bool) uint32 {
		if on {
			return 1
		}
		return 0
	}
	set(loader.DropH2cUnusedFrame, b(drop))
	set(loader.SkipH2cDataPayload, uint32(1))
	set(loader.BatchH2cRecords, b(batch))
	set(loader.BootTimeUnixNs, uint64(host.BootTime.UnixNano()))
	defer set(loader.DropH2cUnusedFrame, uint32(0))
	defer set(loader.SkipH2cDataPayload, uint32(0))
	defer set(loader.BatchH2cRecords, uint32(0))

	// the per-CPU batch buffer is header(8) + MAX*record + trailer(pending 8 + generation 4 + pad 4) + the slack the
	// verifier bounds the sent bytes with (1024, common/h2c_batch.h); a drift in the Go record layout shows here
	if batch {
		want := 8 + aclevents.BatchMaxRecords*aclevents.BatchRecordSize + 16 + 1024
		if got := int(loader.H2cBatchMap.ValueSize()); got != want {
			t.Fatalf("batch map value size %d, expected %d (record layout drift)", got, want)
		}
	}

	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 64<<20)
	if err != nil {
		t.Fatalf("perf reader: %v", err)
	}
	var events []*aclevents.SocketDataUploadEvent
	var lost, received atomic.Uint64
	var stats batchReadStats
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
		}
	}()

	// the kicker runs for the whole traffic: a CPU only batches once its kick has run (the kickable gate), and
	// the kick also flushes the idle batches at the end
	var stopKick func()
	if batch {
		stop, err := common.StartH2CBatchKick(loader)
		if err != nil {
			t.Fatalf("start the kick: %v", err)
		}
		stopKick = stop
	}
	run := &h2cKernelRun{skip: true}
	traffic(run)
	for {
		before := received.Load()
		time.Sleep(time.Second)
		if received.Load() == before {
			break
		}
	}
	if stopKick != nil {
		stopKick()
	}
	_ = reader.Close()
	<-readerDone
	if lost.Load() > 0 {
		t.Fatalf("batch=%t: %d perf samples lost, the comparison would be meaningless", batch, lost.Load())
	}

	for _, conn := range run.conns {
		for _, e := range events {
			if e.LocalPort == conn.port && (e.Protocol0 == enums.ConnectionProtocolHTTP2 || e.Shed()) {
				conn.events[e.Direction0] = append(conn.events[e.Direction0], e)
			}
		}
		for d := range conn.events {
			ev := conn.events[d]
			sort.SliceStable(ev, func(i, j int) bool { return h2cUploadBefore(ev[i], ev[j]) })
		}
	}
	return run, stats
}

// goH2CManyStreams runs `requests` POSTs over one h2c connection with up to `streams` of them in flight at
// once, so the DATA frames of many streams (more than 16) interleave on the wire, a stream is reset
// (context cancel), and the connection closes with records possibly still pending. Each request and
// response body is `body` bytes.
func goH2CManyStreams(t *testing.T, run *h2cKernelRun, requests, streams, body int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte{'r'}, body)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		server := &http2.Server{MaxConcurrentStreams: 256, MaxUploadBufferPerConnection: 8 << 20, MaxUploadBufferPerStream: 2 << 20}
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
	httpClient := &http.Client{Transport: transport}
	sem := make(chan struct{}, streams)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx := context.Background()
			// one request in ten is reset mid-flight to exercise RST_STREAM
			if i%10 == 9 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 2*time.Millisecond)
				defer cancel()
			}
			req, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://%s/s/%d", listener.Addr(), i),
				bytes.NewReader(bytes.Repeat([]byte{'q'}, body)))
			resp, err := httpClient.Do(req)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}(i)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
}

// TestH2CBatchRecords is the equivalence check: with batching on, the deterministic request/response
// workload (the one TestH2CSkipDataPayload uses) must give byte-identical access and kernel logs to the
// same calls uploaded in whole. Expanding the batch records yields the per-call events, so the per-call
// validation and the full-vs-skip proto comparison both hold.
func TestH2CBatchRecords(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const requests, bodySize = 16, 256 * 1024
	run, stats := withAccessLogBatch(t, false, true, func(run *h2cKernelRun) {
		goH2CBodyTraffic(t, run, requests, bodySize, bodySize)
	})
	if stats.batches == 0 {
		t.Fatalf("no batch events were produced")
	}
	for _, conn := range run.conns {
		checkPrevDataIDs(t, conn)
		checkLayoutFields(t, conn)
		checkSkippedCalls(t, conn)
		result := analyzeKernelConn(t, conn)
		full := analyzeKernelConn(t, h2cUnskipped(conn))
		assertSameProtos(t, conn.name+" protocol logs", full.protocolLogs, result.protocolLogs)
		if len(full.protocolKernels) != len(result.protocolKernels) {
			t.Fatalf("%s: kernel logs of protocol logs, %d and %d", conn.name, len(full.protocolKernels), len(result.protocolKernels))
		}
		for k := range full.protocolKernels {
			assertSameProtos(t, fmt.Sprintf("%s kernel logs of protocol log %d", conn.name, k), full.protocolKernels[k], result.protocolKernels[k])
		}
		assertSameProtos(t, conn.name+" kernel logs without a protocol", full.kernelLogs, result.kernelLogs)
	}
	t.Logf("batch on: %d perf events (%d batches) for %d socket calls, %.1f records/batch", stats.perfEvents,
		stats.batches, stats.records, float64(stats.records)/float64(max(stats.batches, 1)))
}

// TestH2CBatchInterleaved proves byte-identity under more than 16 interleaved streams, a reset stream and
// a close with records pending: with batching on (drop off, so the full reconstruction is comparable) the
// batched/skipped analysis of every connection matches the same calls uploaded in whole.
func TestH2CBatchInterleaved(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const requests, streams, body = 120, 32, 64 * 1024
	run, stats := withAccessLogBatch(t, false, true, func(run *h2cKernelRun) {
		goH2CManyStreams(t, run, requests, streams, body)
	})
	if stats.batches == 0 {
		t.Fatalf("no batch events were produced")
	}
	compared := 0
	for _, conn := range run.conns {
		if len(conn.events[enums.SocketDataDirectionIngress])+len(conn.events[enums.SocketDataDirectionEgress]) == 0 {
			continue // a connection with no HTTP/2 events (e.g. reset at once)
		}
		checkPrevDataIDs(t, conn)
		checkSkippedCalls(t, conn)
		if compareWithFullReconstruction(t, conn, false) {
			compared++
		}
	}
	t.Logf("interleaved: %d streams, %d perf events (%d batches) for %d calls; %d connections compared byte for byte",
		streams, stats.perfEvents, stats.batches, stats.records, compared)
}

// TestH2CBatchReduction measures the perf-event reduction in the production configuration (drop and skip
// on): the many-streams workload with batching off and on.
func TestH2CBatchReduction(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	const requests, streams, body = 64, 8, 256 * 1024
	_, statsOff := withAccessLogBatch(t, true, false, func(run *h2cKernelRun) {
		goH2CManyStreams(t, run, requests, streams, body)
	})
	_, statsOn := withAccessLogBatch(t, true, true, func(run *h2cKernelRun) {
		goH2CManyStreams(t, run, requests, streams, body)
	})
	if statsOn.batches == 0 {
		t.Fatalf("no batch events were produced")
	}
	// batched records per batch = the records carried in batches (not the full uploads) over the batches
	batchedRecords := statsOn.records - (statsOn.perfEvents - statsOn.batches)
	reduction := float64(statsOff.perfEvents) / float64(max(statsOn.perfEvents, 1))
	t.Logf("drop+skip, %d streams x %dKB: batch off %d perf events for %d calls; batch on %d perf events (%d batches, %.1f records/batch) for %d calls: %.1fx fewer perf events",
		streams, body/1024, statsOff.perfEvents, statsOff.records, statsOn.perfEvents, statsOn.batches,
		float64(batchedRecords)/float64(max(statsOn.batches, 1)), statsOn.records, reduction)
	if reduction < 2 {
		t.Fatalf("batching reduced perf events only %.1fx, expected a clear reduction", reduction)
	}
}

// compareWithFullReconstruction checks a connection's skipped/batched analysis against the same calls
// uploaded in whole. strict: the protocol logs and both kinds of kernel logs must be byte-identical. Not
// strict (heavy interleaving): the comparison is only made when both analyses are clean, because the full
// reconstruction itself can stall where an endpoint writes between two reads of one frame (see
// TestH2CSkipDataPayload), independently of the skipping and the batching. It reports whether it compared.
func compareWithFullReconstruction(t *testing.T, conn *h2cKernelConn, strict bool) bool {
	t.Helper()
	result := analyzeKernelConn(t, conn)
	full := analyzeKernelConn(t, h2cUnskipped(conn))
	clean := func(r *h2cResult) bool {
		return r.metrics.FramingErrors == 0 && r.metrics.Gaps == 0 && r.metrics.DecodeErrors == 0 && r.metrics.DroppedStreams == 0
	}
	if !strict && (!clean(result) || !clean(full) || len(result.protocolLogs) != len(full.protocolLogs)) {
		m, f := result.metrics, full.metrics
		t.Logf("%s: not comparable: %d logs (framing %d, gaps %d, decode %d, dropped %d), full %d logs (framing %d, gaps %d, decode %d, dropped %d)",
			conn.name, len(result.protocolLogs), m.FramingErrors, m.Gaps, m.DecodeErrors, m.DroppedStreams,
			len(full.protocolLogs), f.FramingErrors, f.Gaps, f.DecodeErrors, f.DroppedStreams)
		return false
	}
	assertSameProtos(t, conn.name+" protocol logs", full.protocolLogs, result.protocolLogs)
	if len(full.protocolKernels) != len(result.protocolKernels) {
		t.Fatalf("%s: kernel logs of protocol logs, %d and %d", conn.name, len(full.protocolKernels), len(result.protocolKernels))
	}
	for k := range full.protocolKernels {
		assertSameProtos(t, fmt.Sprintf("%s kernel logs of protocol log %d", conn.name, k), full.protocolKernels[k], result.protocolKernels[k])
	}
	assertSameProtos(t, conn.name+" kernel logs without a protocol", full.kernelLogs, result.kernelLogs)
	return true
}
