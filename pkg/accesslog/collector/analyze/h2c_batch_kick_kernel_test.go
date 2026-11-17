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
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// TestH2CBatchKickFlushesIdle runs the production idle kick (common.StartH2CBatchKick) with batching on,
// makes a few requests over one h2c connection, then keeps the connection open and idle for 3s before it is
// closed. The records of the last calls are held in per-CPU batches with nothing on the connection to flush
// them but the kick: they must all arrive within about 2s of the last request, well before the close, and
// the connection's events must be complete. The kick's own pipe writes must never be recorded as traffic.
func TestH2CBatchKickFlushesIdle(t *testing.T) { //nolint:funlen // one scenario whose steps share the loaded BPF and the state of the run
	withH2CSkipDataPayload(t)
	requireBPF(t)
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		set   func(interface{}) error
		value interface{}
	}{
		{loader.DropH2cUnusedFrame.Set, uint32(0)}, {loader.SkipH2cDataPayload.Set, uint32(1)},
		{loader.BatchH2cRecords.Set, uint32(1)}, {loader.BootTimeUnixNs.Set, uint64(host.BootTime.UnixNano())},
	} {
		if err := v.set(v.value); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = loader.SkipH2cDataPayload.Set(uint32(0)) }()
	defer func() { _ = loader.BatchH2cRecords.Set(uint32(0)) }()
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)

	stop, err := common.StartH2CBatchKick(loader)
	if err != nil {
		t.Fatalf("start the kick: %v", err)
	}
	defer stop()
	var kickFd uint32
	if err := loader.BatchKickFd.Get(&kickFd); err != nil || kickFd == 0 {
		t.Fatalf("kick fd %d: %v", kickFd, err)
	}

	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	type arrival struct {
		event *aclevents.SocketDataUploadEvent
		at    time.Time
		batch bool
	}
	var mu sync.Mutex
	var arrivals []arrival
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			record, err := reader.Read()
			if err != nil {
				return
			}
			if len(record.RawSample) == 0 {
				continue
			}
			now := time.Now()
			mu.Lock()
			if aclevents.IsBatchRecord(record.RawSample) {
				for i := 0; i < aclevents.BatchRecordCount(record.RawSample); i++ {
					e := &aclevents.SocketDataUploadEvent{}
					if aclevents.DecodeBatchRecordInto(e, record.RawSample, i, nil) {
						arrivals = append(arrivals, arrival{e, now, true})
					}
				}
			} else {
				e := &aclevents.SocketDataUploadEvent{}
				e.ReadFrom(btf.NewReader(record.RawSample))
				arrivals = append(arrivals, arrival{e, now, false})
			}
			mu.Unlock()
		}
	}()

	run := &h2cKernelRun{skip: true}
	var lastRequest, closeAt time.Time
	h2cIdleTraffic(t, run, 6, 256*1024, &lastRequest, &closeAt)
	time.Sleep(2 * time.Second)
	_ = reader.Close()
	<-done

	ports := map[uint16]*h2cKernelConn{}
	for _, conn := range run.conns {
		ports[conn.port] = conn
	}
	pipeConID := uint64(os.Getpid())<<32 | uint64(kickFd)
	var latestBatch time.Time
	batched := 0
	for _, a := range arrivals {
		if a.event.ConnectionID == pipeConID {
			t.Fatalf("the kick write was recorded as traffic: %+v", *a.event.Detach())
		}
		conn := ports[a.event.LocalPort]
		if conn == nil || a.event.Protocol0 != enums.ConnectionProtocolHTTP2 {
			continue
		}
		conn.events[a.event.Direction0] = append(conn.events[a.event.Direction0], a.event)
		if a.batch {
			batched++
			if a.at.After(latestBatch) {
				latestBatch = a.at
			}
			if !a.at.Before(closeAt) {
				t.Fatalf("a record arrived only with the close (%s after the last request): the kick did not flush it",
					a.at.Sub(lastRequest))
			}
		}
	}
	if batched == 0 {
		t.Fatalf("no batched records")
	}
	if wait := latestBatch.Sub(lastRequest); wait > 2500*time.Millisecond {
		t.Fatalf("the last batch arrived %s after the last request, the kick should flush within about 2s", wait)
	}
	for _, conn := range run.conns {
		for d := range conn.events {
			ev := conn.events[d]
			sort.SliceStable(ev, func(i, j int) bool { return h2cUploadBefore(ev[i], ev[j]) })
		}
		checkPrevDataIDs(t, conn)
		checkSkippedCalls(t, conn)
	}
	t.Logf("%d batched records, the last one %s after the last request (the connection closed %s after it)",
		batched, latestBatch.Sub(lastRequest).Round(time.Millisecond), closeAt.Sub(lastRequest).Round(time.Millisecond))
}

// h2cIdleTraffic makes `requests` POSTs of `body` bytes both ways over one h2c connection, records the time
// the last one completed, keeps the connection open and idle for 3s, then closes it and records that time
func h2cIdleTraffic(t *testing.T, run *h2cKernelRun, requests, body int, lastRequest, closeAt *time.Time) {
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
		//nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
		server := &http2.Server{MaxUploadBufferPerConnection: 4 << 20, MaxUploadBufferPerStream: 1 << 20}
		server.ServeConn(run.record(raw, "server", false), &http2.ServeConnOpts{ //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write(payload)
			}),
		})
	}()
	transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) { //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return run.record(raw, "client", true), nil
	}}
	client := &http.Client{Transport: transport}
	for i := 0; i < requests; i++ {
		resp, err := client.Post(fmt.Sprintf("http://%s/idle/%d", listener.Addr(), i), "application/octet-stream",
			bytes.NewReader(bytes.Repeat([]byte{'q'}, body)))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	*lastRequest = time.Now()
	time.Sleep(3 * time.Second)
	*closeAt = time.Now()
	transport.CloseIdleConnections() //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
}

// TestH2CBatchProductionReader runs the production read path end to end: the btf reader of the socket
// data queue with the batch splitter the agent registers (aclevents.SplitH2CBatch), the production supplier
// (the memory protection admission and the pooled event) and the production idle kick, over interleaved
// many-stream traffic. Every connection's events must be complete and byte-identical in analysis to the same
// calls uploaded in whole, and the reader must have split batches.
func TestH2CBatchProductionReader(t *testing.T) { //nolint:funlen // one scenario whose steps share the loaded BPF and the state of the run
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
		{loader.DropH2cUnusedFrame.Set, uint32(0)}, {loader.SkipH2cDataPayload.Set, uint32(1)},
		{loader.BatchH2cRecords.Set, uint32(1)}, {loader.BootTimeUnixNs.Set, uint64(host.BootTime.UnixNano())},
	} {
		if err := v.set(v.value); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = loader.SkipH2cDataPayload.Set(uint32(0)) }()
	defer func() { _ = loader.BatchH2cRecords.Set(uint32(0)) }()
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	stop, err := common.StartH2CBatchKick(loader)
	if err != nil {
		t.Fatalf("start the kick: %v", err)
	}
	defer stop()

	mapName := loader.SocketDataUploadQueue.String()
	btf.SetBatchSampleSplitter(mapName, aclevents.SplitH2CBatch)
	defer btf.SetBatchSampleSplitter(mapName, nil)
	before := aclevents.H2CBatchesSeen()

	var mu sync.Mutex
	var events []*aclevents.SocketDataUploadEvent
	linker := btf.NewLinker()
	linker.ReadEventAsyncWithBufferSize(loader.SocketDataUploadQueue, func(data interface{}) {
		var e *aclevents.SocketDataUploadEvent
		switch d := data.(type) {
		case *aclevents.H2CRecord:
			// a batch record: the event it stands for, with its cut bytes
			e = aclevents.DetachRecord(d)
			if b := d.BufferData(); b != nil {
				e.Buffer = append([]byte(nil), b...)
			}
			d.ReleaseBuffer()
		default:
			e = data.(*aclevents.SocketDataUploadEvent)
		}
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}, 64<<20, 1, func() interface{} {
		if !buffer.AcquireEvent() {
			return nil
		}
		return aclevents.AcquireUploadEvent()
	})

	run := &h2cKernelRun{skip: true}
	// deterministic request/response first (compared strictly), then interleaved many-stream traffic
	goH2CBodyTraffic(t, run, 8, 256*1024, 256*1024)
	run.mu.Lock()
	sequential := len(run.conns)
	run.mu.Unlock()
	goH2CManyStreams(t, run, 64, 8, 256*1024)
	// the kick flushes what the connections left in the per-CPU batches
	for last := -1; ; {
		time.Sleep(1500 * time.Millisecond)
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n == last {
			break
		}
		last = n
	}
	_ = linker.Close()

	split := aclevents.H2CBatchesSeen() - before
	if split == 0 {
		t.Fatalf("the production reader split no batches")
	}
	mu.Lock()
	defer mu.Unlock()
	for i, conn := range run.conns {
		strict := i < sequential
		for _, e := range events {
			if e.LocalPort == conn.port && e.Protocol0 == enums.ConnectionProtocolHTTP2 {
				conn.events[e.Direction0] = append(conn.events[e.Direction0], e)
			}
		}
		if len(conn.events[enums.SocketDataDirectionIngress])+len(conn.events[enums.SocketDataDirectionEgress]) == 0 {
			continue
		}
		for d := range conn.events {
			ev := conn.events[d]
			sort.SliceStable(ev, func(i, j int) bool { return h2cUploadBefore(ev[i], ev[j]) })
		}
		checkPrevDataIDs(t, conn)
		checkSkippedCalls(t, conn)
		compareWithFullReconstruction(t, conn, strict)
	}
	t.Logf("the production reader split %d batches; %d events delivered", split, len(events))
}
