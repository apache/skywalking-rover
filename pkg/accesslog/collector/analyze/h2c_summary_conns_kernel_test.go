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
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// h2cSideCounts is what BPF uploaded of the connections of one side (client: the connect side), per direction
type h2cSideCounts struct {
	events, payload, records, cut [3]int64
}

// h2cManyConnsRun runs `conns` h2c connections at once (Go client and server, both observed), each with
// `requests` requests of 8 streams and 256KB both ways, with the production switches (drop, skip, batch) and
// the summaries as given, and counts by side and direction the full events, the ones that carry more than 1KB
// of data (payload uploaded in full), and the batch records
func h2cManyConnsRun(t *testing.T, summarize, late bool, conns, requests int) (client, server h2cSideCounts,
	lost uint64) {
	t.Helper()
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	b := uint32(0)
	if summarize {
		b = 1
	}
	for _, v := range []struct {
		set   func(interface{}) error
		value interface{}
	}{
		{loader.DropH2cUnusedFrame.Set, uint32(1)}, {loader.SkipH2cDataPayload.Set, uint32(1)},
		{loader.BatchH2cRecords.Set, uint32(1)}, {loader.SummarizeH2cPayload.Set, b},
		{loader.BootTimeUnixNs.Set, uint64(host.BootTime.UnixNano())},
	} {
		if err := v.set(v.value); err != nil {
			t.Fatal(err)
		}
	}
	defer loader.SummarizeH2cPayload.Set(uint32(0))
	defer loader.BatchH2cRecords.Set(uint32(0))
	defer loader.SkipH2cDataPayload.Set(uint32(0))
	defer loader.DropH2cUnusedFrame.Set(uint32(0))
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	h2cClearMap(t, loader.H2cSumMap)
	stopKick, err := common.StartH2CBatchKick(loader)
	if err != nil {
		t.Fatalf("start the kick: %v", err)
	}
	defer stopKick()
	manager := NewH2CSummaries(loader.H2cSumMap, loader.H2cSumEpochMap, loader.ActiveConnectionMap,
		func(*events.H2CSummary) {})
	stopFlush := make(chan struct{})
	if summarize {
		go func() {
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
	}

	type seen struct {
		port      uint16
		direction enums.SocketDataDirection
		dataLen   uint16
		record    bool
	}
	var mu sync.Mutex
	var all []seen
	var lostSamples, received atomic.Uint64
	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 16<<20)
	if err != nil {
		t.Fatalf("perf reader: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var local []seen
		for {
			record, err := reader.Read()
			if err != nil {
				mu.Lock()
				all = append(all, local...)
				mu.Unlock()
				return
			}
			lostSamples.Add(record.LostSamples)
			received.Add(1)
			if len(record.RawSample) == 0 {
				continue
			}
			if events.IsBatchRecord(record.RawSample) {
				n := events.BatchRecordCount(record.RawSample)
				for i := 0; i < n; i++ {
					var e events.SocketDataUploadEvent
					if events.DecodeBatchRecordInto(&e, record.RawSample, i, nil) {
						local = append(local, seen{e.LocalPort, e.Direction0, e.DataLen, true})
					}
				}
				continue
			}
			var e events.SocketDataUploadEvent
			e.ReadFrom(btf.NewReader(record.RawSample))
			if e.Protocol0 == enums.ConnectionProtocolHTTP2 && e.Sequence0 == 0 {
				local = append(local, seen{e.LocalPort, e.Direction0, e.DataLen, false})
			}
			e.ReleaseBuffer()
		}
	}()

	sides := h2cClusterTraffic(t, loader, conns, requests, late)
	for {
		before := received.Load()
		time.Sleep(1500 * time.Millisecond)
		if received.Load() == before {
			break
		}
	}
	close(stopFlush)
	_ = reader.Close()
	<-done
	for _, s := range all {
		isClient, ok := sides[s.port]
		if !ok || (s.direction != enums.SocketDataDirectionIngress && s.direction != enums.SocketDataDirectionEgress) {
			continue
		}
		side := &server
		if isClient {
			side = &client
		}
		if s.record {
			side.records[s.direction]++
			if s.dataLen > 0 {
				side.cut[s.direction]++
			}
			continue
		}
		side.events[s.direction]++
		if s.dataLen > 1024 {
			side.payload[s.direction]++
		}
	}
	return client, server, lostSamples.Load()
}

// TestH2CSummaryManyConns is the cluster cell in small: hundreds of h2c connections at once, client and
// server observed, with the summaries off and on. With them on, no side may upload more DATA payload in full
// than with them off.
func TestH2CSummaryManyConns(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	conns, requests := 200, 8
	type result struct {
		client, server h2cSideCounts
		lost           uint64
	}
	var results [2]result
	for i, summarize := range []bool{false, true} {
		c, s, l := h2cManyConnsRun(t, summarize, false, conns, requests)
		results[i] = result{c, s, l}
		t.Logf("summaries=%t: %d conns x %d requests, lost samples %d", summarize, conns, requests, l)
		for _, side := range []struct {
			name string
			c    h2cSideCounts
		}{{"client", c}, {"server", s}} {
			t.Logf("  %s: ingress %d events (%d with >1KB of data), %d records (%d cut); egress %d events (%d with >1KB), %d records (%d cut)",
				side.name, side.c.events[1], side.c.payload[1], side.c.records[1], side.c.cut[1], side.c.events[2],
				side.c.payload[2], side.c.records[2], side.c.cut[2])
		}
	}
	off, on := results[0], results[1]
	for _, side := range []struct {
		name    string
		off, on h2cSideCounts
	}{{"client", off.client, on.client}, {"server", off.server, on.server}} {
		for d := 1; d <= 2; d++ {
			if side.on.payload[d] > side.off.payload[d]*2+100 {
				t.Errorf("%s direction %d: %d events with payload uploaded in full with the summaries, %d without",
					side.name, d, side.on.payload[d], side.off.payload[d])
			}
		}
	}
}

// h2cClusterTraffic is the stress client and server of the cluster cell in small: `conns` connections of Go's
// x/net http2 transport, 8 workers each posting 256KB and reading 256KB answered after 50ms by Go's http2
// server, `requests` requests per worker. With late, the connections are opened before the test process is
// monitored (as when the agent discovers the pod after the client connected) and it is monitored once the
// traffic runs. It returns the local ports of the connections: true for the client side.
func h2cClusterTraffic(t *testing.T, loader *bpf.Loader, conns, requests int, late bool) map[uint16]bool {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	sides := map[uint16]bool{}
	note := func(c net.Conn, client bool) {
		mu.Lock()
		sides[uint16(c.LocalAddr().(*net.TCPAddr).Port)] = client
		mu.Unlock()
	}
	// the stress server (test/stress/server): net/http with h2c.NewHandler (prior knowledge), the body read
	// with a 64KB buffer, a Content-Length response after the delay
	payload := bytes.Repeat([]byte{'r'}, 256*1024)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64<<10)
		_, _ = io.CopyBuffer(io.Discard, r.Body, buf)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	srv := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{MaxConcurrentStreams: 1024})}
	go func() { _ = srv.Serve(&notingListener{Listener: listener, note: note}) }()
	defer srv.Close()
	pid := uint32(os.Getpid())
	if late {
		_ = loader.UnmonitorProcess(pid)
	}
	body := bytes.Repeat([]byte{'q'}, 256*1024)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for c := 0; c < conns; c++ {
		tr := &http2.Transport{AllowHTTP: true, DisableCompression: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err == nil {
					note(raw, true)
				}
				return raw, err
			}}
		client := &http.Client{Transport: tr}
		// the connection is made with the first request
		resp, err := client.Get(fmt.Sprintf("http://%s/warm", listener.Addr()))
		if err != nil {
			t.Fatalf("warm up: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		for s := 0; s < 8; s++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				discard := make([]byte, 64<<10)
				<-start
				for i := 0; i < requests; i++ {
					req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/s", listener.Addr()), bytes.NewReader(body))
					req.ContentLength = int64(len(body))
					req.Header.Set("Content-Type", "application/octet-stream")
					resp, err := client.Do(req)
					if err != nil {
						continue
					}
					_, _ = io.CopyBuffer(io.Discard, resp.Body, discard)
					_ = resp.Body.Close()
				}
			}()
		}
		defer tr.CloseIdleConnections()
	}
	close(start)
	if late {
		time.Sleep(200 * time.Millisecond)
		if err := loader.MonitorProcess(pid); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	return sides
}

// notingListener notes the local port of every accepted connection
type notingListener struct {
	net.Listener
	note func(c net.Conn, client bool)
}

func (l *notingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.note(c, false)
	}
	return c, err
}
