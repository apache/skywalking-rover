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
	"encoding/binary"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// Kernel tests of two BPF changes besides the runs: the upload of a call made with many iov entries
// (upload_socket_data_iov in skywalking-rover/bpf/include/socket_data.h), and the h2c upgrade (h2c_upgrade in
// syscalls/h2c.h).

// h2cTimedEvent is an event the reader decoded (a batch record as the event it stands for), with when it arrived
type h2cTimedEvent struct {
	event   *aclevents.SocketDataUploadEvent
	arrived time.Time
	record  bool
}

// h2cBPFSwitches are the switches a run sets (and resets after it)
type h2cBPFSwitches struct {
	drop, skip, batch, summarize, skipHTTP1 uint32
}

// withH2CEvents loads the access log BPF with the switches, runs the traffic and returns every event of the socket
// data queue it decoded, with its arrival time
func withH2CEvents(t *testing.T, sw h2cBPFSwitches, traffic func()) []h2cTimedEvent {
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
	for _, v := range []struct {
		v     *ebpf.Variable
		value uint32
	}{{loader.DropH2cUnusedFrame, sw.drop}, {loader.SkipH2cDataPayload, sw.skip}, {loader.BatchH2cRecords, sw.batch},
		{loader.SummarizeH2cPayload, sw.summarize}, {loader.SkipHttp1BodyPayload, sw.skipHTTP1}} {
		set(v.v, v.value)
		defer set(v.v, uint32(0))
	}
	set(loader.BootTimeUnixNs, uint64(host.BootTime.UnixNano()))
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)

	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 64<<20)
	if err != nil {
		t.Fatalf("perf reader: %v", err)
	}
	var mu sync.Mutex
	var events []h2cTimedEvent
	var received int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			record, err := reader.Read()
			if err != nil {
				return
			}
			now := time.Now()
			if record.LostSamples > 0 {
				t.Errorf("%d perf samples lost", record.LostSamples)
			}
			mu.Lock()
			received++
			if aclevents.IsBatchRecord(record.RawSample) {
				for i := 0; i < aclevents.BatchRecordCount(record.RawSample); i++ {
					if _, ok := aclevents.DecodeBatchSummary(record.RawSample, i); ok {
						continue
					}
					e := &aclevents.SocketDataUploadEvent{}
					if aclevents.DecodeBatchRecordInto(e, record.RawSample, i, nil) {
						events = append(events, h2cTimedEvent{event: e, arrived: now, record: true})
					}
				}
			} else if len(record.RawSample) > 0 {
				e := &aclevents.SocketDataUploadEvent{}
				e.ReadFrom(btf.NewReader(record.RawSample))
				events = append(events, h2cTimedEvent{event: e, arrived: now})
			}
			mu.Unlock()
		}
	}()
	var stopKick func()
	if sw.batch != 0 {
		if stopKick, err = common.StartH2CBatchKick(loader); err != nil {
			t.Fatalf("start the kick: %v", err)
		}
	}
	traffic()
	for {
		mu.Lock()
		n := received
		mu.Unlock()
		time.Sleep(1500 * time.Millisecond)
		mu.Lock()
		quiet := n == received
		mu.Unlock()
		if quiet {
			break
		}
	}
	if stopKick != nil {
		stopKick()
	}
	_ = reader.Close()
	<-done
	return events
}

// h2cEventsOf is the events of the connection of the local port in the direction, in the order of their data ids
func h2cEventsOf(events []h2cTimedEvent, port uint16, d enums.SocketDataDirection) []h2cTimedEvent {
	var result []h2cTimedEvent
	for _, e := range events {
		if e.event.LocalPort == port && e.event.Direction0 == d {
			result = append(result, e)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return h2cUploadBefore(result[i].event, result[j].event) })
	return result
}

// h2cTCPPair is a connected pair of TCP connections over the loopback, accepted and dialed while the BPF programs are
// attached, so they are followed
func h2cTCPPair(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := listener.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	return s.(*net.TCPConn), c.(*net.TCPConn)
}

// h2cFrame is one HTTP/2 frame
func h2cFrame(typ http2.FrameType, flags http2.Flags, stream uint32, payload []byte) []byte {
	h := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), byte(typ), byte(flags), 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[5:], stream)
	return append(h, payload...)
}

// onCPU runs f on a thread pinned to the CPU
func onCPU(t *testing.T, cpu int, f func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// the thread stays locked: it ends with the goroutine, so no other goroutine runs pinned to the CPU
		runtime.LockOSThread()
		var set unix.CPUSet
		set.Set(cpu)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			t.Errorf("pin to CPU %d: %v", cpu, err)
			return
		}
		f()
	}()
	<-done
}

// TestH2CIovEntries writes one call with writev of 12 iov entries, a HEADERS frame in entries 8 and 9 (behind
// the first 6, which is all a call made with an iov uploaded before): every byte of the call is uploaded, and the
// follower never says the call holds no header block
func TestH2CIovEntries(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	var port uint16
	var written []byte
	events := withH2CEvents(t, h2cBPFSwitches{drop: 1, skip: 1, batch: 1}, func() {
		server, client := h2cTCPPair(t)
		defer server.Close()
		defer client.Close()
		port = uint16(server.LocalAddr().(*net.TCPAddr).Port)
		go func() { _, _ = io.Copy(io.Discard, client) }()
		preface := append([]byte(http2.ClientPreface), h2cFrame(http2.FrameSettings, 0, 0, nil)...)
		_, _ = client.Write(preface)
		_, _ = io.ReadFull(server, make([]byte, len(preface)))
		_, _ = server.Write(h2cFrame(http2.FrameSettings, 0, 0, nil))
		var entries net.Buffers
		for i := 0; i < 3; i++ {
			frame := h2cFrame(http2.FrameData, 0, 1, bytes.Repeat([]byte{byte('a' + i)}, 100))
			entries = append(entries, frame[:9], frame[9:])
		}
		// a window update in entry 7, the HEADERS frame header in entry 8, its block in 9, two more DATA frames
		entries = append(entries, h2cFrame(http2.FrameWindowUpdate, 0, 0, []byte{0, 0, 0x10, 0}))
		headers := h2cFrame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 3, []byte{0x88, 0x5f, 0x87, 0x49, 0x7c, 0xa5, 0x8a, 0xe8, 0x19, 0xaa})
		entries = append(entries, headers[:9], headers[9:])
		last := h2cFrame(http2.FrameData, http2.FlagDataEndStream, 3, bytes.Repeat([]byte{'z'}, 50))
		entries = append(entries, last[:9], last[9:], h2cFrame(http2.FrameData, 0, 1, []byte("tail")))
		for _, e := range entries {
			written = append(written, e...)
		}
		if n, err := entries.WriteTo(server); err != nil || n != int64(len(written)) {
			t.Fatalf("writev: %d %v", n, err)
		}
		time.Sleep(50 * time.Millisecond)
	})
	var uploaded []byte
	var call *aclevents.SocketDataUploadEvent
	for _, e := range h2cEventsOf(events, port, enums.SocketDataDirectionEgress) {
		if e.event.TotalSize0 == uint64(len(written)) {
			if call == nil {
				call = e.event
			}
			uploaded = append(uploaded, e.event.BufferData()...)
		}
	}
	if call == nil {
		t.Fatalf("the call of %d bytes was not uploaded", len(written))
	}
	if !bytes.Equal(uploaded, written) {
		t.Fatalf("%d of %d bytes uploaded", len(uploaded), len(written))
	}
	// the follower reads the frames of a call from its first entry only: it cannot tell where they are behind it, and
	// never says the call holds no header block
	if flags, off, _ := buffer.H2CFramesOf(call); flags&buffer.H2CFramesNoHeaderBlock != 0 {
		t.Fatalf("the frames of the call: flags %d, first frame at %d", flags, off)
	}
}

// TestH2CUpgrade is an HTTP/1.1 connection that switches to h2c (RFC 7540 3.2): the request goes as HTTP/1, the
// call of the 101 response and every call behind it as HTTP/2 both ways, and the follower starts over: it takes the
// head of the 101 for a frame it steps over, the client preface sets the direction of the requests, and a DATA frame
// of the response is cut behind its header as on any followed h2c connection. A 101 to a WebSocket stays HTTP/1.
func TestH2CUpgrade(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	var serverPort, clientPort uint16
	request := "GET / HTTP/1.1\r\nHost: upgrade\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" +
		"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n"
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
	events := withH2CEvents(t, h2cBPFSwitches{drop: 1, skip: 1, batch: 1, skipHTTP1: 1}, func() {
		server, client := h2cTCPPair(t)
		defer server.Close()
		defer client.Close()
		serverPort = uint16(server.LocalAddr().(*net.TCPAddr).Port)
		clientPort = uint16(client.LocalAddr().(*net.TCPAddr).Port)
		_, _ = client.Write([]byte(request))
		_, _ = io.ReadFull(server, make([]byte, len(request)))
		_, _ = server.Write([]byte(response))
		_, _ = io.ReadFull(client, make([]byte, len(response)))
		preface := append([]byte(http2.ClientPreface), h2cFrame(http2.FrameSettings, 0, 0, nil)...)
		_, _ = client.Write(preface)
		_, _ = io.ReadFull(server, make([]byte, len(preface)))
		replies := [][]byte{h2cFrame(http2.FrameSettings, 0, 0, nil),
			h2cFrame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 1, []byte{0x88}),
			h2cFrame(http2.FrameData, 0, 1, bytes.Repeat([]byte{'d'}, 16384)),
			h2cFrame(http2.FrameData, http2.FlagDataEndStream, 1, []byte("end"))}
		for _, r := range replies {
			_, _ = server.Write(r)
			_, _ = io.ReadFull(client, make([]byte, len(r)))
		}
		time.Sleep(50 * time.Millisecond)
	})
	// both ends switch: every call of each side behind the 101 is HTTP/2 (checked below, per side)
	for _, side := range []struct {
		name string
		port uint16
	}{{"server", serverPort}, {"client", clientPort}} {
		var all []h2cTimedEvent
		for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
			all = append(all, h2cEventsOf(events, side.port, d)...)
		}
		sort.SliceStable(all, func(i, j int) bool { return h2cUploadBefore(all[i].event, all[j].event) })
		switched, cut, upgradeRequest := false, false, false
		for _, e := range all {
			if e.event.Sequence0 != 0 {
				continue
			}
			http1 := bytes.HasPrefix(e.event.BufferData(), []byte("GET "))
			switch {
			case http1 && (switched || e.event.Protocol0 != enums.ConnectionProtocolHTTP):
				t.Fatalf("%s: the HTTP/1 call %q as protocol %d", side.name, e.event.BufferData(), e.event.Protocol0)
			case http1:
				upgradeRequest = upgradeRequest || (string(e.event.BufferData()) == request && e.event.TotalSize0 == uint64(len(request)))
			case e.event.Protocol0 != enums.ConnectionProtocolHTTP2:
				t.Fatalf("%s: a call behind the 101 (%d bytes) as protocol %d", side.name, e.event.TotalSize0, e.event.Protocol0)
			default:
				switched = true
				cut = cut || (e.event.HaveReduce == 1 && e.event.TotalSize0 == 16393 && e.event.DataLen == 9)
			}
		}
		if !upgradeRequest {
			t.Fatalf("%s: the HTTP/1.1 upgrade request is not uploaded as its bytes", side.name)
		}
		if !switched {
			t.Fatalf("%s: no call behind the 101", side.name)
		}
		if side.name == "server" && !cut {
			for _, e := range all {
				f, off, _ := buffer.H2CFramesOf(e.event)
				t.Logf("server %s data id %d: %d bytes, protocol %d, cut %d, data %d, skipped %d, frames %d/%d, record %t",
					directionName(e.event.Direction0), e.event.DataID0, e.event.TotalSize0, e.event.Protocol0,
					e.event.HaveReduce, e.event.DataLen, e.event.PayloadSkipped0, f, off, e.record)
			}
			t.Fatalf("the server's DATA frame behind the upgrade was not cut: the follower did not start over")
		}
	}
}

// TestH2CUpgradeWebSocket is a 101 to a WebSocket: the connection stays HTTP/1
func TestH2CUpgradeWebSocket(t *testing.T) {
	requireBPF(t)
	var serverPort, clientPort uint16
	request := "GET /ws HTTP/1.1\r\nHost: ws\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
	events := withH2CEvents(t, h2cBPFSwitches{drop: 1, skip: 1, batch: 1, skipHTTP1: 1}, func() {
		server, client := h2cTCPPair(t)
		defer server.Close()
		defer client.Close()
		serverPort = uint16(server.LocalAddr().(*net.TCPAddr).Port)
		clientPort = uint16(client.LocalAddr().(*net.TCPAddr).Port)
		_, _ = client.Write([]byte(request))
		_, _ = io.ReadFull(server, make([]byte, len(request)))
		_, _ = server.Write([]byte(response))
		_, _ = io.ReadFull(client, make([]byte, len(response)))
		_, _ = server.Write([]byte{0x81, 0x02, 'h', 'i'})
		_, _ = io.ReadFull(client, make([]byte, 4))
		time.Sleep(50 * time.Millisecond)
	})
	// neither end switches: no call of either side, either direction, is HTTP/2, and the frame behind the 101 is seen
	seen := 0
	for _, port := range []uint16{serverPort, clientPort} {
		for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
			for _, e := range h2cEventsOf(events, port, d) {
				seen++
				if e.event.Protocol0 == enums.ConnectionProtocolHTTP2 {
					t.Fatalf("a call of the WebSocket connection (%d bytes) as HTTP/2", e.event.TotalSize0)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatalf("no call of the WebSocket connection")
	}
}

// h2cChainForks counts, over the uploads of a connection (the first event of each call, both directions), the
// previous data ids named by more than one upload (a fork of the chain) and the uploads no other names (but the
// last): what the user space links by
func h2cChainForks(conn *h2cKernelConn) (uploads, forks, unnamed int) {
	named := map[uint64]int{}
	ids := map[uint64]bool{}
	var last uint64
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		for _, e := range conn.events[d] {
			if e.Sequence0 != 0 || ids[e.DataID0] {
				continue
			}
			ids[e.DataID0] = true
			named[e.PrevDataID0]++
			last = max(last, e.DataID0)
		}
	}
	for _, n := range named {
		if n > 1 {
			forks += n - 1
		}
	}
	for id := range ids {
		if named[id] == 0 && id != last {
			unnamed++
		}
	}
	return len(ids), forks, unnamed
}

// TestH2CUploadChain runs real Go h2c endpoints with large bodies both ways and 8 streams at once, so a read and
// a write of one connection are often made at once on two CPUs, with the production switches, and counts the forks
// of the chain of the uploads: two uploads that name the same previous one (socket_data_chain_upload in
// skywalking-rover/bpf/include/socket_data.h). With the claims there are none.
func TestH2CUploadChain(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	run, _, _ := withAccessLogSummary(t, true, true, func(run *h2cKernelRun) {
		var wg sync.WaitGroup
		for c := 0; c < 4; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				goH2CManyStreams(t, run, 64, 8, 256*1024)
			}()
		}
		wg.Wait()
	})
	total, forks, unnamed := 0, 0, 0
	for _, conn := range run.conns {
		u, f, n := h2cChainForks(conn)
		total, forks, unnamed = total+u, forks+f, unnamed+n
		if f > 0 || n > 0 {
			t.Logf("%s: %d uploads, %d forks of the chain, %d uploads no other names", conn.name, u, f, n)
		}
	}
	t.Logf("%d connections, %d uploads: %d forks of the chain, %d uploads no other names", len(run.conns), total, forks, unnamed)
	if total == 0 {
		t.Fatalf("no upload")
	}
	if forks > 0 {
		t.Fatalf("%d uploads name a previous upload another one names", forks)
	}
}

// TestSocketDataLastIDAdvances writes 300 calls one after the other on one followed h2c connection and reads
// socket_data_last_id_map before the close: the entry, stored in place after its first upload
// (socket_data_store_last in skywalking-rover/bpf/include/socket_data.h), names the last upload, and every upload
// names the one before it
func TestSocketDataLastIDAdvances(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	var last struct {
		RandomID uint64
		DataID   uint64
	}
	events := withH2CEvents(t, h2cBPFSwitches{drop: 1, skip: 1}, func() {
		server, client := h2cTCPPair(t)
		defer server.Close()
		defer client.Close()
		port = uint16(server.LocalAddr().(*net.TCPAddr).Port)
		go func() { _, _ = io.Copy(io.Discard, client) }()
		preface := append([]byte(http2.ClientPreface), h2cFrame(http2.FrameSettings, 0, 0, nil)...)
		_, _ = client.Write(preface)
		_, _ = io.ReadFull(server, make([]byte, len(preface)))
		for i := 0; i < 300; i++ {
			_, _ = server.Write(h2cFrame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, uint32(1+2*i), []byte{0x88}))
		}
		time.Sleep(50 * time.Millisecond)
		raw, err := server.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.Control(func(fd uintptr) {
			conid := uint64(os.Getpid())<<32 | uint64(fd)
			if err := loader.SocketDataLastIdMap.Lookup(conid, &last); err != nil {
				t.Errorf("the last upload of the connection: %v", err)
			}
		})
	})
	var ids []uint64
	prevOf := map[uint64]uint64{}
	for _, e := range h2cEventsOf(events, port, enums.SocketDataDirectionEgress) {
		if e.event.Sequence0 == 0 {
			ids = append(ids, e.event.DataID0)
			prevOf[e.event.DataID0] = e.event.PrevDataID0
		}
	}
	for _, e := range h2cEventsOf(events, port, enums.SocketDataDirectionIngress) {
		if e.event.Sequence0 == 0 {
			ids = append(ids, e.event.DataID0)
			prevOf[e.event.DataID0] = e.event.PrevDataID0
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) < 300 {
		t.Fatalf("%d uploads", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if prevOf[ids[i]] != ids[i-1] {
			t.Fatalf("upload %d names %d, the upload before it is %d", ids[i], prevOf[ids[i]], ids[i-1])
		}
	}
	if last.DataID != ids[len(ids)-1] {
		t.Fatalf("the last upload of the connection is %d in the map, %d uploaded", last.DataID, ids[len(ids)-1])
	}
}
