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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The tests below attach the access log BPF programs to this process (the event layout of
// bpf/accesslog/include) and check what they upload against the
// bytes the endpoints really read and wrote. They need root and are skipped otherwise. How the frames
// are followed through a peek and frames forged into payloads and header blocks is in
// h2c_follower_kernel_test.go (TestH2CPeek, TestH2CForgedFrames); these tests cover the event of the
// layout: it carries the details of the call (function name, L4 counters, ports), also on the held
// frame header the BPF side uploads after all, and the analyzer reports the same access logs with
// access_log.protocol_analyze.drop_h2c_unused_frame on.

// TestH2CDropUnusedFramesEvents runs the h2c traffic of Go's client and server with the dropping off
// and on: every uploaded stream is the real one, minus whole droppable frames when on, and every
// event carries the details of its own socket call.
func TestH2CDropUnusedFramesEvents(t *testing.T) {
	requireBPF(t)
	const requests = 8
	for _, drop := range []bool{false, true} {
		run := withAccessLogBPF(t, drop, func(run *h2cKernelRun) { goH2CTraffic(t, run, requests) })
		uploaded := verifyKernelRun(t, run)
		t.Logf("drop=%t: %d socket data events uploaded for %d requests", drop, uploaded, requests)
	}
}

// TestH2CDropUnusedFramesAccessLogs sends requests from a raw client between control frames that are
// dropped, with the server reading every frame the way Go's x/net framer does, and requires the access
// logs of the analyzer over the uploaded events to be the same with the dropping off and on.
func TestH2CDropUnusedFramesAccessLogs(t *testing.T) {
	requireBPF(t)
	var logs [2][]string
	for i, drop := range []bool{false, true} {
		run := withAccessLogBPF(t, drop, func(run *h2cKernelRun) { requestTraffic(t, run) })
		verifyKernelRun(t, run)
		server := run.conns[0]
		for _, p := range analyzeKernelConn(t, server).protocolLogs {
			h := p.GetHttp()
			logs[i] = append(logs[i], fmt.Sprintf("%s %s req=%d/%d status=%d resp=%d/%d", h.GetRequest().GetMethod(),
				h.GetRequest().GetPath(), h.GetRequest().GetSizeOfHeadersBytes(), h.GetRequest().GetSizeOfBodyBytes(),
				h.GetResponse().GetStatusCode(), h.GetResponse().GetSizeOfHeadersBytes(), h.GetResponse().GetSizeOfBodyBytes()))
		}
		t.Logf("drop=%t: %d socket calls, %d uploads of the server ingress: %v", drop, len(server.calls[enums.SocketDataDirectionIngress]),
			len(server.events[enums.SocketDataDirectionIngress]), logs[i])
		if drop && len(server.events[enums.SocketDataDirectionIngress]) >= len(server.calls[enums.SocketDataDirectionIngress]) {
			t.Fatalf("no socket call of the server ingress was dropped")
		}
	}
	if len(logs[0]) != 2 {
		t.Fatalf("expected 2 access logs, got %v", logs[0])
	}
	if fmt.Sprint(logs[0]) != fmt.Sprint(logs[1]) {
		t.Fatalf("the access logs differ: off %v, on %v", logs[0], logs[1])
	}
}

// TestH2CHeldHeaderEvent reads frame headers on their own and then follows them with calls that are
// their payload, that are a part of it, or that run past it. Twice the next call is not the payload,
// and the BPF side uploads the held header after all: as the event of its own socket call, with the
// function name, the L4 counters and the ports of that call.
func TestH2CHeldHeaderEvent(t *testing.T) {
	requireBPF(t)
	for _, drop := range []bool{false, true} {
		run := withAccessLogBPF(t, drop, func(run *h2cKernelRun) { splitReadTraffic(t, run) })
		verifyKernelRun(t, run)
		server := run.conns[0]
		// the uploaded lone headers of droppable frames: with the dropping on, the held headers
		var held []*aclevents.SocketDataUploadEvent
		for _, e := range server.events[enums.SocketDataDirectionIngress] {
			if e.DataLen == 9 && h2cControlPayloadLen(e.BufferData()) > 0 {
				held = append(held, e)
			}
		}
		// the payload read in two parts, and the payload read together with the next frame
		if drop && len(held) != 2 {
			t.Fatalf("%d held headers uploaded after all, expected 2", len(held))
		}
		for _, e := range held {
			if e.TotalSize0 != 9 || e.Finished != 1 || e.Sequence0 != 0 || e.L4PackageCount == 0 || e.L4TotalPackageSize == 0 {
				t.Fatalf("the held header %d does not carry its own socket call: %+v", e.DataID0, *e.Detach())
			}
		}
		t.Logf("drop=%t: %d socket calls, %d uploads of the server ingress", drop,
			len(server.calls[enums.SocketDataDirectionIngress]), len(server.events[enums.SocketDataDirectionIngress]))
	}
}

func requireBPF(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise the memlock limit: %v", err)
	}
}

type h2cKernelConn struct {
	name string
	port uint16
	// the port of the other end
	remotePort uint16
	client     bool
	mu         sync.Mutex
	real       [3][]byte
	// the size of every socket call of a direction, in order
	calls  [3][]int
	events [3][]*aclevents.SocketDataUploadEvent
}

// add records one socket call
func (c *h2cKernelConn) add(d enums.SocketDataDirection, data []byte) {
	if len(data) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.real[d] = append(c.real[d], data...)
	c.calls[d] = append(c.calls[d], len(data))
}

// preface tells whether the direction starts with the client connection preface
func (c *h2cKernelConn) preface(d enums.SocketDataDirection) bool {
	return c.client == (d == enums.SocketDataDirectionEgress)
}

type h2cKernelRun struct {
	drop bool
	// skip is access_log.protocol_analyze.skip_h2c_data_payload, see h2c_skip_kernel_test.go
	skip  bool
	mu    sync.Mutex
	conns []*h2cKernelConn
}

// record wraps a connection so its socket calls are recorded under the name
func (r *h2cKernelRun) record(conn net.Conn, name string, client bool) *recordingConn {
	port := uint16(conn.LocalAddr().(*net.TCPAddr).Port)
	recorded := &h2cKernelConn{name: fmt.Sprintf("%s:%d", name, port), port: port, client: client,
		remotePort: uint16(conn.RemoteAddr().(*net.TCPAddr).Port)}
	r.mu.Lock()
	r.conns = append(r.conns, recorded)
	r.mu.Unlock()
	return &recordingConn{Conn: conn, record: recorded}
}

// recordingConn records the bytes of every successful read and write: one Read or Write of a net.Conn
// is one socket call, so this is what BPF sees. The calls are kept below the upload limit of a socket
// call (120KB), which loopback would otherwise exceed, because a truncated upload is not comparable.
type recordingConn struct {
	net.Conn
	record *h2cKernelConn
}

const recordingConnMaxCall = 32 * 1024

func (c *recordingConn) Read(p []byte) (int, error) {
	if len(p) > recordingConnMaxCall {
		p = p[:recordingConnMaxCall]
	}
	n, err := c.Conn.Read(p)
	c.record.add(enums.SocketDataDirectionIngress, p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		chunk := p[written:]
		if len(chunk) > recordingConnMaxCall {
			chunk = chunk[:recordingConnMaxCall]
		}
		n, err := c.Conn.Write(chunk)
		c.record.add(enums.SocketDataDirectionEgress, chunk[:n])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// h2cUploadBefore orders the events of a connection as the user space does: by data id, then sequence
func h2cUploadBefore(a, b *aclevents.SocketDataUploadEvent) bool {
	if a.DataID0 != b.DataID0 {
		return a.DataID0 < b.DataID0
	}
	return a.Sequence0 < b.Sequence0
}

// h2cBPF is the access log programs, loaded and attached once for the tests of the package: the ones the
// connection lifecycle and a plain read and write go through, monitoring this process
var h2cBPF struct {
	once   sync.Once
	loader *bpf.Loader
	err    error
}

func h2cLoadBPF() (*bpf.Loader, error) {
	h2cBPF.once.Do(func() {
		h2cBPF.loader, h2cBPF.err = h2cLoadAttachBPF("")
	})
	return h2cBPF.loader, h2cBPF.err
}

// h2cLoadAttachBPF loads the access log programs with the attach mode given (bpf.NewLoaderWithAttach) and attaches the
// ones the tests go through, monitoring this process
func h2cLoadAttachBPF(mode string) (*bpf.Loader, error) {
	loader, err := bpf.NewLoaderWithAttach(mode)
	if err != nil {
		return nil, fmt.Errorf("load: %v", err)
	}
	if err := loader.MonitorProcess(uint32(os.Getpid())); err != nil {
		_ = loader.Close()
		return nil, fmt.Errorf("monitor the test process: %v", err)
	}
	// each hook through its tracepoint/kprobe or its trampoline twin, as the loader decided for the kernel
	// (bpf.Loader.AddSyscall); recvfrom for the peek of TestH2CPeek, as the transfer collector attaches it
	loader.AddSyscall("read", loader.TracepointEnterRead, loader.TracepointExitRead, loader.FentryEnterRead, loader.FexitExitRead)
	loader.AddSyscall("write", loader.TracepointEnterWrite, loader.TracepointExitWrite, loader.FentryEnterWrite, loader.FexitExitWrite)
	loader.AddSyscall("recvfrom", loader.TracepointEnterRecvfrom, loader.TracepointExitRecvfrom, loader.FentryEnterRecvfrom, loader.FexitExitRecvfrom)
	loader.AddSyscall("writev", loader.TracepointEnterWritev, loader.TracepointExitWritev, loader.FentryEnterWritev, loader.FexitExitWritev)
	loader.AddSyscall("connect", loader.TracepointEnterConnect, loader.TracepointExitConnect, loader.FentryEnterConnect, loader.FexitExitConnect)
	loader.AddSyscall("accept", loader.TracepointEnterAccept, loader.TracepointExitAccept, loader.FentryEnterAccept, loader.FexitExitAccept)
	loader.AddSyscall("accept4", loader.TracepointEnterAccept, loader.TracepointExitAccept, loader.FentryEnterAccept4, loader.FexitExitAccept4)
	loader.AddSyscall("close", loader.TracepointEnterClose, loader.TracepointExitClose, loader.FentryEnterClose, loader.FexitExitClose)
	loader.AddKprobeHook("security_socket_sendmsg", loader.SecuritySocketSendmsg, loader.FentrySecuritySocketSendmsg)
	loader.AddKprobeHook("security_socket_recvmsg", loader.SecuritySocketRecvmsg, loader.FentrySecuritySocketRecvmsg)
	loader.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_connect": loader.TcpConnect})
	loader.AddLink(link.Kretprobe, map[string]*ebpf.Program{"sock_alloc": loader.SockAllocRet})
	if err := loader.HasError(); err != nil {
		_ = loader.Close()
		return nil, fmt.Errorf("attach: %v", err)
	}
	return loader, nil
}

// h2cClearMap removes every entry of a hash map
func h2cClearMap(t *testing.T, m *ebpf.Map) {
	t.Helper()
	var key uint64
	var keys []uint64
	value := make([]byte, m.ValueSize())
	for it := m.Iterate(); it.Next(&key, &value); {
		keys = append(keys, key)
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("clear %s: %v", m, err)
		}
	}
}

// withAccessLogBPF sets the dropping, starts from no active connection, runs the traffic and hands every
// HTTP/2 data event to its recorded connection
func withAccessLogBPF(t *testing.T, drop bool, traffic func(run *h2cKernelRun)) *h2cKernelRun {
	t.Helper()
	return withAccessLogBPFModes(t, drop, false, traffic)
}

// withAccessLogBPFModes is withAccessLogBPF with the skipping of the DATA payloads set as well
func withAccessLogBPFModes(t *testing.T, drop, skip bool, traffic func(run *h2cKernelRun)) *h2cKernelRun {
	t.Helper()
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		variable *ebpf.Variable
		on       bool
	}{{loader.DropH2cUnusedFrame, drop}, {loader.SkipH2cDataPayload, skip}} {
		value := uint32(0)
		if v.on {
			value = 1
		}
		if err := v.variable.Set(value); err != nil {
			t.Fatalf("set the switch: %v", err)
		}
	}
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 32<<20)
	if err != nil {
		t.Fatalf("perf reader: %v", err)
	}
	var events []*aclevents.SocketDataUploadEvent
	// the readers run beside the traffic; lost and received are written by them
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
			e := &aclevents.SocketDataUploadEvent{}
			e.ReadFrom(btf.NewReader(record.RawSample))
			events = append(events, e)
		}
	}()

	run := &h2cKernelRun{drop: drop, skip: skip}
	traffic(run)
	// the readers may lag behind the ring buffers on a slow machine: wait until they are idle, a reader
	// that is closed early drops what it did not read without counting it as lost
	for {
		before := received.Load()
		time.Sleep(time.Second)
		if received.Load() == before {
			break
		}
	}
	_ = reader.Close()
	<-readerDone
	if lost.Load() > 0 {
		t.Fatalf("drop=%t skip=%t: %d perf samples lost, the comparison would be meaningless", drop, skip, lost.Load())
	}

	for _, conn := range run.conns {
		for _, e := range events {
			// a call sent without its data under memory pressure (Shed) and a receive with MSG_PEEK (Peek) decode
			// without a protocol
			if e.LocalPort == conn.port && (e.Protocol0 == enums.ConnectionProtocolHTTP2 || e.Shed() || e.Peek()) {
				conn.events[e.Direction0] = append(conn.events[e.Direction0], e)
			}
		}
		for d := range conn.events {
			events := conn.events[d]
			sort.SliceStable(events, func(i, j int) bool { return h2cUploadBefore(events[i], events[j]) })
		}
	}
	return run
}

// goH2CTraffic is the measured workload between Go's h2c client and server
func goH2CTraffic(t *testing.T, run *h2cKernelRun, requests int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	body := bytes.Repeat([]byte{'r'}, 256*1024)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		(&http2.Server{}).ServeConn(run.record(raw, "server", false), &http2.ServeConnOpts{ //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write(body)
			}),
		})
	}()
	transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) { //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// the transport may dial more than once while its first connection is being set up
		return run.record(raw, "client", true), nil
	}}
	defer transport.CloseIdleConnections() //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
	httpClient := &http.Client{Transport: transport}
	var wg sync.WaitGroup
	concurrency := make(chan struct{}, 8)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		concurrency <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-concurrency }()
			resp, err := httpClient.Post(fmt.Sprintf("http://%s/download/%d", listener.Addr(), i), "application/octet-stream",
				bytes.NewReader(bytes.Repeat([]byte{'q'}, 1024)))
			if err != nil {
				t.Errorf("request: %v", err)
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if n != int64(len(body)) {
				t.Errorf("response body %d bytes", n)
			}
		}(i)
	}
	wg.Wait()
}

// h2cRawSession is a recorded TCP connection whose two ends the test drives by hand: the client writes
// frames, the server reads them in the sizes the test chooses
type h2cRawSession struct {
	t               *testing.T
	server, client  *recordingConn
	peer, responder *h2cEndpoint
	listener        net.Listener
}

// h2cRawPair connects a recorded server and client; the server connection is recorded first
func h2cRawPair(t *testing.T, run *h2cKernelRun) *h2cRawSession {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- raw
	}()
	rawClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rawServer, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	return &h2cRawSession{t: t, server: run.record(rawServer, "server", false), client: run.record(rawClient, "client", true),
		peer: newH2CEndpoint(), responder: newH2CEndpoint(), listener: listener}
}

func (s *h2cRawSession) close() {
	_ = s.server.Close()
	_ = s.client.Close()
	_ = s.listener.Close()
}

// write sends the frames in one call, and waits so the reads that follow find all of them: each read
// is then one socket call of the size it asks for
func (s *h2cRawSession) write(frames ...[]byte) {
	if _, err := s.client.Write(bytes.Join(frames, nil)); err != nil {
		s.t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
}

// read makes one server read of each size
func (s *h2cRawSession) read(sizes ...int) {
	for _, size := range sizes {
		if size == 0 {
			continue
		}
		if _, err := io.ReadFull(s.server, make([]byte, size)); err != nil {
			s.t.Fatal(err)
		}
	}
}

// send writes the frames in one call, and the server reads each of them as x/net does: the preface,
// then the header and the payload of every frame in calls of their own
func (s *h2cRawSession) send(frames ...[]byte) {
	s.write(frames...)
	for _, f := range frames {
		if bytes.HasPrefix(f, []byte(http2.ClientPreface)) {
			s.read(len(http2.ClientPreface))
			f = f[len(http2.ClientPreface):]
		}
		s.read(9, len(f)-9)
	}
}

// respond writes a response to the stream in one call
func (s *h2cRawSession) respond(stream uint32, body int) {
	_ = s.responder.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: []byte{0x88}, EndHeaders: true})
	_ = s.responder.framer.WriteData(stream, true, make([]byte, body))
	s.serverWrite(s.responder.take())
}

func (s *h2cRawSession) serverWrite(data []byte) {
	if _, err := s.server.Write(data); err != nil {
		s.t.Fatal(err)
	}
}

// splitReadTraffic writes control frames from a raw client and reads them on the server in the sizes
// given, so every way a held header is resolved happens exactly once
func splitReadTraffic(t *testing.T, run *h2cKernelRun) {
	s := h2cRawPair(t, run)
	defer s.close()
	peer := s.peer

	s.write([]byte(http2.ClientPreface), peer.settings())
	s.read(len(http2.ClientPreface), 9)
	// the payload in two reads: the held header is uploaded after all, before the first of them
	s.write(peer.windowUpdate(1, 100))
	s.read(9, 2, 2)
	// header and payload: both dropped, also with a write of the other direction in between
	s.write(peer.windowUpdate(0, 200), peer.ping(false), peer.windowUpdate(3, 300))
	s.read(9, 4, 9, 8, 9)
	s.serverWrite(newH2CEndpoint().settings())
	s.read(4)
	// the payload read together with the next frame: the held header is uploaded after all
	s.write(peer.windowUpdate(1, 400), peer.settingsAck())
	s.read(9, 4+9)
	// a priority signal read in two parts, and a lone SETTINGS ACK
	s.write(peer.priority(5, 3), peer.settingsAck())
	s.read(9, 5, 9)
}

func (s *h2cRawSession) headers(stream uint32, block []byte, endHeaders, endStream bool) []byte {
	_ = s.peer.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: block,
		EndHeaders: endHeaders, EndStream: endStream})
	return s.peer.take()
}

func (s *h2cRawSession) data(stream uint32, endStream bool, payload []byte) []byte {
	_ = s.peer.framer.WriteData(stream, endStream, payload)
	return s.peer.take()
}

// requestTraffic sends two requests from a raw client, between control frames that are dropped
func requestTraffic(t *testing.T, run *h2cKernelRun) {
	s := h2cRawPair(t, run)
	defer s.close()
	s.send(append([]byte(http2.ClientPreface), s.peer.settings()...))
	s.serverWrite(s.responder.settings())
	s.send(s.peer.settingsAck(), s.peer.windowUpdate(0, 1<<20))
	s.send(s.headers(1, h2cStaticRequest("/first"), true, false), s.data(1, true, make([]byte, 300)))
	s.respond(1, 100)
	s.send(s.peer.windowUpdate(0, 100), s.peer.ping(false))
	s.serverWrite(s.responder.ping(true))
	s.send(s.headers(3, h2cStaticRequest("/second"), true, true))
	s.respond(3, 50)
	s.send(s.peer.windowUpdate(0, 50))
}

// h2cStaticRequest is a request header block that only uses the static table, so a header block that
// cannot be decoded never leaves the HPACK tables of the two ends out of step
func h2cStaticRequest(path string) []byte {
	block := []byte{0x83, 0x86, 0x04, byte(len(path))}
	block = append(block, path...)
	return append(block, 0x01, 0x03, 'h', '2', 'c')
}

// analyzeKernelConn runs the agent's HTTP/2 analyzer over copies of the uploads of one connection, in the
// order of their data ids: the analysis releases the buffers of the events it consumes, and the uploads
// are checked afterwards
func analyzeKernelConn(t *testing.T, conn *h2cKernelConn) *h2cResult {
	t.Helper()
	var sent []h2cEvent
	for _, events := range conn.events {
		for _, e := range events {
			c := e.Detach()
			c.Buffer = append([]byte(nil), e.BufferData()...)
			sent = append(sent, h2cEvent{event: c})
		}
	}
	sort.SliceStable(sent, func(i, j int) bool { return h2cUploadBefore(sent[i].event, sent[j].event) })
	return h2cAnalyze(t, sent, 1<<30)
}

// verifyKernelRun checks the uploads of every recorded connection and returns how many there were
func verifyKernelRun(t *testing.T, run *h2cKernelRun) (uploaded int) {
	t.Helper()
	for _, conn := range run.conns {
		for d := enums.SocketDataDirectionIngress; d <= enums.SocketDataDirectionEgress; d++ {
			realData, events := conn.real[d], conn.events[d]
			uploaded += len(events)
			got := uploadedStream(t, events)
			if !run.drop {
				if !bytes.Equal(got, realData) {
					t.Fatalf("dropping off, %s %s: the uploaded stream (%d bytes) is not the real one (%d bytes)",
						conn.name, directionName(d), len(got), len(realData))
				}
				continue
			}
			realFrames, realComplete := h2cFrames(t, realData, conn.preface(d))
			gotFrames, gotComplete := h2cFrames(t, got, conn.preface(d))
			// the real stream may end inside a frame when the connection is closed; the uploaded one may
			// not unless the real one does: a missing frame end means BPF dropped a call that belonged to it
			if realComplete && !gotComplete {
				t.Fatalf("dropping on, %s %s: the uploaded stream ends inside a frame", conn.name, directionName(d))
			}
			kept := 0
			for _, f := range realFrames {
				if kept < len(gotFrames) && bytes.Equal(gotFrames[kept], f) {
					kept++
					continue
				}
				if h2cDroppable(f) {
					continue
				}
				t.Fatalf("dropping on, %s %s: frame %x of the real stream is missing from the upload",
					conn.name, directionName(d), f[:9])
			}
			if kept != len(gotFrames) {
				t.Fatalf("dropping on, %s %s: the upload carries frames the real stream does not", conn.name, directionName(d))
			}
		}
		checkPrevDataIDs(t, conn)
		checkLayoutFields(t, conn)
	}
	return uploaded
}

// uploadedStream concatenates the bytes of the events of one direction; a call that BPF did not
// upload in full would make the comparison meaningless
func uploadedStream(t *testing.T, events []*aclevents.SocketDataUploadEvent) []byte {
	t.Helper()
	var result []byte
	for _, e := range events {
		if e.Finished == 1 && e.HaveReduce == 1 {
			t.Fatalf("socket call %d was truncated by the upload limit", e.DataID0)
		}
		result = append(result, e.BufferData()...)
	}
	return result
}

// h2cWalkFrames finds the frames of a direction: the stream offset each complete frame starts at, and
// the offset behind the last of them, which is the length of the stream when it ends on a boundary
func h2cWalkFrames(t *testing.T, stream []byte, preface bool) (starts []int, end int) {
	t.Helper()
	if preface && len(stream) > 0 {
		if !bytes.HasPrefix(stream, []byte(http2.ClientPreface)) {
			t.Fatalf("the client direction does not start with the preface")
		}
		end = len(http2.ClientPreface)
	}
	for end+9 <= len(stream) {
		next := end + 9 + (int(stream[end])<<16 | int(stream[end+1])<<8 | int(stream[end+2]))
		if next > len(stream) {
			break
		}
		starts = append(starts, end)
		end = next
	}
	return starts, end
}

// h2cFrames splits a direction into its complete frames and tells whether it ends on a frame boundary
func h2cFrames(t *testing.T, stream []byte, preface bool) (frames [][]byte, complete bool) {
	t.Helper()
	starts, end := h2cWalkFrames(t, stream, preface)
	for i, start := range starts {
		stop := end
		if i+1 < len(starts) {
			stop = starts[i+1]
		}
		frames = append(frames, stream[start:stop])
	}
	return frames, end == len(stream)
}

// h2cControlPayloadLen is the oracle of these tests for the frame set the BPF side may drop: the payload
// length of a droppable frame header, -1 for any other
func h2cControlPayloadLen(header []byte) int {
	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	streamZero := header[5] == 0 && header[6] == 0 && header[7] == 0 && header[8] == 0
	switch {
	case header[5]&0x80 != 0:
		return -1
	case http2.FrameType(header[3]) == http2.FrameWindowUpdate && length == 4 && header[4] == 0:
		return 4
	case http2.FrameType(header[3]) == http2.FramePing && length == 8 && header[4]&0xfe == 0 && streamZero:
		return 8
	case http2.FrameType(header[3]) == http2.FramePriority && length == 5 && header[4] == 0 && !streamZero:
		return 5
	case http2.FrameType(header[3]) == http2.FrameSettings && length == 0 && header[4] == 1 && streamZero:
		return 0
	}
	return -1
}

func h2cDroppable(frame []byte) bool {
	return len(frame) >= 9 && h2cControlPayloadLen(frame) == len(frame)-9
}

// checkPrevDataIDs checks what keeps the user space from waiting for a call it will never see: the
// previous data id of every upload is 0 or names a call that was uploaded. They are not contiguous even
// without the dropping: the reader and the writer of a connection run on different threads, and the
// previous data id is the last call uploaded when the call returned, not the call before it.
func checkPrevDataIDs(t *testing.T, conn *h2cKernelConn) {
	t.Helper()
	uploaded := map[uint64]bool{}
	for _, events := range conn.events {
		for _, e := range events {
			uploaded[e.DataID0] = true
		}
	}
	for _, events := range conn.events {
		for _, e := range events {
			if e.PrevDataID0 != 0 && !uploaded[e.PrevDataID0] {
				t.Fatalf("%s: data id %d names %d as its previous upload, which was never uploaded",
					conn.name, e.DataID0, e.PrevDataID0)
			}
		}
	}
}

// checkLayoutFields checks the details the event of the layout carries: every event carries the function
// name, the L4 counters and the ports of its own socket call
func checkLayoutFields(t *testing.T, conn *h2cKernelConn, otherIngress ...enums.SocketFunctionName) {
	t.Helper()
	for d, events := range conn.events {
		funcNames := []enums.SocketFunctionName{enums.SocketFunctionNameRead}
		if enums.SocketDataDirection(d) == enums.SocketDataDirectionEgress {
			funcNames = []enums.SocketFunctionName{enums.SocketFunctionNameWrite}
		} else {
			// the receive calls of the traffic besides its reads (a recvfrom that peeks)
			funcNames = append(funcNames, otherIngress...)
		}
		for _, e := range events {
			funcOK := false
			for _, f := range funcNames {
				funcOK = funcOK || e.FunctionName == uint32(f)
			}
			if !funcOK || e.LocalPort != conn.port || e.RemotePort != conn.remotePort || e.SSL != 0 ||
				e.L4PackageCount == 0 || e.L4TotalPackageSize == 0 {
				t.Fatalf("%s %s: socket call %d does not carry its own details: %+v", conn.name,
					directionName(enums.SocketDataDirection(d)), e.DataID0, *e.Detach())
			}
		}
	}
}

func directionName(d enums.SocketDataDirection) string {
	if d == enums.SocketDataDirectionIngress {
		return "ingress"
	}
	return "egress"
}
