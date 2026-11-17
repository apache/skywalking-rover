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

package collector

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"google.golang.org/protobuf/proto"
)

// l24KernelRun is what one run of the HTTP/1 exchange over the loopback gave: the data events of its two
// connections' ends, the l24 events, the calls really made
type l24KernelRun struct {
	events []*events.SocketDataUploadEvent
	l24    []*events.SocketL24Event
	// the bytes of every write and of every read that returned data, per local port, in order
	writes, reads map[uint16][]int
	ports         [2]uint16
}

// the messages of the exchange: small enough for one segment of the loopback each (so each read returns exactly one
// message, the same in every run), and the size class of the uploaded chunks
var l24ExchangeSizes = []int{120, 1500, 9000, 30000}

func l24Message(head string, size int) []byte {
	h := fmt.Sprintf("%s\r\nContent-Length: %d\r\n\r\n", head, size)
	return append([]byte(h), bytes.Repeat([]byte{'x'}, size)...)
}

// countingConn records the size of every write and every read that returned data
type countingConn struct {
	net.Conn
	run  *l24KernelRun
	port uint16
	mu   *sync.Mutex
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.run.reads[c.port] = append(c.run.reads[c.port], n)
		c.mu.Unlock()
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.run.writes[c.port] = append(c.run.writes[c.port], n)
	c.mu.Unlock()
	return n, err
}

// runL24Traffic loads the access log programs with the L2 to L4 details on or off, attaches what a plain read and write
// go through (and the l24 hooks with the switch on, as L24Collector does), runs a ping-pong HTTP/1 exchange over the
// loopback and gives every event of its connections
func runL24Traffic(t *testing.T, l2l3 bool) *l24KernelRun {
	t.Helper()
	loader, err := bpf.NewLoaderWithOptions(bpf.LoaderOptions{KernelMetricsL2L3: l2l3})
	if err != nil {
		t.Fatalf("l2l3=%t: load: %v", l2l3, err)
	}
	defer loader.Close()
	if loader.KernelMetricsL2L3() != l2l3 {
		t.Fatalf("l2l3=%t: the loader says %t", l2l3, loader.KernelMetricsL2L3())
	}
	if err := loader.MonitorProcess(uint32(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct {
		name                 string
		enter, exit, fe, fex *ebpf.Program
	}{
		{"read", loader.TracepointEnterRead, loader.TracepointExitRead, loader.FentryEnterRead, loader.FexitExitRead},
		{"write", loader.TracepointEnterWrite, loader.TracepointExitWrite, loader.FentryEnterWrite, loader.FexitExitWrite},
		{"connect", loader.TracepointEnterConnect, loader.TracepointExitConnect, loader.FentryEnterConnect, loader.FexitExitConnect},
		{"accept", loader.TracepointEnterAccept, loader.TracepointExitAccept, loader.FentryEnterAccept, loader.FexitExitAccept},
		{"accept4", loader.TracepointEnterAccept, loader.TracepointExitAccept, loader.FentryEnterAccept4, loader.FexitExitAccept4},
		{"close", loader.TracepointEnterClose, loader.TracepointExitClose, loader.FentryEnterClose, loader.FexitExitClose},
	} {
		loader.AddSyscall(call.name, call.enter, call.exit, call.fe, call.fex)
	}
	loader.AddKprobeHook("tcp_sendmsg", loader.TcpSendmsg, loader.FentryTcpSendmsg)
	loader.AddTracePointHook("skb", "skb_copy_datagram_iovec", loader.TracepointSkbCopyDatagramIovec, loader.RawTpSkbCopyDatagramIovec)
	loader.AddKprobeHook("security_socket_sendmsg", loader.SecuritySocketSendmsg, loader.FentrySecuritySocketSendmsg)
	loader.AddKprobeHook("security_socket_recvmsg", loader.SecuritySocketRecvmsg, loader.FentrySecuritySocketRecvmsg)
	loader.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_connect": loader.TcpConnect})
	loader.AddLink(link.Kretprobe, map[string]*ebpf.Program{"sock_alloc": loader.SockAllocRet})
	ctx := &common.AccessLogContext{BPF: loader, Config: &common.Config{}}
	programs := l24Programs(ctx)
	for _, h := range l24Hooks {
		loaded := loader.L24ProgramLoaded(h.program)
		if loaded != l2l3 && !(l2l3 && loader.L24RefusedPrograms()[h.program] != nil) {
			t.Fatalf("l2l3=%t: program %s loaded: %t", l2l3, h.program, loaded)
		}
		info, err := programs[h.program].Info()
		if err != nil {
			t.Fatal(err)
		}
		if stub := info.Type == ebpf.SocketFilter; stub == loaded {
			t.Fatalf("l2l3=%t: program %s is a %s", l2l3, h.program, info.Type)
		}
		if !loaded {
			continue
		}
		if err := attachL24Hook(ctx, h, programs[h.program]); err != nil {
			t.Logf("%s %s %s does not attach here: %v", h.program, h.kind, h.symbol, err)
		}
	}
	if err := loader.HasError(); err != nil {
		t.Fatalf("attach: %v", err)
	}

	run := &l24KernelRun{writes: map[uint16][]int{}, reads: map[uint16][]int{}}
	var mu sync.Mutex
	var received atomic.Uint64
	readQueue := func(m *ebpf.Map, decode func(sample []byte)) (stop func()) {
		reader, err := perf.NewReader(m, 16<<20)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				record, err := reader.Read()
				if err != nil {
					return
				}
				if record.LostSamples > 0 {
					t.Errorf("%s lost %d samples", m, record.LostSamples)
				}
				received.Add(1)
				if len(record.RawSample) > 0 {
					mu.Lock()
					decode(record.RawSample)
					mu.Unlock()
				}
			}
		}()
		return func() { _ = reader.Close(); <-done }
	}
	stopData := readQueue(loader.SocketDataUploadQueue, func(sample []byte) {
		e := &events.SocketDataUploadEvent{}
		e.ReadFrom(btf.NewReader(sample))
		run.events = append(run.events, e)
	})
	stopL24 := readQueue(loader.SocketL24Queue, func(sample []byte) {
		e := &events.SocketL24Event{}
		e.ReadFrom(btf.NewReader(sample))
		run.l24 = append(run.l24, e)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		conn := &countingConn{Conn: raw, run: run, port: uint16(raw.LocalAddr().(*net.TCPAddr).Port), mu: &mu}
		defer conn.Close()
		buf := make([]byte, 64*1024)
		for _, size := range l24ExchangeSizes {
			request := l24Message("POST /l2l3 HTTP/1.1\r\nHost: l2l3", size)
			if _, err := io.ReadFull(conn, buf[:len(request)]); err != nil {
				return
			}
			if _, err := conn.Write(l24Message("HTTP/1.1 200 OK", size)); err != nil {
				return
			}
		}
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := &countingConn{Conn: raw, run: run, port: uint16(raw.LocalAddr().(*net.TCPAddr).Port), mu: &mu}
	run.ports = [2]uint16{client.port, uint16(listener.Addr().(*net.TCPAddr).Port)}
	buf := make([]byte, 64*1024)
	for _, size := range l24ExchangeSizes {
		if _, err := client.Write(l24Message("POST /l2l3 HTTP/1.1\r\nHost: l2l3", size)); err != nil {
			t.Fatal(err)
		}
		response := l24Message("HTTP/1.1 200 OK", size)
		if _, err := io.ReadFull(client, buf[:len(response)]); err != nil {
			t.Fatal(err)
		}
	}
	_ = client.Close()
	<-serverDone
	_ = listener.Close()
	// until the readers are idle
	for {
		before := received.Load()
		time.Sleep(time.Second)
		if received.Load() == before {
			break
		}
	}
	stopData()
	stopL24()

	// the events of the two ends of the connection, in the order of their calls
	var ours []*events.SocketDataUploadEvent
	for _, e := range run.events {
		if e.LocalPort == run.ports[0] || e.LocalPort == run.ports[1] {
			ours = append(ours, e)
		}
	}
	// the client end first, then the server end (the client port is any)
	sort.SliceStable(ours, func(i, j int) bool {
		a, b := ours[i], ours[j]
		if (a.LocalPort == run.ports[1]) != (b.LocalPort == run.ports[1]) {
			return b.LocalPort == run.ports[1]
		}
		if a.DataID0 != b.DataID0 {
			return a.DataID0 < b.DataID0
		}
		return a.Sequence0 < b.Sequence0
	})
	run.events = ours
	return run
}

// l24Calls is the first chunk event of every call of the end of the connection of the direction
func l24Calls(run *l24KernelRun, port uint16, d enums.SocketDataDirection) []*events.SocketDataUploadEvent {
	var calls []*events.SocketDataUploadEvent
	for _, e := range run.events {
		if e.LocalPort == port && e.Direction0 == d && e.Sequence0 == 0 {
			calls = append(calls, e)
		}
	}
	return calls
}

// l24Normalized is the event without what differs between two runs of the same exchange: the times, the connection,
// the data ids, the ports and the side of the connection the port is on
func l24Normalized(run *l24KernelRun, e *events.SocketDataUploadEvent) events.SocketDataUploadEvent {
	c := *e.Detach()
	c.StartTime0, c.EndTime0, c.ConnectionID, c.RandomID, c.DataID0, c.PrevDataID0 = 0, 0, 0, 0, 0, 0
	side := uint16(0)
	if e.LocalPort == run.ports[1] {
		side = 1
	}
	c.LocalPort, c.RemotePort = side, 0
	c.Buffer = append([]byte(nil), e.BufferData()...)
	return c
}

// TestL2L3KernelMetrics runs one HTTP/1 exchange over the loopback with access_log.kernel_metrics.l2_l3 off and on.
// On: every read and write of the exchange sends its L2 to L4 details, and its kernel log carries the interface
// (the loopback), the time in the IP layer and the device queue, and for a write the packages __tcp_transmit_skb sent.
// Off: the l24 programs are stubs, no l24 event is sent, the kernel logs are those of the L4 counters alone, and the
// socket data events of the exchange are the same, field by field and byte by byte, as with the switch on.
func TestL2L3KernelMetrics(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise the memlock limit: %v", err)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	off := runL24Traffic(t, false)
	on := runL24Traffic(t, true)

	// on: the details of every call of the exchange
	store := events.NewL24Store(1<<16, time.Hour, time.Hour)
	for _, e := range on.l24 {
		store.Put(events.L24Key{ConnectionID: e.ConnectionID, RandomID: e.RandomID, DataID: e.DataID}, &e.Metrics)
	}
	events.SetL24Store(store)
	defer events.SetL24Store(nil)
	checked, reads, timedReads := 0, 0, 0
	for _, port := range on.ports {
		for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionEgress, enums.SocketDataDirectionIngress} {
			calls := l24Calls(on, port, d)
			sizes := on.writes[port]
			if d == enums.SocketDataDirectionIngress {
				sizes = on.reads[port]
			}
			if len(calls) != len(sizes) {
				t.Fatalf("port %d %d: %d events for %d calls", port, d, len(calls), len(sizes))
			}
			for i, e := range calls {
				what := fmt.Sprintf("port %d direction %d call %d (%d bytes)", port, d, i, sizes[i])
				m, ok := events.LookupL24(e)
				if !ok {
					t.Fatalf("%s: no L2/L3 details", what)
				}
				log := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, e)
				if d == enums.SocketDataDirectionEgress {
					w := log.GetWrite()
					if w == nil || w.L3Metrics == nil || w.L2Metrics == nil || w.L4Metrics == nil {
						t.Fatalf("%s: the write log is %v", what, log)
					}
					if w.L3Metrics.TotalDuration == 0 || w.L2Metrics.Ifindex != uint32(lo.Index) ||
						w.L2Metrics.TotalDuration == 0 || w.L2Metrics.TotalEnterQueueBufferCount == 0 || w.L4Metrics.TotalDuration == 0 ||
						w.L4Metrics.TotalTransmitPackageCount < 1 || w.L4Metrics.TotalPackageSize != int64(sizes[i]) ||
						uint32(w.L4Metrics.TotalTransmitPackageCount) != m.L4TransmitPackageCount {
						t.Fatalf("%s: the write log is %v, the details %+v", what, log, m)
					}
				} else {
					r := log.GetRead()
					if r == nil || r.L3Metrics == nil || r.L2Metrics == nil || r.L4Metrics == nil {
						t.Fatalf("%s: the read log is %v", what, log)
					}
					if r.L2Metrics.Ifindex != uint32(lo.Index) || r.L2Metrics.TotalRcvPackageFromQueueDuration == 0 ||
						r.L2Metrics.TotalPackageToQueueDuration == 0 || r.L2Metrics.TotalPackageSize != uint64(sizes[i]) {
						t.Fatalf("%s: the read log is %v, the details %+v", what, log, m)
					}
					// ip_rcv and tcp_v4_rcv return after they queued the sk_buff: a reader that copies it before (on
					// another CPU) takes its details without those times
					reads++
					if r.L3Metrics.TotalDuration > 0 && r.L4Metrics.TotalDuration > 0 {
						timedReads++
					}
				}
				checked++
			}
		}
	}
	if timedReads*2 < reads {
		t.Fatalf("on: %d of %d reads have their L3 and L4 times", timedReads, reads)
	}
	t.Logf("on: %d calls with their L2/L3 details (%d of %d reads with the L3/L4 times), %d l24 events", checked,
		timedReads, reads, len(on.l24))

	// off: no details, the logs of the L4 counters, the same events
	if len(off.l24) != 0 {
		t.Fatalf("off: %d l24 events", len(off.l24))
	}
	events.SetL24Store(nil)
	for _, port := range off.ports {
		for i, e := range l24Calls(off, port, enums.SocketDataDirectionEgress) {
			w := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, e).GetWrite()
			if w == nil || w.L3Metrics != nil || w.L2Metrics != nil || w.L4Metrics.TotalTransmitPackageCount != 1 ||
				w.L4Metrics.TotalPackageSize != int64(off.writes[port][i]) || w.L4Metrics.TotalDuration != 0 {
				t.Fatalf("off: port %d write %d: %v", port, i, w)
			}
		}
	}
	if len(off.events) != len(on.events) || len(off.events) == 0 {
		t.Fatalf("%d events off, %d on", len(off.events), len(on.events))
	}
	for i := range off.events {
		a, b := l24Normalized(off, off.events[i]), l24Normalized(on, on.events[i])
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("event %d differs:\noff %+v\non  %+v", i, a, b)
		}
		// and the kernel log without details is the same
		ka, kb := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, &a),
			forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, &b)
		if !proto.Equal(ka, kb) {
			t.Fatalf("event %d: kernel log off %v, on %v", i, ka, kb)
		}
	}
	t.Logf("off: %d events, the same as on", len(off.events))
}
