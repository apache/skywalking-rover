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
	"encoding/binary"
	"fmt"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// The tests below attach the access log BPF programs to this process (see h2cLoadBPF) with
// access_log.protocol_analyze.skip_http1_body_payload_bpf off, on, and on with the coalescing of the skipped
// calls (merge_kernel_logs), and check every event of an HTTP/1 connection against the bytes the endpoints
// really read and wrote (skywalking-rover bpf/accesslog/syscalls/h1.h): an uploaded call carries its bytes,
// a skipped event stands for a call (or, coalesced, a run of consecutive calls) wholly inside one
// Content-Length body, with the exact size, and is never a call that overlapped another one of its fd.
// They need root and are skipped otherwise.

type h1BPFMode struct {
	name           string
	skip, coalesce bool
}

var h1BPFModes = []h1BPFMode{{"off", false, false}, {"skip", true, false}, {"coalesce", true, true}}

// withH1SkipBPF sets the switches, starts from no active connection, runs the traffic and hands every event
// of a recorded connection to it, both directions ordered as the user space orders them
func withH1SkipBPF(t *testing.T, mode h1BPFMode, traffic func(run *h2cKernelRun)) *h2cKernelRun {
	t.Helper()
	run, _ := withH1SkipBPFRecorded(t, mode, traffic)
	return run
}

// withH1SkipBPFRecorded is withH1SkipBPF that also returns the perf records of the recorded connections in
// the order the reader read them
func withH1SkipBPFRecorded(t *testing.T, mode h1BPFMode, traffic func(run *h2cKernelRun)) (*h2cKernelRun, [][]byte) {
	t.Helper()
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	set := func(v *ebpf.Variable, value interface{}) {
		if err := v.Set(value); err != nil {
			t.Fatalf("set %s: %v", v, err)
		}
	}
	b := func(v bool) uint32 {
		if v {
			return 1
		}
		return 0
	}
	set(loader.DropH2cUnusedFrame, uint32(0))
	set(loader.SkipH2cDataPayload, uint32(0))
	set(loader.SkipHttp1BodyPayload, b(mode.skip))
	set(loader.CoalesceHttp1BodyPayload, b(mode.coalesce))
	set(loader.BootTimeUnixNs, uint64(host.BootTime.UnixNano()))
	defer set(loader.SkipHttp1BodyPayload, uint32(0))
	defer set(loader.CoalesceHttp1BodyPayload, uint32(0))
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	var events []*aclevents.SocketDataUploadEvent
	var samples [][]byte
	var lost, received atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
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
			samples = append(samples, append([]byte(nil), record.RawSample...))
		}
	}()
	run := &h2cKernelRun{}
	traffic(run)
	for {
		before := received.Load()
		time.Sleep(time.Second)
		if received.Load() == before {
			break
		}
	}
	_ = reader.Close()
	<-done
	if lost.Load() > 0 {
		t.Fatalf("%s: %d perf samples lost", mode.name, lost.Load())
	}
	for _, conn := range run.conns {
		for _, e := range events {
			if e.LocalPort == conn.port && e.RemotePort == conn.remotePort && e.Protocol0 != enums.ConnectionProtocolUnknown {
				conn.events[e.Direction0] = append(conn.events[e.Direction0], e)
			}
		}
		for d := range conn.events {
			ev := conn.events[d]
			sort.SliceStable(ev, func(i, j int) bool { return h2cUploadBefore(ev[i], ev[j]) })
		}
	}
	var recorded [][]byte
	for i, e := range events {
		for _, conn := range run.conns {
			if e.LocalPort == conn.port && e.RemotePort == conn.remotePort && e.Protocol0 != enums.ConnectionProtocolUnknown {
				recorded = append(recorded, samples[i])
			}
		}
	}
	return run, recorded
}

// h1Framing is where the bodies of the messages of a connection are, as RFC 7230 3.3.3 and the analyzer
// frame them: per direction the Content-Length body byte ranges, up to where the messages could be framed
type h1Framing struct {
	bodies [3][][2]int
	end    [3]int
}

type h1Head struct {
	start, length int
	line          string
	headers       http.Header
}

// h1ParseHead parses the head at pos, false when there is none (or it does not end)
func h1ParseHead(real []byte, pos int) (h1Head, bool) {
	end := bytes.Index(real[pos:], []byte("\r\n\r\n"))
	if end < 0 {
		return h1Head{}, false
	}
	lines := strings.Split(string(real[pos:pos+end]), "\r\n")
	h := h1Head{start: pos, length: end + 4, line: lines[0], headers: http.Header{}}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return h1Head{}, false
		}
		h.headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return h, true
}

// h1Chunks frames a chunked body that starts at pos: the ranges of the chunk data, and where the body ends
// (-1 when it does not end in the stream)
func h1Chunks(real []byte, pos int) ([][2]int, int) {
	var data [][2]int
	for {
		eol := bytes.Index(real[pos:], []byte("\r\n"))
		if eol < 0 {
			return data, -1
		}
		line, _, _ := strings.Cut(string(real[pos:pos+eol]), ";")
		size, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil {
			return data, -1
		}
		pos += eol + 2
		if size == 0 {
			end := bytes.Index(real[pos:], []byte("\r\n"))
			for end > 0 {
				// a trailer line
				pos += end + 2
				end = bytes.Index(real[pos:], []byte("\r\n"))
			}
			if end < 0 {
				return data, -1
			}
			return data, pos + 2
		}
		data = append(data, [2]int{pos, pos + int(size)})
		pos += int(size) + 2
		if pos > len(real) {
			return data, -1
		}
	}
}

// h1Frame frames the messages of the real streams of a connection: the requests of the direction that
// starts with one, the responses of the other in their order (a HEAD request, a 1xx, 204 or 304 response
// has no body, an interim 1xx answers no request), a Content-Length body, the data of chunked bodies, and
// the rest of the stream behind a response delimited by the close; it stops at what it cannot frame (an
// upgrade, another transfer coding)
func h1Frame(real [3][]byte) h1Framing {
	var f h1Framing
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	reqDir, respDir := in, out
	if bytes.HasPrefix(real[in], []byte("HTTP/")) || (len(real[in]) == 0 && len(real[out]) > 0 && !bytes.HasPrefix(real[out], []byte("HTTP/"))) {
		reqDir, respDir = out, in
	}
	var methods []string
	pos := 0
	for pos < len(real[reqDir]) {
		h, ok := h1ParseHead(real[reqDir], pos)
		te := h.headers.Values("Transfer-Encoding")
		if !ok || (len(te) > 0 && (len(te) != 1 || !strings.EqualFold(te[0], "chunked"))) || len(h.headers.Values("Content-Length")) > 1 {
			break
		}
		method, _, _ := strings.Cut(h.line, " ")
		methods = append(methods, method)
		start := pos + h.length
		if len(te) == 1 {
			data, end := h1Chunks(real[reqDir], start)
			f.bodies[reqDir] = append(f.bodies[reqDir], data...)
			if end < 0 {
				pos = len(real[reqDir])
				break
			}
			pos = end
			continue
		}
		cl, _ := strconv.Atoi(h.headers.Get("Content-Length"))
		f.bodies[reqDir] = append(f.bodies[reqDir], [2]int{start, start + cl})
		pos = start + cl
	}
	f.end[reqDir] = pos
	pos = 0
	for pos < len(real[respDir]) {
		h, ok := h1ParseHead(real[respDir], pos)
		te := h.headers.Values("Transfer-Encoding")
		if !ok || (len(te) > 0 && (len(te) != 1 || !strings.EqualFold(te[0], "chunked"))) {
			break
		}
		fields := strings.Fields(h.line)
		status, _ := strconv.Atoi(fields[1])
		start := pos + h.length
		if status == 101 {
			break
		}
		if status < 200 {
			pos = start
			continue
		}
		if len(methods) == 0 {
			break
		}
		method := methods[0]
		methods = methods[1:]
		cl := 0
		if method != http.MethodHead && status != 204 && status != 304 {
			values := h.headers.Values("Content-Length")
			if len(te) == 1 {
				data, end := h1Chunks(real[respDir], start)
				f.bodies[respDir] = append(f.bodies[respDir], data...)
				if end < 0 {
					pos = len(real[respDir])
					break
				}
				pos = end
				continue
			}
			if len(values) == 0 {
				// delimited by the close: the rest of the stream
				f.bodies[respDir] = append(f.bodies[respDir], [2]int{start, len(real[respDir])})
				pos = len(real[respDir])
				break
			}
			if len(values) != 1 {
				break
			}
			cl, _ = strconv.Atoi(values[0])
		}
		f.bodies[respDir] = append(f.bodies[respDir], [2]int{start, start + cl})
		pos = start + cl
	}
	f.end[respDir] = pos
	return f
}

type h1Stats struct {
	calls, events, skippable, skippedCalls, skippedEvents, uploadedBytes, realBytes, outOfOrder int
	// per direction: the skippable and the skipped calls, and the last real offset a skipped call ends at
	skippableIn, skippedIn [3]int
	lastSkipped            [3]int
}

// h1Limits bounds where a direction may skip: from (the real offset a skipped call may start at) up to
// (where it may end)
type h1Limits struct {
	upTo [3]int
}

func h1NoLimits() h1Limits {
	return h1Limits{upTo: [3]int{1 << 62, 1 << 62, 1 << 62}}
}

// checkH1Conn matches the events of every direction with the real socket calls: an uploaded call is its
// bytes, a skipped event stands for one call (or, coalesced, a run of consecutive calls) wholly inside one
// body, with the exact summed size, and was alone on its fd (in flight 1); the previous data ids chain the
// events of the connection. With sequential, every call must have been alone on its fd.
func checkH1Conn(t *testing.T, conn *h2cKernelConn, mode h1BPFMode, limits h1Limits, sequential bool) (st h1Stats) {
	t.Helper()
	type ev struct {
		e    *aclevents.SocketDataUploadEvent
		data []byte
	}
	var all []ev
	framing := h1Frame(conn.real)
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		inBody := func(s, e int) int {
			for i, r := range framing.bodies[d] {
				if s >= r[0] && e <= r[1] && e > s {
					return i
				}
			}
			return -1
		}
		var evs []ev
		for _, e := range conn.events[d] {
			if len(evs) > 0 && evs[len(evs)-1].e.DataID0 == e.DataID0 {
				evs[len(evs)-1].data = append(evs[len(evs)-1].data, e.BufferData()...)
				continue
			}
			evs = append(evs, ev{e: e, data: append([]byte(nil), e.BufferData()...)})
		}
		all = append(all, evs...)
		offsets := make([]int, len(conn.calls[d])+1)
		for i, c := range conn.calls[d] {
			offsets[i+1] = offsets[i] + c
			if inBody(offsets[i], offsets[i+1]) >= 0 {
				st.skippable++
				st.skippableIn[d]++
			}
		}
		st.calls += len(conn.calls[d])
		st.events += len(evs)
		st.realBytes += len(conn.real[d])
		ci := 0
		for k, x := range evs {
			e := x.e
			st.uploadedBytes += len(x.data)
			if ci >= len(conn.calls[d]) {
				t.Fatalf("%s %s %s: more events than calls", mode.name, conn.name, directionName(d))
			}
			if sequential && e.InFlight != 1 {
				t.Fatalf("%s %s %s: event %d of a call alone on its fd has %d calls in flight", mode.name, conn.name,
					directionName(d), k, e.InFlight)
			}
			if e.PayloadSkipped0 != 1 {
				real := conn.real[d][offsets[ci]:offsets[ci+1]]
				if !bytes.Equal(x.data, real) || e.TotalSize0 != uint64(len(real)) || e.DataIDSpan != 0 {
					for j := max(0, k-3); j < len(evs) && j < k+3; j++ {
						t.Logf("event %d: dlen=%d total=%d skipped=%d id=%d prev=%d span=%d inflight=%d %q", j, evs[j].e.DataLen,
							evs[j].e.TotalSize0, evs[j].e.PayloadSkipped0, evs[j].e.DataID0, evs[j].e.PrevDataID0,
							evs[j].e.DataIDSpan, evs[j].e.InFlight, string(evs[j].data[:min(40, len(evs[j].data))]))
					}
					t.Fatalf("%s %s %s: call %d (%d bytes at %d) not uploaded byte for byte (%d bytes, total %d)", mode.name,
						conn.name, directionName(d), ci, len(real), offsets[ci], len(x.data), e.TotalSize0)
				}
				ci++
				continue
			}
			if !mode.skip {
				t.Fatalf("%s %s %s: a call skipped with the switch off", mode.name, conn.name, directionName(d))
			}
			if e.DataLen != 0 || e.Protocol0 != enums.ConnectionProtocolHTTP || e.Finished != 1 || e.InFlight != 1 {
				t.Fatalf("%s %s %s: bad skipped event %+v", mode.name, conn.name, directionName(d), *e.Detach())
			}
			if !mode.coalesce && e.DataIDSpan != 0 {
				t.Fatalf("%s %s %s: a coalesced event without the coalescing", mode.name, conn.name, directionName(d))
			}
			st.skippedEvents++
			first, sum, body := ci, 0, -2
			for sum < int(e.TotalSize0) && ci < len(conn.calls[d]) {
				b := inBody(offsets[ci], offsets[ci+1])
				if b < 0 || (body != -2 && b != body) {
					t.Fatalf("%s %s %s: call %d skipped but not inside one body (%d..%d)", mode.name, conn.name,
						directionName(d), ci, offsets[ci], offsets[ci+1])
				}
				if offsets[ci+1] > limits.upTo[d] {
					t.Fatalf("%s %s %s: call %d (%d..%d) skipped behind %d, where the direction is lost", mode.name,
						conn.name, directionName(d), ci, offsets[ci], offsets[ci+1], limits.upTo[d])
				}
				body = b
				sum += conn.calls[d][ci]
				ci++
				if !mode.coalesce {
					break
				}
			}
			if sum != int(e.TotalSize0) {
				t.Fatalf("%s %s %s: skipped event of calls %d..%d has total %d, the calls %d", mode.name, conn.name,
					directionName(d), first, ci-1, e.TotalSize0, sum)
			}
			if e.L4PackageCount == 0 || e.L4TotalPackageSize == 0 {
				t.Fatalf("%s %s %s: skipped event without L4 counters %+v", mode.name, conn.name, directionName(d), *e.Detach())
			}
			if uint64(e.DataIDSpan) < uint64(ci-first-1) {
				t.Fatalf("%s %s %s: an event of %d calls spans %d data ids", mode.name, conn.name, directionName(d),
					ci-first, e.DataIDSpan)
			}
			st.skippedCalls += ci - first
			st.skippedIn[d] += ci - first
			st.lastSkipped[d] = offsets[ci]
		}
		if ci != len(conn.calls[d]) {
			t.Fatalf("%s %s %s: %d calls, the events cover %d", mode.name, conn.name, directionName(d), len(conn.calls[d]), ci)
		}
	}
	// every previous data id names an event of the connection (none names a held call that was never
	// sent), and in data id order it is the event before, except behind a call that was made earlier but
	// returned later (Go's background read): its previous id is the newest upload when it returned
	ids := map[uint64]bool{}
	for _, x := range all {
		ids[x.e.DataID0] = true
	}
	// a coalesced event never stands for the data id of another upload of the connection
	for _, x := range all {
		if x.e.DataIDSpan == 0 {
			continue
		}
		for _, y := range all {
			if y.e.DataID0 >= x.e.FirstDataID() && y.e.DataID0 < x.e.DataID0 {
				t.Fatalf("%s %s: the coalesced event of %d to %d covers the upload %d", mode.name, conn.name,
					x.e.FirstDataID(), x.e.DataID0, y.e.DataID0)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].e.DataID0 < all[j].e.DataID0 })
	for i := 1; i < len(all); i++ {
		p := all[i].e.PrevDataID0
		if p != 0 && !ids[p] {
			t.Fatalf("%s %s: event %d names the previous data id %d, which no event has", mode.name, conn.name, all[i].e.DataID0, p)
		}
		if p != all[i-1].e.DataID0 {
			st.outOfOrder++
		}
	}
	return st
}

func (st h1Stats) String() string {
	return fmt.Sprintf("calls=%5d events=%5d skippable=%5d skipped calls=%5d skipped events=%4d uploaded=%8d of %8d bytes late=%d",
		st.calls, st.events, st.skippable, st.skippedCalls, st.skippedEvents, st.uploadedBytes, st.realBytes, st.outOfOrder)
}

type recordingListener struct {
	net.Listener
	run *h2cKernelRun
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.run.record(c, "server", false), nil
}

var h1Sizes = []int{1, 100, 1000, 4095, 4096, 10000, 65536, 100000, 262144, 1 << 20}

// goH1Traffic: Go's net/http client and server, keep-alive, a POST of every size answered by a body of the
// same size, both with Content-Length, then a HEAD and a 204 between them
func goH1Traffic(t *testing.T, run *h2cKernelRun) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		switch {
		case r.Method == http.MethodHead:
			w.Header().Set("Content-Length", "5000")
			return
		case n == 3:
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(int(n)))
		_, _ = w.Write(bytes.Repeat([]byte{'r'}, int(n)))
	})}
	go server.Serve(&recordingListener{Listener: listener, run: run})
	defer server.Close()
	transport := &http.Transport{MaxConnsPerHost: 1, DisableCompression: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return run.record(raw, "client", true), nil
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	url := fmt.Sprintf("http://%s/echo", listener.Addr())
	for round := 0; round < 2; round++ {
		for i, size := range h1Sizes {
			resp, err := client.Post(url, "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte{'q'}, size)))
			if err != nil {
				t.Fatal(err)
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if n != int64(size) {
				t.Fatalf("response %d bytes", n)
			}
			if i%4 == 1 {
				// no body: the following messages are still followed
				head, err := client.Head(url)
				if err != nil {
					t.Fatal(err)
				}
				_ = head.Body.Close()
				empty, err := client.Post(url, "text/plain", strings.NewReader("abc"))
				if err != nil {
					t.Fatal(err)
				}
				_ = empty.Body.Close()
			}
		}
	}
}

// h1Session is a recorded client and server connection the traffic of a test is scripted on
type h1Session struct {
	*h2cRawSession
}

func h1Pair(t *testing.T, run *h2cKernelRun) *h1Session {
	return &h1Session{h2cRawPair(t, run)}
}

func h1Settle() { time.Sleep(20 * time.Millisecond) }

// transfer writes the data from one end in writes of writeSize (a pause after each, so the reads find
// them in the socket), then the other end reads it in reads of readSize
func (s *h1Session) transfer(from, to *recordingConn, data []byte, writeSize, readSize int) {
	for off := 0; off < len(data); off += writeSize {
		if _, err := from.Write(data[off:min(len(data), off+writeSize)]); err != nil {
			s.t.Fatal(err)
		}
		h1Settle()
	}
	buf := make([]byte, readSize)
	for got := 0; got < len(data); {
		n, err := to.Read(buf[:min(readSize, len(data)-got)])
		if err != nil {
			s.t.Fatal(err)
		}
		got += n
	}
}

// exchange sends the request from the client and the response from the server
func (s *h1Session) exchange(req []byte, reqWrite, reqRead int, resp []byte, respWrite, respRead int) {
	s.transfer(s.client, s.server, req, reqWrite, reqRead)
	s.transfer(s.server, s.client, resp, respWrite, respRead)
}

// post is a request with a body of n bytes answered by a body of m bytes, both with Content-Length
func (s *h1Session) post(n, m int) {
	req := append([]byte(fmt.Sprintf("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", n)), bytes.Repeat([]byte{'q'}, n)...)
	resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", m)), bytes.Repeat([]byte{'r'}, m)...)
	s.exchange(req, 9000, 7000, resp, 11000, 5000)
}

// mark is the bytes a direction of an end transferred so far
func h1Mark(c *recordingConn, d enums.SocketDataDirection) int {
	c.record.mu.Lock()
	defer c.record.mu.Unlock()
	return len(c.record.real[d])
}

// rawH1Traffic: odd write and read sizes, header and body in one write, the body ending in the call that
// carries the next head
func rawH1Traffic(t *testing.T, run *h2cKernelRun, readSize int) {
	s := h1Pair(t, run)
	defer s.close()
	for i, size := range []int{5000, 300000, 77, 0, 123456} {
		body := bytes.Repeat([]byte{'a' + byte(i)}, size)
		req := []byte(fmt.Sprintf("POST /r%d HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", i, size))
		// the head with the first 100 body bytes in one write, the rest in 7777 byte writes
		first := min(100, size)
		_, _ = s.client.Write(append(append([]byte(nil), req...), body[:first]...))
		for off := first; off < size; off += 7777 {
			h1Settle()
			_, _ = s.client.Write(body[off:min(size, off+7777)])
		}
		want := len(req) + size
		buf := make([]byte, readSize)
		for got := 0; got < want; {
			n, err := s.server.Read(buf[:min(readSize, want-got)])
			if err != nil {
				t.Fatal(err)
			}
			got += n
		}
		// the response: the head alone, then the body in 3 writes, the client reads 333 byte calls
		resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\ncontent-length:  %d \r\n\r\n", size))
		_, _ = s.server.Write(resp)
		for k := 0; k < 3; k++ {
			h1Settle()
			_, _ = s.server.Write(body[k*size/3 : (k+1)*size/3])
		}
		want = len(resp) + size
		cbuf := make([]byte, 333)
		for got := 0; got < want; {
			n, err := s.client.Read(cbuf[:min(333, want-got)])
			if err != nil {
				t.Fatal(err)
			}
			got += n
		}
	}
}

// noBodyH1Traffic: a HEAD answered with a Content-Length and no body, a 204 and a 304 with one, a 100
// Continue in front of a body: the messages behind each are still followed in both directions
func noBodyH1Traffic(t *testing.T, s *h1Session) {
	s.post(50000, 50000)
	s.exchange([]byte("HEAD /h HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 50000\r\n\r\n"), 1000, 1000)
	s.post(30000, 30000)
	s.exchange(append([]byte("POST /n HTTP/1.1\r\nHost: x\r\nContent-Length: 30000\r\n\r\n"), make([]byte, 30000)...), 9000, 7000,
		[]byte("HTTP/1.1 204 No Content\r\nContent-Length: 30000\r\n\r\n"), 1000, 1000)
	s.exchange([]byte("GET /m HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"a\"\r\n\r\n"), 1000, 1000,
		[]byte("HTTP/1.1 304 Not Modified\r\nContent-Length: 5000\r\n\r\n"), 1000, 1000)
	head := []byte("POST /c HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 40000\r\n\r\n")
	s.transfer(s.client, s.server, head, 1000, 1000)
	s.transfer(s.server, s.client, []byte("HTTP/1.1 100 Continue\r\n\r\n"), 1000, 1000)
	s.transfer(s.client, s.server, make([]byte, 40000), 9000, 7000)
	s.transfer(s.server, s.client, append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n"), make([]byte, 40000)...), 11000, 5000)
}

// h1GiveUp is a message a direction cannot be followed behind, and which directions it loses
type h1GiveUp struct {
	name string
	// send transfers the message (and its answer)
	send func(s *h1Session)
	// the requests (r), the responses (p) or both (rp) are lost
	lost string
}

var h1GiveUps = []h1GiveUp{
	{"head split over reads", func(s *h1Session) {
		req := append([]byte("POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 30000\r\n\r\n"), make([]byte, 30000)...)
		s.transfer(s.client, s.server, req, 40000, 30)
		s.transfer(s.server, s.client, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "server"},
	{"another transfer coding", func(s *h1Session) {
		s.exchange([]byte("POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"chunked with a content length", func(s *h1Session) {
		s.exchange([]byte("POST /c HTTP/1.1\r\nHost: x\r\nContent-Length: 15\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"chunk size not hex", func(s *h1Session) {
		s.exchange([]byte("POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5x\r\nhello\r\n0\r\n\r\n"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "r"},
	{"upgrade", func(s *h1Session) {
		s.exchange([]byte("GET /u HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"two content lengths", func(s *h1Session) {
		s.exchange([]byte("POST /t HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"bad content length", func(s *h1Session) {
		s.exchange([]byte("POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 5x\r\n\r\nhello"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"long head", func(s *h1Session) {
		s.exchange([]byte("GET /l HTTP/1.1\r\nHost: x\r\nX-Long: "+strings.Repeat("v", 1100)+"\r\n\r\n"), 4000, 4000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"unknown method", func(s *h1Session) {
		s.exchange([]byte("FETCH /f HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"pipelined", func(s *h1Session) {
		s.transfer(s.client, s.server, []byte("GET /1 HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000)
		s.transfer(s.server, s.client, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
		s.transfer(s.server, s.client, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"connect", func(s *h1Session) {
		s.exchange([]byte("CONNECT x:443 HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 1000, 1000)
	}, "rp"},
	{"switching protocols", func(s *h1Session) {
		s.exchange([]byte("GET /w HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000,
			[]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"), 1000, 1000)
	}, "rp"},
}

// closeMidBodyTraffic: the client sends a head and a part of its body and closes; the server reads it all
// and closes: the calls a direction still holds are uploaded with the close
func closeMidBodyTraffic(t *testing.T, s *h1Session) {
	s.post(40000, 40000)
	head := []byte("POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
	s.transfer(s.client, s.server, append(head, make([]byte, 30000)...), 6000, 6000)
	_ = s.client.Close()
	h1Settle()
	_ = s.server.Close()
}

// overlapTraffic: the client's fd has a blocking read in flight (a thread blocked in read) while the client
// writes a request body on it: those writes overlap a call of their fd and are never skipped, the ones
// before are. The read returns after them, with a smaller data id, so it is read in front of them: the
// connection is not followed anymore behind it. mark is called before the overlap.
func overlapTraffic(t *testing.T, s *h1Session, mark func()) {
	s.post(40000, 40000)
	mark()
	raw, err := s.client.Conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	_ = raw.Control(func(f uintptr) { fd = int(f) })
	if err := syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	head := []byte("POST /o HTTP/1.1\r\nHost: x\r\nContent-Length: 60000\r\n\r\n")
	resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 30000\r\n\r\n"), make([]byte, 30000)...)
	var wg sync.WaitGroup
	wg.Add(1)
	var readErr error
	var first int
	go func() {
		defer wg.Done()
		// the response arrives after the whole request body: the read is in flight meanwhile
		buf := make([]byte, 64<<10)
		n, err := syscall.Read(fd, buf)
		if err != nil {
			readErr = err
			return
		}
		first = n
		s.client.record.add(enums.SocketDataDirectionIngress, buf[:n])
	}()
	time.Sleep(100 * time.Millisecond)
	write := func(p []byte) {
		n, err := syscall.Write(fd, p)
		if err != nil || n != len(p) {
			t.Errorf("write: %d %v", n, err)
		}
		s.client.record.add(enums.SocketDataDirectionEgress, p[:n])
		h1Settle()
	}
	write(head)
	for i := 0; i < 6; i++ {
		write(make([]byte, 10000))
	}
	readAll := func(c *recordingConn, n int) {
		buf := make([]byte, 7000)
		for got := 0; got < n; {
			k, err := c.Read(buf[:min(7000, n-got)])
			if err != nil {
				t.Fatal(err)
			}
			got += k
		}
	}
	readAll(s.server, len(head)+60000)
	if _, err := s.server.Write(resp); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	readAll(s.client, len(resp)-first)
	s.post(40000, 40000)
}

func TestHTTP1BodySkipBPFGo(t *testing.T) {
	requireBPF(t)
	for _, mode := range h1BPFModes {
		run := withH1SkipBPF(t, mode, func(run *h2cKernelRun) { goH1Traffic(t, run) })
		if len(run.conns) != 2 {
			t.Fatalf("%d connections", len(run.conns))
		}
		for _, conn := range run.conns {
			st := checkH1Conn(t, conn, mode, h1NoLimits(), false)
			t.Logf("%-8s %-14s %s", mode.name, conn.name, st)
			if h1LateRead(conn) {
				// a read returned after a call that entered after it (a read descheduled inside the syscall while
				// the request went out and the answer came): BPF does not follow the connection behind it
				t.Logf("%s %s: a read returned late, the skipping stopped there", mode.name, conn.name)
				continue
			}
			if mode.skip && st.skippedCalls*10 < st.skippable*8 {
				h1DumpEvents(t, conn, 60)
				t.Fatalf("%s %s: only %d of %d skippable calls skipped", mode.name, conn.name, st.skippedCalls, st.skippable)
			}
		}
	}
}

func TestHTTP1BodySkipBPFRaw(t *testing.T) {
	requireBPF(t)
	for _, mode := range h1BPFModes {
		for _, readSize := range []int{4096, 50} {
			run := withH1SkipBPF(t, mode, func(run *h2cKernelRun) { rawH1Traffic(t, run, readSize) })
			for _, conn := range run.conns {
				st := checkH1Conn(t, conn, mode, h1NoLimits(), true)
				t.Logf("%-8s read%-5d %-14s %s", mode.name, readSize, conn.name, st)
				for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
					// the server reads the first head in 50 byte calls: the requests are lost, and with them the
					// responses, which cannot tell the request they answer
					if !mode.skip || (readSize < 1000 && !conn.client) {
						continue
					}
					if st.skippedIn[d] != st.skippableIn[d] {
						t.Fatalf("%s %s %s: %d of %d skippable calls skipped", mode.name, conn.name, directionName(d),
							st.skippedIn[d], st.skippableIn[d])
					}
				}
			}
		}
	}
}

// TestHTTP1BodySkipBPFNoBody: the bodies behind a HEAD, a 204, a 304 and a 100 Continue are still skipped
func TestHTTP1BodySkipBPFNoBody(t *testing.T) {
	requireBPF(t)
	for _, mode := range h1BPFModes {
		var marks [2][3]int
		run := withH1SkipBPF(t, mode, func(run *h2cKernelRun) {
			s := h1Pair(t, run)
			defer s.close()
			noBodyH1Traffic(t, s)
			for i, c := range []*recordingConn{s.server, s.client} {
				for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
					marks[i][d] = h1Mark(c, d)
				}
			}
			s.post(50000, 50000)
		})
		for i, conn := range run.conns {
			st := checkH1Conn(t, conn, mode, h1NoLimits(), true)
			t.Logf("%-8s %-14s %s", mode.name, conn.name, st)
			if !mode.skip {
				continue
			}
			if st.skippedCalls != st.skippable {
				t.Fatalf("%s %s: %d of %d skippable calls skipped", mode.name, conn.name, st.skippedCalls, st.skippable)
			}
			for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
				if st.lastSkipped[d] <= marks[i][d] {
					t.Fatalf("%s %s %s: nothing skipped in the last exchange", mode.name, conn.name, directionName(d))
				}
			}
		}
	}
}

// TestHTTP1BodySkipBPFGiveUps: behind a message the cursor cannot follow, nothing of the directions it
// loses is skipped anymore, and before it everything is
func TestHTTP1BodySkipBPFGiveUps(t *testing.T) {
	requireBPF(t)
	for _, g := range h1GiveUps {
		for _, mode := range h1BPFModes[1:] {
			var limits [2]h1Limits
			run := withH1SkipBPF(t, mode, func(run *h2cKernelRun) {
				s := h1Pair(t, run)
				defer s.close()
				s.post(40000, 40000)
				for i, c := range []*recordingConn{s.server, s.client} {
					limits[i] = h1NoLimits()
					requests, responses := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
					if c == s.client {
						requests, responses = responses, requests
					}
					lost := g.lost
					if lost == "server" {
						lost = map[bool]string{true: "rp", false: ""}[c == s.server]
					}
					if strings.Contains(lost, "r") {
						limits[i].upTo[requests] = h1Mark(c, requests)
					}
					if strings.Contains(lost, "p") {
						limits[i].upTo[responses] = h1Mark(c, responses)
					}
				}
				g.send(s)
				if g.name != "switching protocols" && g.name != "connect" {
					s.post(40000, 40000)
				}
			})
			for i, conn := range run.conns {
				st := checkH1Conn(t, conn, mode, limits[i], true)
				t.Logf("%-22s %-8s %-14s %s", g.name, mode.name, conn.name, st)
				for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
					if st.skippedIn[d] == 0 {
						t.Fatalf("%s %s %s %s: nothing skipped before the give up", g.name, mode.name, conn.name, directionName(d))
					}
				}
			}
		}
	}
}

// TestHTTP1BodySkipBPFCloseMidBody: the calls held for the coalesced event are uploaded with the close
func TestHTTP1BodySkipBPFCloseMidBody(t *testing.T) {
	requireBPF(t)
	for _, mode := range h1BPFModes {
		run := withH1SkipBPF(t, mode, func(run *h2cKernelRun) {
			s := h1Pair(t, run)
			defer s.close()
			closeMidBodyTraffic(t, s)
		})
		for _, conn := range run.conns {
			st := checkH1Conn(t, conn, mode, h1NoLimits(), true)
			t.Logf("%-8s %-14s %s", mode.name, conn.name, st)
			if mode.skip && st.skippedCalls != st.skippable {
				t.Fatalf("%s %s: %d of %d skippable calls skipped", mode.name, conn.name, st.skippedCalls, st.skippable)
			}
		}
	}
}

// TestHTTP1BodySkipBPFOverlap: the writes made while a read of the fd was in flight are uploaded in whole,
// and nothing of the connection is skipped behind the read that returned late
func TestHTTP1BodySkipBPFOverlap(t *testing.T) {
	requireBPF(t)
	for _, mode := range h1BPFModes {
		var limits h1Limits
		run := withH1SkipBPF(t, mode, func(run *h2cKernelRun) {
			s := h1Pair(t, run)
			defer s.close()
			overlapTraffic(t, s, func() {
				for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
					limits.upTo[d] = h1Mark(s.client, d)
				}
			})
		})
		for _, conn := range run.conns {
			if !conn.client {
				st := checkH1Conn(t, conn, mode, h1NoLimits(), false)
				t.Logf("%-8s %-14s %s", mode.name, conn.name, st)
				if mode.skip && st.skippedCalls != st.skippable {
					t.Fatalf("%s: %d of %d skippable calls skipped", mode.name, st.skippedCalls, st.skippable)
				}
				continue
			}
			// nothing of the client is skipped behind the overlap
			st := checkH1Conn(t, conn, mode, limits, false)
			t.Logf("%-8s %-14s %s", mode.name, conn.name, st)
			overlapped, overlappedBody := 0, 0
			for _, e := range conn.events[enums.SocketDataDirectionEgress] {
				if e.InFlight == 2 {
					overlapped++
					if e.TotalSize0 == 10000 {
						overlappedBody++
					}
					if e.PayloadSkipped0 != 0 {
						t.Fatalf("%s: a write that overlapped a read was skipped", mode.name)
					}
				}
			}
			if overlapped != 7 || overlappedBody != 6 {
				t.Fatalf("%s: %d writes overlapped the read, %d of the body", mode.name, overlapped, overlappedBody)
			}
			// everything in front of the overlap
			for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
				if mode.skip && st.skippedIn[d] == 0 {
					t.Fatalf("%s %s: nothing skipped in front of the overlap", mode.name, directionName(d))
				}
			}
		}
	}
}

// the offsets of the fields of a perf record of the socket data event (bpf/accesslog/include/socket_data_event.h)
const (
	h1OffFinished       = 3
	h1OffSequence       = 4
	h1OffDataLen        = 6
	h1OffInFlight       = 14
	h1OffStartTime      = 16
	h1OffEndTime        = 24
	h1OffDataID         = 48
	h1OffPrevDataID     = 56
	h1OffTotalSize      = 64
	h1OffL4Count        = 2
	h1OffL4Size         = 72
	h1OffPayloadSkipped = 81
	h1OffDataIDSpan     = 86
	h1HeaderSize        = 100
)

// h1RecordedTraffic is the traffic of perf records as the reader read them
func h1RecordedTraffic(samples [][]byte) *h1Traffic {
	traffic := &h1Traffic{expected: map[uint64][]h1Expected{}, disturbed: map[uint64]bool{}}
	for i, sample := range samples {
		e := &aclevents.SocketDataUploadEvent{}
		e.ReadFrom(btf.NewReader(sample))
		traffic.records = append(traffic.records, h1Record{sample: sample, conn: e.ConnectionID, first: e.Sequence0 == 0, slot: i})
	}
	return traffic
}

// h1Unskipped rebuilds the records BPF would have uploaded without skipping from the records of a run with
// skip_http1_body_payload_bpf: every call uploaded without its content gets its real bytes (in 20480 byte
// chunks), and a coalesced event becomes the calls it stands for (with the data ids of its span, the L4
// counters on the first, the times of the event), which is what merging the kernel logs makes the same
func h1Unskipped(t *testing.T, run *h2cKernelRun, samples [][]byte) [][]byte {
	t.Helper()
	type key struct {
		port uint16
		dir  enums.SocketDataDirection
		id   uint64
	}
	// the offset of every call in the real stream of its direction, and the index of its first call
	offsets, firstCall := map[key]int{}, map[key]int{}
	conns := map[uint16]*h2cKernelConn{}
	for _, conn := range run.conns {
		conns[conn.port] = conn
		for d, events := range conn.events {
			off, call := 0, 0
			for _, e := range events {
				if e.Sequence0 != 0 {
					continue
				}
				k := key{conn.port, enums.SocketDataDirection(d), e.DataID0}
				offsets[k], firstCall[k] = off, call
				off += int(e.TotalSize0)
				for sum := 0; sum < int(e.TotalSize0) && call < len(conn.calls[d]); call++ {
					sum += conn.calls[d][call]
				}
			}
		}
	}
	var out [][]byte
	for _, sample := range samples {
		if sample[h1OffPayloadSkipped] != 1 {
			out = append(out, sample)
			continue
		}
		e := &aclevents.SocketDataUploadEvent{}
		e.ReadFrom(btf.NewReader(sample))
		conn := conns[e.LocalPort]
		k := key{e.LocalPort, e.Direction0, e.DataID0}
		off, call := offsets[k], firstCall[k]
		var sizes []int
		for sum := 0; sum < int(e.TotalSize0); call++ {
			sizes = append(sizes, conn.calls[e.Direction0][call])
			sum += sizes[len(sizes)-1]
		}
		if len(sizes) > 1+int(e.DataIDSpan) {
			t.Fatalf("an event of %d calls spans %d data ids", len(sizes), e.DataIDSpan)
		}
		prev := e.PrevDataID0
		for i, size := range sizes {
			id := e.FirstDataID() + uint64(i)
			if i == len(sizes)-1 {
				id = e.DataID0
			}
			real := conn.real[e.Direction0][off : off+size]
			off += size
			for seq := 0; seq == 0 || len(real) > 0; seq++ {
				n := min(len(real), 20480)
				r := append(append([]byte(nil), sample[:h1HeaderSize]...), real[:n]...)
				real = real[n:]
				binary.LittleEndian.PutUint16(r[h1OffSequence:], uint16(seq))
				binary.LittleEndian.PutUint16(r[h1OffDataLen:], uint16(n))
				binary.LittleEndian.PutUint64(r[h1OffDataID:], id)
				binary.LittleEndian.PutUint64(r[h1OffPrevDataID:], prev)
				binary.LittleEndian.PutUint64(r[h1OffTotalSize:], uint64(size))
				binary.LittleEndian.PutUint16(r[h1OffDataIDSpan:], 0)
				r[h1OffPayloadSkipped] = 0
				r[h1OffFinished] = 0
				if len(real) == 0 {
					r[h1OffFinished] = 1
				}
				if i > 0 {
					r[h1OffL4Count] = 0
					binary.LittleEndian.PutUint64(r[h1OffL4Size:], 0)
				}
				out = append(out, r)
			}
			prev = id
		}
	}
	return out
}

// TestHTTP1BodySkipRecordedStreams analyzes the perf records of Go's client and server as the reader read
// them: with BPF uploading every call, with and without the user space skipping, and with the calls in flight
// hidden, as an older BPF side uploads them; with skip_http1_body_payload_bpf, against the records rebuilt
// with the real bytes of the skipped calls, without and with the coalescing (and the merging of the kernel
// logs). The access logs must be the same bytes.
func TestHTTP1BodySkipRecordedStreams(t *testing.T) {
	requireBPF(t)
	_, samples := withH1SkipBPFRecorded(t, h1BPFModes[0], func(run *h2cKernelRun) { goH1Traffic(t, run) })
	traffic := h1RecordedTraffic(samples)
	hidden := h1RecordedTraffic(h1HideInFlight(samples))
	for _, every := range []int{1, 7, 1 << 30} {
		off := h1SkipRun(t, traffic, false, every)
		on := h1SkipRun(t, traffic, true, every)
		before := h1SkipRun(t, hidden, true, every)
		h1AssertSameOutputs(t, "user space skipping", off.outputs, on.outputs)
		h1AssertSameOutputs(t, "user space skipping without the calls in flight", off.outputs, before.outputs)
		// both ends of every exchange; the reader reads the per CPU buffers in turn, which the analysis does
		// not always put back in order (a few exchanges)
		if len(off.outputs) < 3*(len(h1Sizes)+2*3) {
			t.Fatalf("%d access logs", len(off.outputs))
		}
		if testing.Verbose() && every == 1 {
			var metrics bytes.Buffer
			_ = telemetry.Write(&metrics)
			for _, line := range strings.Split(metrics.String(), "\n") {
				if strings.HasPrefix(line, "rover_http1_body_skip") {
					t.Log(line)
				}
			}
		}
		t.Logf("every %d: %d records, the user space skips %d (%.1f%%) with the calls in flight, %d (%.1f%%) without", every,
			on.records, on.skipped, 100*float64(on.skipped)/float64(on.records), before.skipped,
			100*float64(before.skipped)/float64(before.records))
		if every == 1 && on.skipped <= before.skipped {
			t.Fatalf("the calls in flight do not let the user space skip: %d skipped with them, %d without", on.skipped, before.skipped)
		}
	}
	for _, traffic := range []struct {
		name string
		f    func(t *testing.T, run *h2cKernelRun)
	}{{"content-length", goH1Traffic}, {"chunked", goChunkedTraffic}} {
		h1RecordedBPFStreams(t, traffic.name, traffic.f)
	}
}

// h1RecordedBPFStreams is TestHTTP1BodySkipRecordedStreams for the BPF skipping of the traffic
func h1RecordedBPFStreams(t *testing.T, name string, traffic func(t *testing.T, run *h2cKernelRun)) {
	for _, mode := range h1BPFModes[1:] {
		run, samples := withH1SkipBPFRecorded(t, mode, func(run *h2cKernelRun) { traffic(t, run) })
		// every call is in the events: uploaded with its bytes, or in a skipped event
		late := false
		for _, conn := range run.conns {
			checkH1Conn(t, conn, mode, h1NoLimits(), false)
			for _, events := range conn.events {
				for _, e := range events {
					late = late || e.PrevDataID0 > e.DataID0
				}
			}
		}
		if late {
			// a read returned after calls that entered after it (BPF stops following the connection there):
			// the analyzer reads it in front of them, out of step with or without the skipping, and the rebuilt
			// calls of a coalesced event take data ids of their own, so the logs are not comparable
			t.Logf("%s %s: a read returned late, the logs are not compared", name, mode.name)
			continue
		}
		// in the order of the data ids: the reader reads the per CPU buffers in turn, and a call read late puts
		// the analysis out of step now and then, differently with the bytes of a call than without
		samples = h1InDataIDOrder(samples)
		on := h1RecordedTraffic(samples)
		off := h1RecordedTraffic(h1Unskipped(t, run, samples))
		on.merge, off.merge = mode.coalesce, mode.coalesce
		for _, merge := range []bool{false, true} {
			if mode.coalesce && !merge {
				continue
			}
			on.merge, off.merge = merge, merge
			for _, every := range []int{1, 7, 1 << 30} {
				offRun := h1SkipRun(t, off, false, every)
				onRun := h1SkipRun(t, on, false, every)
				if want := map[string]int{"chunked": 16, "content-length": 64}[name]; len(onRun.outputs) != want {
					for _, conn := range run.conns {
						h1DumpEvents(t, conn, 1000)
					}
					t.Fatalf("%s %s every %d: %d access logs, %d expected", name, mode.name, every, len(onRun.outputs), want)
				}
				h1AssertSameOutputs(t, fmt.Sprintf("%s %s merge=%t every %d", name, mode.name, merge, every), offRun.outputs, onRun.outputs)
				if every == 1 {
					t.Logf("%s %s merge=%t: %d records (%d rebuilt), %d uploaded without content, %d access logs", name, mode.name, merge,
						onRun.records, offRun.records, onRun.bpfSkipped, len(onRun.outputs))
				}
			}
		}
	}
}

// h1HideInFlight is the records with the calls in flight unknown, as an older BPF side uploads them
func h1HideInFlight(samples [][]byte) [][]byte {
	out := make([][]byte, len(samples))
	for i, sample := range samples {
		out[i] = append([]byte(nil), sample...)
		binary.LittleEndian.PutUint16(out[i][h1OffInFlight:], 0)
	}
	return out
}

// h1InDataIDOrder orders the records by connection, data id and sequence
func h1InDataIDOrder(samples [][]byte) [][]byte {
	sorted := append([][]byte(nil), samples...)
	field := func(s []byte, off int) uint64 { return binary.LittleEndian.Uint64(s[off:]) }
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if field(a, 32) != field(b, 32) {
			return field(a, 32) < field(b, 32)
		}
		if field(a, h1OffDataID) != field(b, h1OffDataID) {
			return field(a, h1OffDataID) < field(b, h1OffDataID)
		}
		return binary.LittleEndian.Uint16(a[h1OffSequence:]) < binary.LittleEndian.Uint16(b[h1OffSequence:])
	})
	return sorted
}

// h1DumpEvents logs the first events of a connection in data id order, for a failure
func h1DumpEvents(t *testing.T, conn *h2cKernelConn, n int) {
	var all []*aclevents.SocketDataUploadEvent
	for _, events := range conn.events {
		all = append(all, events...)
	}
	sort.SliceStable(all, func(i, j int) bool { return h2cUploadBefore(all[i], all[j]) })
	for i, e := range all {
		if i == n {
			break
		}
		t.Logf("%s id=%d prev=%d seq=%d dir=%d total=%d len=%d skipped=%d span=%d inflight=%d", conn.name, e.DataID0,
			e.PrevDataID0, e.Sequence0, e.Direction0, e.TotalSize0, e.DataLen, e.PayloadSkipped0, e.DataIDSpan, e.InFlight)
	}
}

// TestSocketDataIDsAreUnique: threads writing on one fd at once each take their own data id, also on the
// later connections that reuse the fd (the claims of the ids name the generator entry)
func TestSocketDataIDsAreUnique(t *testing.T) {
	requireBPF(t)
	const writers, writes, connections = 16, 64, 4
	run := withH1SkipBPF(t, h1BPFModes[0], func(run *h2cKernelRun) {
		for n := 0; n < connections; n++ {
			s := h1Pair(t, run)
			raw, err := s.client.Conn.(*net.TCPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var fd int
			_ = raw.Control(func(f uintptr) { fd = int(f) })
			s.transfer(s.client, s.server, []byte("POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n"), 1000, 1000)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.Copy(io.Discard, s.server)
			}()
			var wg sync.WaitGroup
			start := make(chan struct{})
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					p := bytes.Repeat([]byte{'w'}, 64)
					for i := 0; i < writes; i++ {
						// the raw syscall: net.Conn serializes its writes
						_, _ = syscall.Write(fd, p)
					}
				}()
			}
			close(start)
			wg.Wait()
			_ = s.client.Close()
			<-done
			s.close()
		}
	})
	for _, conn := range run.conns {
		if !conn.client {
			continue
		}
		seen := map[uint64]bool{}
		calls := 0
		for _, e := range conn.events[enums.SocketDataDirectionEgress] {
			if e.Sequence0 != 0 {
				continue
			}
			calls++
			if seen[e.DataID0] {
				t.Fatalf("%s: data id %d taken twice", conn.name, e.DataID0)
			}
			seen[e.DataID0] = true
		}
		t.Logf("%s: %d writes, every data id unique", conn.name, calls)
		if calls < writers*writes {
			t.Fatalf("%s: %d writes uploaded", conn.name, calls)
		}
	}
}

// transferReads writes the data from one end in writes of writeSize, then reads it at the other end in reads
// of the sizes given (the last one repeated)
func (s *h1Session) transferReads(from, to *recordingConn, data []byte, writeSize int, reads ...int) {
	for off := 0; off < len(data); off += writeSize {
		if _, err := from.Write(data[off:min(len(data), off+writeSize)]); err != nil {
			s.t.Fatal(err)
		}
		h1Settle()
	}
	buf := make([]byte, 64<<10)
	for got, i := 0, 0; got < len(data); i++ {
		size := reads[min(i, len(reads)-1)]
		n, err := to.Read(buf[:min(size, len(data)-got)])
		if err != nil {
			s.t.Fatal(err)
		}
		got += n
	}
}

// h1Chunked frames the pieces as chunks, each with the extension when there is one, and the trailer lines
func h1Chunked(pieces []int, ext string, trailers string) []byte {
	var b bytes.Buffer
	for i, n := range pieces {
		fmt.Fprintf(&b, "%x%s\r\n", n, ext)
		b.Write(bytes.Repeat([]byte{'a' + byte(i%26)}, n))
		b.WriteString("\r\n")
	}
	b.WriteString("0\r\n" + trailers + "\r\n")
	return b.Bytes()
}

// rawChunkedTraffic: chunked requests and responses of every shape on one keep-alive connection, then a
// Content-Length exchange behind them
func rawChunkedTraffic(t *testing.T, s *h1Session) {
	chunkedReq := []byte("POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	chunkedResp := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding:  Chunked \r\n\r\n")
	ok := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	// one chunk of 30000 bytes, sent by the client
	s.transfer(s.client, s.server, append(append([]byte(nil), chunkedReq...), h1Chunked([]int{30000}, "", "")...), 9000, 7000)
	s.transfer(s.server, s.client, ok, 1000, 1000)
	// chunks with extensions, and trailers
	s.transfer(s.client, s.server, []byte("GET /e HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000)
	s.transfer(s.server, s.client, append(append([]byte(nil), chunkedResp...), h1Chunked([]int{4096, 8192, 20000}, ";name=value", "X-Checksum: 1\r\nX-More: 2\r\n")...), 11000, 5000)
	// the size lines cut by the reads (3 bytes at a time around them), the last chunk in a call of its own
	s.transfer(s.client, s.server, []byte("GET /s HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000)
	body := h1Chunked([]int{10000, 10000}, "", "")
	s.transfer(s.server, s.client, chunkedResp, 1000, 1000)
	s.transferReads(s.server, s.client, body[:len(body)-5], 30000, 3, 3, 3, 3000, 7000, 2, 2, 2, 2, 2, 2, 5000)
	s.transferReads(s.server, s.client, body[len(body)-5:], 1000, 1000)
	// a Content-Length exchange behind the chunked ones (keep-alive)
	s.post(40000, 40000)
	// many small chunks in one call: more boundaries than BPF follows in a call (that direction is lost)
	small := make([]int, 40)
	for k := range small {
		small[k] = 10
	}
	s.transfer(s.client, s.server, []byte("GET /m HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000)
	s.transfer(s.server, s.client, append(append([]byte(nil), chunkedResp...), h1Chunked(small, "", "")...), 4000, 4000)
}

// rawCloseTraffic: a response delimited by the close, whose body comes in calls of every size, one of them
// starting like a message
func rawCloseTraffic(t *testing.T, s *h1Session) {
	s.post(40000, 40000)
	s.transfer(s.client, s.server, []byte("GET /stream HTTP/1.1\r\nHost: x\r\n\r\n"), 1000, 1000)
	s.transfer(s.server, s.client, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nfirst bytes"), 1000, 1000)
	for _, part := range [][]byte{bytes.Repeat([]byte{'b'}, 20000), []byte("short"), bytes.Repeat([]byte{'c'}, 3000),
		[]byte("GET /not-a-request HTTP/1.1\r\n...."), bytes.Repeat([]byte{'d'}, 9), bytes.Repeat([]byte{'e'}, 5000),
		bytes.Repeat([]byte{'f'}, 30000)} {
		s.transfer(s.server, s.client, part, 64<<10, 64<<10)
	}
	_ = s.server.Close()
	h1Settle()
}

// goChunkedTraffic: Go's server streams chunked responses (a write and a flush per piece, and io.Copy of a
// reader of unknown length), and Go's client sends chunked request bodies, keep-alive
func goChunkedTraffic(t *testing.T, run *h2cKernelRun) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pieces := []int{1, 100, 5000, 40000, 3, 100000}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/flush" {
			for _, p := range pieces {
				_, _ = w.Write(bytes.Repeat([]byte{'f'}, p))
				w.(http.Flusher).Flush()
			}
			return
		}
		// io.Copy of a reader of unknown length: chunks of 32KB
		_, _ = io.Copy(w, struct{ io.Reader }{bytes.NewReader(bytes.Repeat([]byte{'r'}, int(n)))})
	})}
	go server.Serve(&recordingListener{Listener: listener, run: run})
	defer server.Close()
	transport := &http.Transport{MaxConnsPerHost: 1, DisableCompression: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return run.record(raw, "client", true), nil
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for round := 0; round < 2; round++ {
		for _, size := range []int{10000, 300000} {
			// a body of unknown length goes out chunked
			req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/copy", listener.Addr()),
				struct{ io.Reader }{bytes.NewReader(bytes.Repeat([]byte{'q'}, size))})
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := io.Copy(io.Discard, resp.Body); n != int64(size) {
				t.Fatalf("response %d bytes", n)
			}
			_ = resp.Body.Close()
		}
		resp, err := client.Get(fmt.Sprintf("http://%s/flush", listener.Addr()))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		// and a Content-Length exchange behind them
		resp, err = client.Post(fmt.Sprintf("http://%s/copy", listener.Addr()), "text/plain", bytes.NewReader(make([]byte, 1000)))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// TestHTTP1BodySkipBPFChunked: the data of chunked bodies is skipped (raw senders of every chunk shape, Go's
// streaming server and chunked client), the calls holding framing bytes are uploaded, and the messages behind
// are followed
func TestHTTP1BodySkipBPFChunked(t *testing.T) {
	requireBPF(t)
	for _, tr := range []struct {
		name string
		f    func(run *h2cKernelRun)
	}{
		{"raw", func(run *h2cKernelRun) {
			s := h1Pair(t, run)
			defer s.close()
			rawChunkedTraffic(t, s)
		}},
		{"go", func(run *h2cKernelRun) { goChunkedTraffic(t, run) }},
	} {
		var uploaded [2]int
		for i, mode := range h1BPFModes {
			run := withH1SkipBPF(t, mode, tr.f)
			total := 0
			for _, conn := range run.conns {
				st := checkH1Conn(t, conn, mode, h1NoLimits(), tr.name == "raw")
				t.Logf("%-5s %-8s %-14s %s", tr.name, mode.name, conn.name, st)
				if i == 0 {
					h1LogChunking(t, tr.name, conn)
				}
				total += st.realBytes
				if i < 2 {
					uploaded[i] += st.uploadedBytes
				}
				if mode.skip && st.skippedCalls == 0 {
					t.Fatalf("%s %s %s: nothing skipped", tr.name, mode.name, conn.name)
				}
			}
			if i == 1 {
				t.Logf("%s: %d bytes uploaded without the skipping, %d with it (%.1f%%)", tr.name, uploaded[0], uploaded[1],
					100*float64(uploaded[1])/float64(uploaded[0]))
			}
		}
	}
}

// TestHTTP1BodySkipBPFClose: the calls behind the head of a response delimited by the close are skipped but
// where the analyzer looks for a message start in them
func TestHTTP1BodySkipBPFClose(t *testing.T) {
	requireBPF(t)
	for _, mode := range h1BPFModes {
		run := withH1SkipBPF(t, mode, func(run *h2cKernelRun) {
			s := h1Pair(t, run)
			defer s.close()
			rawCloseTraffic(t, s)
		})
		for _, conn := range run.conns {
			st := checkH1Conn(t, conn, mode, h1NoLimits(), true)
			t.Logf("%-8s %-14s %s", mode.name, conn.name, st)
			if !conn.client || !mode.skip {
				continue
			}
			// the response body: of 7 calls, the 20000 and 30000 byte ones; the 3000 and 5000 byte ones follow a
			// call shorter than 16 bytes (the analyzer reads into them), the others are short or start like a
			// request
			var skipped []uint64
			for _, e := range conn.events[enums.SocketDataDirectionIngress] {
				if e.PayloadSkipped0 == 1 {
					skipped = append(skipped, e.TotalSize0)
				}
			}
			if !strings.HasSuffix(fmt.Sprint(skipped), "20000 30000]") {
				t.Fatalf("%s: skipped %v", mode.name, skipped)
			}
		}
	}
}

// h1LogChunking logs how the chunked bodies of the connection are cut: the chunk sizes, and the chunk
// boundaries (gaps between chunk data) per socket call that holds any
func h1LogChunking(t *testing.T, name string, conn *h2cKernelConn) {
	framing := h1Frame(conn.real)
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		sizes := map[int]int{}
		for _, r := range framing.bodies[d] {
			sizes[r[1]-r[0]]++
		}
		perCall := map[int]int{}
		off := 0
		for _, c := range conn.calls[d] {
			n := 0
			for k := 1; k < len(framing.bodies[d]); k++ {
				gap := framing.bodies[d][k-1][1]
				if gap >= off && gap < off+c {
					n++
				}
			}
			if n > 0 {
				perCall[n]++
			}
			off += c
		}
		t.Logf("%s %s %s: chunk data sizes %v, calls by chunk boundaries %v", name, conn.name, directionName(d), sizes, perCall)
	}
}

// h1LateRead tells whether a call of the connection returned after a call that entered after it uploaded (its
// previous data id is the larger one)
func h1LateRead(conn *h2cKernelConn) bool {
	for _, events := range conn.events {
		for _, e := range events {
			if e.PrevDataID0 > e.DataID0 {
				return true
			}
		}
	}
	return false
}
