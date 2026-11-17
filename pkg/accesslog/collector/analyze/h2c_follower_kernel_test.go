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
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The follower of the frames on the kernel (skywalking-rover/bpf/accesslog/syscalls/h2c.h) with the access log event
// layout: a read that only peeks, frames forged into payloads and header blocks, payloads of many streams at once,
// forged frame headers inside a skipped payload, and the skipping together with the dropping. They check what is
// uploaded against the bytes the endpoints really read and what the analyzer reports over it. They need root and
// are skipped otherwise; the hand cut calls of the same follower are in h2c_follower_test.go.

// continuation is a CONTINUATION frame of the raw client
func (s *h2cRawSession) continuation(stream uint32, endHeaders bool, block []byte) []byte {
	_ = s.peer.framer.WriteContinuation(stream, endHeaders, block)
	return s.peer.take()
}

// h2cPeek makes the server peek at the next n bytes of its connection with recvfrom(MSG_PEEK)
func h2cPeek(t *testing.T, s *h2cRawSession, n int) {
	t.Helper()
	raw, err := s.server.Conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	peeked := make([]byte, n)
	var peekErr error
	if err := raw.Read(func(fd uintptr) bool {
		_, _, peekErr = unix.Recvfrom(int(fd), peeked, unix.MSG_PEEK)
		return !errors.Is(peekErr, unix.EAGAIN)
	}); err != nil || peekErr != nil {
		t.Fatalf("peek: %v %v", err, peekErr)
	}
}

// h2cPeekEvents are the events of the peeks of the direction: decoded as the kernel log of their call alone (no
// protocol, no bytes, no previous upload), with the details of the recvfrom
func h2cPeekEvents(t *testing.T, conn *h2cKernelConn, d enums.SocketDataDirection) []*aclevents.SocketDataUploadEvent {
	t.Helper()
	var peeks []*aclevents.SocketDataUploadEvent
	for _, e := range conn.events[d] {
		if !e.Peek() {
			continue
		}
		if e.GetFunctionName() != enums.SocketFunctionNameRecvfrom || e.Protocol() != enums.ConnectionProtocolUnknown ||
			e.BufferLen() != 0 || e.PrevDataID0 != 0 || e.L4PackageCount == 0 || e.L4TotalPackageSize == 0 {
			t.Fatalf("a peek is decoded as %+v", *e.Detach())
		}
		if forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, e) == nil {
			t.Fatalf("a peek has no kernel log")
		}
		peeks = append(peeks, e)
	}
	return peeks
}

// TestH2CPeek peeks at frames the server has not read yet: a peek is no read, so the follower does not move
// with it: the WINDOW_UPDATE frames read after it are dropped as the one before it is, and the peek is uploaded
// once, as the kernel log of its call without its bytes
func TestH2CPeek(t *testing.T) {
	requireBPF(t)
	var first, second, third []byte
	run := withAccessLogBPF(t, true, func(run *h2cKernelRun) {
		s := h2cRawPair(t, run)
		defer s.close()
		peer := s.peer
		first, second, third = peer.windowUpdate(0, 1), peer.windowUpdate(0, 2), peer.windowUpdate(0, 3)
		s.write([]byte(http2.ClientPreface), peer.settings())
		s.read(len(http2.ClientPreface), 9)
		s.write(first)
		s.read(9, 4)
		s.write(second, third)
		h2cPeek(t, s, 13)
		s.read(9, 4, 9, 4)
	})
	server := run.conns[0]
	checkPrevDataIDs(t, server)
	checkLayoutFields(t, server, enums.SocketFunctionNameRecvfrom)
	if peeks := h2cPeekEvents(t, server, enums.SocketDataDirectionIngress); len(peeks) != 1 {
		t.Fatalf("%d peek uploads", len(peeks))
	}
	for _, e := range server.events[enums.SocketDataDirectionIngress] {
		if data := e.BufferData(); bytes.Equal(data, first[9:]) || bytes.Equal(data, second[9:]) || bytes.Equal(data, third[9:]) {
			t.Fatalf("a WINDOW_UPDATE is uploaded (data id %d): the peek moved the follower", e.DataID0)
		}
	}
	t.Logf("%d socket calls, %d uploads of the server ingress", len(server.calls[enums.SocketDataDirectionIngress]),
		len(server.events[enums.SocketDataDirectionIngress]))
}

// TestH2CPeekHeaders peeks at a HEADERS frame whose header block indexes the dynamic table, before the server
// receives it: the header block is decoded once (as received), so every stream is reported with its own path, and
// the peek is the kernel log of its call
func TestH2CPeekHeaders(t *testing.T) {
	requireBPF(t)
	for _, drop := range []bool{false, true} {
		run := withAccessLogBPF(t, drop, func(run *h2cKernelRun) {
			s := h2cRawPair(t, run)
			defer s.close()
			s.send(append([]byte(http2.ClientPreface), s.peer.settings()...))
			s.serverWrite(s.responder.settings())
			for i, stream := range []uint32{1, 3, 5} {
				frame := s.peer.headers(stream, true, h2cRequest(fmt.Sprintf("/peek/%d", stream))...)
				s.write(frame)
				if i > 0 {
					h2cPeek(t, s, len(frame))
				}
				s.read(9, len(frame)-9)
				s.respond(stream, 10)
			}
		})
		server := run.conns[0]
		checkPrevDataIDs(t, server)
		checkLayoutFields(t, server, enums.SocketFunctionNameRecvfrom)
		if peeks := h2cPeekEvents(t, server, enums.SocketDataDirectionIngress); len(peeks) != 2 {
			t.Fatalf("drop=%t: %d peek uploads", drop, len(peeks))
		}
		result := analyzeKernelConn(t, server)
		var paths []string
		for _, l := range result.protocolLogs {
			paths = append(paths, l.GetHttp().GetRequest().GetPath())
		}
		sort.Strings(paths)
		if fmt.Sprint(paths) != "[/peek/1 /peek/3 /peek/5]" || result.metrics.DecodeErrors != 0 || result.metrics.FramingErrors != 0 {
			t.Fatalf("drop=%t: paths %v, decode errors %d, framing errors %d", drop, paths, result.metrics.DecodeErrors,
				result.metrics.FramingErrors)
		}
	}
}

// forgedTraffic opens a connection, runs the traffic of a case, then a request behind it and a real PING with
// its ACK
func forgedTraffic(t *testing.T, run *h2cKernelRun, traffic func(s *h2cRawSession)) {
	s := h2cRawPair(t, run)
	defer s.close()
	s.send(append([]byte(http2.ClientPreface), s.peer.settings()...))
	s.serverWrite(s.responder.settings())
	s.send(s.peer.settingsAck(), s.peer.windowUpdate(0, 1<<20))
	traffic(s)
	s.send(s.headers(11, h2cStaticRequest("/after"), true, true))
	s.respond(11, 50)
	s.send(s.peer.ping(false))
	s.serverWrite(s.responder.ping(true))
}

// h2cTunnelPayloads are the frames of an inner h2c connection, carried as the payloads of the DATA frames of a
// stream
func h2cTunnelPayloads(inner *h2cEndpoint) [][]byte {
	headers := func() []byte {
		_ = inner.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: h2cStaticRequest("/inner"),
			EndHeaders: true, EndStream: true})
		return inner.take()
	}
	return [][]byte{append([]byte(http2.ClientPreface), inner.settings()...), inner.settingsAck(),
		inner.windowUpdate(0, 1), inner.pingZero(), headers()}
}

// h2cUploadedCalls is the count of the socket calls of the direction that sent an event (the chunks of a call
// share its data id)
func h2cUploadedCalls(events []*aclevents.SocketDataUploadEvent) int {
	ids := map[uint64]bool{}
	for _, e := range events {
		ids[e.DataID0] = true
	}
	return len(ids)
}

// TestH2CForgedFrames sends frames whose payload is, byte for byte, one or more droppable control frames (in
// DATA, HEADERS and CONTINUATION frames, and a whole h2c connection tunnelled in DATA frames). The follower walks
// the frame headers, so none of them is taken for a control frame: the access logs are the same with the dropping
// off and on, and the real control frames of the connection are still dropped.
func TestH2CForgedFrames(t *testing.T) {
	requireBPF(t)
	forged := h2cForgedFrames()
	tunnelled := 0
	for _, p := range h2cTunnelPayloads(newH2CEndpoint()) {
		tunnelled += len(p)
	}
	after := "/after body=0 status=200 resp=50"
	forgedData := func(body []byte) func(s *h2cRawSession) {
		return func(s *h2cRawSession) {
			s.send(s.headers(1, h2cStaticRequest("/forged-data"), true, false), s.data(1, true, body))
			s.respond(1, 100)
		}
	}
	cases := []struct {
		name     string
		traffic  func(s *h2cRawSession)
		expected []string
	}{
		{"DATA 9 SETTINGS ACK", forgedData(forged[0]), []string{"/forged-data body=9 status=200 resp=100", after}},
		{"DATA 13 WINDOW_UPDATE", forgedData(forged[1]), []string{"/forged-data body=13 status=200 resp=100", after}},
		{"DATA 17 PING", forgedData(forged[2]), []string{"/forged-data body=17 status=200 resp=100", after}},
		{"DATA 26 two WINDOW_UPDATE", forgedData(forged[3]), []string{"/forged-data body=26 status=200 resp=100", after}},
		// the forged header blocks do not decode, so those streams are lost either way; the frames behind them
		// must stay readable
		{"HEADERS 13 WINDOW_UPDATE", func(s *h2cRawSession) { s.send(s.headers(5, forged[1], true, true)) }, []string{after}},
		{"CONTINUATION 9 13 17", func(s *h2cRawSession) {
			s.send(s.headers(3, h2cStaticRequest("/forged-continuation"), false, true), s.continuation(3, false, forged[0]),
				s.continuation(3, false, forged[1]), s.continuation(3, true, forged[2]))
		}, []string{after}},
		{"tunnel", func(s *h2cRawSession) {
			frames := [][]byte{s.headers(9, h2cStaticRequest("/tunnel"), true, false)}
			payloads := h2cTunnelPayloads(newH2CEndpoint())
			for i, p := range payloads {
				frames = append(frames, s.data(9, i == len(payloads)-1, p))
			}
			s.send(frames...)
			s.respond(9, 10)
		}, []string{fmt.Sprintf("/tunnel body=%d status=200 resp=10", tunnelled), after}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logs [2][]string
			for i, drop := range []bool{false, true} {
				run := withAccessLogBPF(t, drop, func(run *h2cKernelRun) { forgedTraffic(t, run, c.traffic) })
				server := run.conns[0]
				result := analyzeKernelConn(t, server)
				// the analysis works on copies, the uploads are still there
				verifyKernelRun(t, run)
				in := enums.SocketDataDirectionIngress
				if drop && h2cUploadedCalls(server.events[in]) >= len(server.calls[in]) {
					t.Fatalf("the real control frames of the server ingress must still be dropped")
				}
				logs[i] = h2cLogSummary(result, true)
				if got := h2cLogSummary(result, false); fmt.Sprint(got) != fmt.Sprint(c.expected) {
					t.Fatalf("drop=%t: access logs %v, expected %v", drop, got, c.expected)
				}
			}
			if fmt.Sprint(logs[0]) != fmt.Sprint(logs[1]) {
				t.Fatalf("the access logs differ: off %v, on %v", logs[0], logs[1])
			}
		})
	}
}

// h2cUnskippedMatched is h2cUnskipped for a run that may also have dropped calls: the events of a direction
// are matched to its real calls in order (an uploaded call is its bytes, a skipped one an event without content
// of the size of a call inside a plain DATA payload, a cut one the start of its call up to the payload, of the
// size of the call), a call no event matches was dropped (only allowed with the dropping on). The skipped and cut
// calls are given their bytes, in upload chunks, as the run without the skipping would have sent them.
func h2cUnskippedMatched(t *testing.T, conn *h2cKernelConn, drop bool) (copied *h2cKernelConn, skipped int) {
	t.Helper()
	copied = &h2cKernelConn{name: conn.name, port: conn.port, remotePort: conn.remotePort, client: conn.client}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		script := &h2cScript{}
		start := 0
		for _, size := range conn.calls[d] {
			script.call(d, conn.real[d][start:start+size], false)
			start += size
		}
		skippable, tailSkippable := h2cSkippable(script), h2cTailSkippable(script)
		// the events of a direction by call (data id), in order
		var groups [][]*aclevents.SocketDataUploadEvent
		for _, e := range conn.events[d] {
			if n := len(groups); n > 0 && groups[n-1][0].DataID0 == e.DataID0 {
				groups[n-1] = append(groups[n-1], e)
				continue
			}
			groups = append(groups, []*aclevents.SocketDataUploadEvent{e})
		}
		next := 0
		for i, c := range script.calls {
			real := c.data
			if next >= len(groups) {
				if !drop {
					t.Fatalf("%s %s: call %d sent no event", conn.name, directionName(d), i)
				}
				continue
			}
			group := groups[next]
			first, last := group[0], group[len(group)-1]
			var data []byte
			for _, e := range group {
				data = append(data, e.BufferData()...)
			}
			cut := last.Finished == 1 && last.HaveReduce == 1
			var matched, whole bool
			switch {
			case first.PayloadSkipped0 == 1:
				matched = first.TotalSize0 == uint64(len(real)) && skippable[i]
				skipped++
			case cut:
				matched = first.TotalSize0 == uint64(len(real)) && len(data) == tailSkippable[i] && bytes.HasPrefix(real, data)
			default:
				matched, whole = bytes.Equal(data, real), true
			}
			if !matched {
				if first.PayloadSkipped0 == 1 {
					skipped--
				}
				if !drop {
					t.Fatalf("%s %s: the events of data id %d are not call %d", conn.name, directionName(d), first.DataID0, i)
				}
				continue
			}
			next++
			if whole {
				copied.events[d] = append(copied.events[d], group...)
				continue
			}
			for sent, seq := 0, uint16(0); sent < len(real); seq++ {
				chunk := min(len(real)-sent, buffer.MaxEventBufferSize)
				e := first.Detach()
				e.PayloadSkipped0, e.Sequence0, e.DataLen, e.HaveReduce, e.Finished = 0, seq, uint16(chunk), 0, 0
				if len(real)-sent > buffer.MaxEventBufferSize {
					e.HaveReduce = 1
				}
				if sent+chunk == len(real) {
					e.Finished = 1
				}
				e.Buffer = append([]byte(nil), real[sent:sent+chunk]...)
				copied.events[d] = append(copied.events[d], e)
				sent += chunk
			}
		}
		if next != len(groups) {
			t.Fatalf("%s %s: %d of %d uploaded calls match no real call", conn.name, directionName(d), len(groups)-next, len(groups))
		}
	}
	return copied, skipped
}

// assertSameAnalysis requires the analysis of a run with the skipping to be that of its calls uploaded in whole:
// the access logs, the kernel logs of each of them and those without a protocol, and the L4 totals
func assertSameAnalysis(t *testing.T, name string, whole, result *h2cResult) {
	t.Helper()
	assertSameProtos(t, name+" protocol logs", whole.protocolLogs, result.protocolLogs)
	if len(whole.protocolKernels) != len(result.protocolKernels) {
		t.Fatalf("%s: kernel logs of protocol logs, %d and %d", name, len(whole.protocolKernels), len(result.protocolKernels))
	}
	for k := range whole.protocolKernels {
		assertSameProtos(t, fmt.Sprintf("%s kernel logs of protocol log %d", name, k), whole.protocolKernels[k], result.protocolKernels[k])
	}
	assertSameProtos(t, name+" kernel logs without a protocol", whole.kernelLogs, result.kernelLogs)
	if whole.l4Totals() != result.l4Totals() {
		t.Fatalf("%s: L4 totals %+v and %+v", name, whole.l4Totals(), result.l4Totals())
	}
}

// h2cKernelRunClean tells whether the analysis reported every request with its sizes and no framing error; it
// fails on the parser errors that never come from the traffic
func h2cKernelRunClean(t *testing.T, label string, result *h2cResult, requests int, sizes string) bool {
	t.Helper()
	m := result.metrics
	if m.DecodeErrors != 0 || m.LateSkips != 0 || m.DroppedStreams != 0 {
		t.Fatalf("%s: the parser must not stumble: decode %d late %d dropped %d", label, m.DecodeErrors, m.LateSkips, m.DroppedStreams)
	}
	clean := m.FramingErrors == 0 && len(result.protocolLogs) == requests
	for _, line := range h2cLogSummary(result, false) {
		clean = clean && strings.HasSuffix(line, sizes)
	}
	if !clean {
		t.Logf("%s: %d access logs of %d, %d framing errors, %d gaps: an endpoint wrote between two reads of a frame "+
			"of its peer, which the analyzer cannot parse in order", label, len(result.protocolLogs), requests, m.FramingErrors, m.Gaps)
	}
	return clean
}

func sortedLogSummary(r *h2cResult) []string {
	summary := h2cLogSummary(r, false)
	sort.Strings(summary)
	return summary
}

// goH2CStreamsTraffic is Go's h2c client and server with requests of a body both ways on several streams at once
func goH2CStreamsTraffic(t *testing.T, run *h2cKernelRun, requests, streams, body int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	response := bytes.Repeat([]byte{'r'}, body)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		server := &http2.Server{MaxUploadBufferPerConnection: 16 << 20, MaxUploadBufferPerStream: 1 << 20}
		server.ServeConn(run.record(raw, "server", false), &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n, _ := io.Copy(io.Discard, r.Body)
				w.Header().Set("x-request-body", fmt.Sprint(n))
				_, _ = w.Write(response)
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
	var wg sync.WaitGroup
	inFlight := make(chan struct{}, streams)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		inFlight <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-inFlight }()
			resp, err := httpClient.Post(fmt.Sprintf("http://%s/streams/%d", listener.Addr(), i), "application/octet-stream",
				bytes.NewReader(bytes.Repeat([]byte{'q'}, body)))
			if err != nil {
				t.Errorf("request: %v", err)
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if n != int64(body) || resp.Header.Get("x-request-body") != fmt.Sprint(body) {
				t.Errorf("response body %d bytes, request body %s", n, resp.Header.Get("x-request-body"))
			}
		}(i)
	}
	wg.Wait()
}

// TestH2CSkipManyStreams runs Go's h2c client and server with 256KB bodies both ways on 8 streams at once with
// the skipping off and on: the payloads of the streams interleave frame by frame, and the follower still skips
// them. With it on, the events are the real calls (checkSkippedCalls), the analysis is that of the calls
// uploaded in whole, and every endpoint direction uploads below 10% of its bytes.
func TestH2CSkipManyStreams(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	const requests, streams, bodySize = 64, 8, 256 * 1024
	var data [2][2][3]int
	var summaries [2][]string
	comparable := true
	for i, skip := range []bool{false, true} {
		run := withAccessLogBPFModes(t, false, skip, func(run *h2cKernelRun) {
			goH2CStreamsTraffic(t, run, requests, streams, bodySize)
		})
		if !skip {
			verifyKernelRun(t, run)
		}
		for _, conn := range run.conns {
			checkPrevDataIDs(t, conn)
			checkLayoutFields(t, conn)
			stats := checkSkippedCalls(t, conn)
			endpoint := 1
			if conn.client {
				endpoint = 0
			}
			for d := range stats.uploadedBytes {
				data[i][endpoint][d] += stats.uploadedBytes[d]
			}
			result := analyzeKernelConn(t, conn)
			sizes := fmt.Sprintf("body=%d status=200 resp=%d", bodySize, bodySize)
			if skip {
				// compared whenever the calls uploaded in whole parse cleanly: once that stumbles (see below), both
				// resynchronize at different events
				whole := analyzeKernelConn(t, h2cUnskipped(conn))
				if h2cKernelRunClean(t, "skip=true whole "+conn.name, whole, requests, sizes) {
					assertSameAnalysis(t, conn.name, whole, result)
				}
			}
			// the runs are compared with each other only when both analyses are clean: with streams at once an
			// endpoint writes between two reads of a frame of its peer, which the analysis after the traffic cannot
			// parse in order, with or without the skipping
			if !h2cKernelRunClean(t, fmt.Sprintf("skip=%t %s", skip, conn.name), result, requests, sizes) {
				comparable = false
			}
			summaries[i] = append(summaries[i], sortedLogSummary(result)...)
		}
		sort.Strings(summaries[i])
	}
	if comparable && fmt.Sprint(summaries[0]) != fmt.Sprint(summaries[1]) {
		t.Fatalf("the access logs differ:\noff %v\non  %v", summaries[0], summaries[1])
	}
	for endpoint, name := range []string{"client", "server"} {
		for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
			on, off := data[1][endpoint][d], data[0][endpoint][d]
			p := 100 * float64(on) / float64(off)
			t.Logf("%s %s: %d data bytes without the skipping, %d with it: %.1f%%", name, directionName(d), off, on, p)
			if p >= 10 {
				t.Fatalf("the %s %s still uploads %.1f%% of its bytes, expected below 10%%", name, directionName(d), p)
			}
		}
	}
}

// TestH2CSkipForgedPayload sends DATA payloads made of forged frame headers (a DATA header announcing 16MB-1, a
// HEADERS frame, a SETTINGS frame, a PADDED DATA header), every read of them starting on one: the follower knows
// it is inside a payload and skips them all, the same payload in a PADDED frame is never skipped, and the access
// logs are those of the run without the skipping.
func TestH2CSkipForgedPayload(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	inner := newH2CEndpoint()
	forgedHeaders := func() []byte {
		_ = inner.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: h2cStaticRequest("/inner"),
			EndHeaders: true, EndStream: true})
		return inner.take()
	}
	forged := bytes.Join([][]byte{{0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, forgedHeaders(),
		inner.settings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0}),
		{0x0, 0x10, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3}}, nil)
	payload := bytes.Repeat(forged, 40)
	traffic := func(s *h2cRawSession) {
		// every read of the payload starts on a forged frame header
		reads := []int{9}
		for at := 0; at < len(payload); at += len(forged) {
			reads = append(reads, len(forged))
		}
		s.write(s.headers(1, h2cStaticRequest("/forged-skip"), true, false), s.data(1, false, payload))
		s.read(9, len(h2cStaticRequest("/forged-skip")))
		s.read(reads...)
		// the same payload in a PADDED frame, read in the same pieces behind its pad length: never skipped
		_ = s.peer.framer.WriteDataPadded(1, false, payload, make([]byte, 7))
		s.write(s.peer.take())
		s.read(9, 1)
		s.read(reads[1:]...)
		s.read(7)
		// the last frame: its tail is read together with the next request
		last := s.data(1, true, payload)
		next := s.headers(3, h2cStaticRequest("/behind-forged"), true, true)
		s.write(last, next)
		s.read(9, len(payload)-100, 100+len(next))
		s.respond(1, 100)
		s.respond(3, 50)
	}
	expected := []string{fmt.Sprintf("/forged-skip body=%d status=200 resp=100", 3*len(payload)),
		"/behind-forged body=0 status=200 resp=50", "/after body=0 status=200 resp=50"}
	var logs [2][]string
	for i, skip := range []bool{false, true} {
		run := withAccessLogBPFModes(t, false, skip, func(run *h2cKernelRun) { forgedTraffic(t, run, traffic) })
		server := run.conns[0]
		result := analyzeKernelConn(t, server)
		if skip {
			checkPrevDataIDs(t, server)
			checkLayoutFields(t, server)
			stats := checkSkippedCalls(t, server)
			// the 40 forged pieces of the plain frame and the one of the last frame, never the padded ones
			if got := stats.skipped[enums.SocketDataDirectionIngress]; got != 41 {
				t.Fatalf("expected the 41 calls inside the plain payloads skipped, got %d", got)
			}
			assertSameAnalysis(t, server.name, analyzeKernelConn(t, h2cUnskipped(server)), result)
		} else {
			verifyKernelRun(t, run)
		}
		assertNoParserErrors(t, result)
		logs[i] = h2cLogSummary(result, true)
		if got := h2cLogSummary(result, false); fmt.Sprint(got) != fmt.Sprint(expected) {
			t.Fatalf("skip=%t: access logs %v, expected %v", skip, got, expected)
		}
	}
	if fmt.Sprint(logs[0]) != fmt.Sprint(logs[1]) {
		t.Fatalf("the access logs differ: off %v, on %v", logs[0], logs[1])
	}
}

// TestH2CSkipWithDropping runs Go's h2c client and server with 256KB bodies with the dropping and the skipping
// both off and both on: with them on, calls are skipped, every event is a real call or a dropped one is missing
// (h2cUnskippedMatched), the analysis is that of the calls uploaded in whole, and the access logs match the run
// with both off.
func TestH2CSkipWithDropping(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	const requests, bodySize = 12, 256 * 1024
	var summaries [2][]string
	comparable := true
	for i, on := range []bool{false, true} {
		run := withAccessLogBPFModes(t, on, on, func(run *h2cKernelRun) { goH2CBodyTraffic(t, run, requests, bodySize, bodySize) })
		if !on {
			verifyKernelRun(t, run)
		}
		skipped := 0
		for _, conn := range run.conns {
			checkPrevDataIDs(t, conn)
			checkLayoutFields(t, conn)
			result := analyzeKernelConn(t, conn)
			if on {
				whole, n := h2cUnskippedMatched(t, conn, true)
				skipped += n
				assertSameAnalysis(t, conn.name, analyzeKernelConn(t, whole), result)
			}
			sizes := fmt.Sprintf("body=%d status=200 resp=%d", bodySize, bodySize)
			if !h2cKernelRunClean(t, fmt.Sprintf("drop=skip=%t %s", on, conn.name), result, requests, sizes) {
				comparable = false
			}
			summaries[i] = append(summaries[i], sortedLogSummary(result)...)
		}
		sort.Strings(summaries[i])
		if on && skipped == 0 {
			t.Fatalf("nothing was skipped with both switches on")
		}
		t.Logf("drop=skip=%t: %d calls skipped", on, skipped)
	}
	if comparable && fmt.Sprint(summaries[0]) != fmt.Sprint(summaries[1]) {
		t.Fatalf("the access logs differ:\noff %v\non  %v", summaries[0], summaries[1])
	}
}
