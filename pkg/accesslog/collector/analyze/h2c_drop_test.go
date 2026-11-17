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
	"fmt"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// The BPF side drops the socket calls of a cleartext HTTP/2 connection that carry nothing but
// WINDOW_UPDATE, PING, PRIORITY or SETTINGS ACK frames (access_log.protocol_analyze.drop_h2c_unused_frame,
// skywalking-rover/bpf/accesslog/syscalls/h2c.h). These tests
// drive the HTTP/2 analyzer of the agent with the same socket calls twice, once as they are uploaded
// without the dropping and once with those calls removed the way BPF removes them - their data ids are never seen,
// and the previous data id of every upload names the last uploaded call - and require the access log
// and the kernel logs the analyzer produces to be identical.

// h2cCall is one socket call of the captured endpoint
type h2cCall struct {
	direction enums.SocketDataDirection
	data      []byte
	// dropped is what BPF does with the call when drop_h2c_unused_frame is on
	dropped bool
	// at is the order the call was made in, which its times are derived from, so a script whose calls
	// are reordered still describes the same calls
	at int
	// id is the order BPF numbers the call in, its data id - 1: a reordered script keeps it
	id int
}

type h2cScript struct {
	calls []h2cCall
}

func (s *h2cScript) call(direction enums.SocketDataDirection, data []byte, dropped bool) {
	s.calls = append(s.calls, h2cCall{direction: direction, data: append([]byte(nil), data...), dropped: dropped,
		at: len(s.calls), id: len(s.calls)})
}

// moved returns a copy of the script with the call at `from` moved to `to`
func (s *h2cScript) moved(from, to int) *h2cScript {
	calls := append([]h2cCall(nil), s.calls...)
	c := calls[from]
	calls = append(calls[:from], calls[from+1:]...)
	calls = append(calls[:to], append([]h2cCall{c}, calls[to:]...)...)
	return &h2cScript{calls: calls}
}

// splitRead adds a frame the way Go's x/net framer reads it: the 9 byte header and the payload in two
// socket calls
func (s *h2cScript) splitRead(direction enums.SocketDataDirection, frame []byte, dropped bool) {
	s.call(direction, frame[:9], dropped)
	if len(frame) > 9 {
		s.call(direction, frame[9:], dropped)
	}
}

// h2cEndpoint produces the bytes one peer sends
type h2cEndpoint struct {
	out     bytes.Buffer
	framer  *http2.Framer
	hbuf    bytes.Buffer
	encoder *hpack.Encoder
}

func newH2CEndpoint() *h2cEndpoint {
	e := &h2cEndpoint{}
	e.framer = http2.NewFramer(&e.out, nil)
	e.encoder = hpack.NewEncoder(&e.hbuf)
	return e
}

func (e *h2cEndpoint) take() []byte {
	result := append([]byte(nil), e.out.Bytes()...)
	e.out.Reset()
	return result
}

func (e *h2cEndpoint) headers(stream uint32, endStream bool, fields ...hpack.HeaderField) []byte {
	e.hbuf.Reset()
	for _, f := range fields {
		_ = e.encoder.WriteField(f)
	}
	_ = e.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: e.hbuf.Bytes(),
		EndHeaders: true, EndStream: endStream})
	return e.take()
}

func (e *h2cEndpoint) data(stream uint32, endStream bool, size int) []byte {
	_ = e.framer.WriteData(stream, endStream, bytes.Repeat([]byte{'d'}, size))
	return e.take()
}

func (e *h2cEndpoint) windowUpdate(stream, increment uint32) []byte {
	_ = e.framer.WriteWindowUpdate(stream, increment)
	return e.take()
}

func (e *h2cEndpoint) ping(ack bool) []byte {
	_ = e.framer.WritePing(ack, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	return e.take()
}

func (e *h2cEndpoint) settings(settings ...http2.Setting) []byte {
	_ = e.framer.WriteSettings(settings...)
	return e.take()
}

func (e *h2cEndpoint) priority(stream, dependency uint32) []byte {
	_ = e.framer.WritePriority(stream, http2.PriorityParam{StreamDep: dependency, Weight: 15})
	return e.take()
}

func (e *h2cEndpoint) rstStream(stream uint32) []byte {
	_ = e.framer.WriteRSTStream(stream, http2.ErrCodeCancel)
	return e.take()
}

// pingZero is a PING with zero opaque data, which is no HPACK instruction that adds to a dynamic table
func (e *h2cEndpoint) pingZero() []byte {
	_ = e.framer.WritePing(false, [8]byte{})
	return e.take()
}

func (e *h2cEndpoint) settingsAck() []byte {
	_ = e.framer.WriteSettingsAck()
	return e.take()
}

func h2cRequest(path string) []hpack.HeaderField {
	return []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"},
		{Name: ":path", Value: path}, {Name: ":authority", Value: "upstream:8080"}}
}

func h2cResponse() []hpack.HeaderField {
	return []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/octet-stream"}}
}

const (
	h2cRequestBody  = 1024
	h2cResponseBody = 256 * 1024
	h2cFrameSize    = 16384
)

// h2cServerScript is the server side of the measured workload: requests with a 1KB body, responses with
// a 256KB body sent as 16KB DATA frames, several streams at once. The server reads every frame in two
// socket calls, so each WINDOW_UPDATE the client returns for the response is a 9 byte and a 4 byte read.
func h2cServerScript() *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress

	s.call(in, []byte(http2.ClientPreface), false)
	s.splitRead(in, client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20},
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096}), false)
	_ = server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: h2cFrameSize})
	_ = server.framer.WriteWindowUpdate(0, 1<<20)
	s.call(out, server.take(), false)
	s.splitRead(in, client.windowUpdate(0, 1<<30), true)
	s.call(out, server.settingsAck(), true)
	s.splitRead(in, client.settingsAck(), true)

	streams := []uint32{1, 3, 5}
	for _, id := range streams {
		s.splitRead(in, client.headers(id, false, h2cRequest(fmt.Sprintf("/download/%d", id))...), false)
		s.splitRead(in, client.data(id, true, h2cRequestBody), false)
	}
	// a priority signal and a ping from the client, both answered or ignored without touching a stream
	s.splitRead(in, client.priority(3, 1), true)
	s.splitRead(in, client.ping(false), true)
	s.call(out, server.ping(true), true)
	// a stream the client resets: RST_STREAM is a control frame the parser acts on, never dropped
	s.splitRead(in, client.headers(7, true, h2cRequest("/reset")...), false)
	s.splitRead(in, client.rstStream(7), false)

	// the responses, interleaved per DATA frame, with the client returning credit for every 32KB
	for _, id := range streams {
		s.call(out, server.headers(id, false, h2cResponse()...), false)
	}
	frames := h2cResponseBody / h2cFrameSize
	for f := 0; f < frames; f++ {
		for _, id := range streams {
			s.call(out, server.data(id, f == frames-1, h2cFrameSize), false)
			if f%2 == 1 {
				s.splitRead(in, client.windowUpdate(0, 2*h2cFrameSize), true)
				s.splitRead(in, client.windowUpdate(id, 2*h2cFrameSize), true)
			}
		}
	}
	return s
}

// h2cClientScript is the client side of the same workload. The client writes through a buffered
// writer, so the two WINDOW_UPDATE frames it returns after reading leave in one 26 byte write, and it
// reads through a buffered reader, so its reads cut across the frames of the server. With
// insideFrames, the credit is returned while a read has stopped inside a frame, which is what an
// application reading the body beside the read loop does.
func h2cClientScript(insideFrames bool) *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress

	preface := append([]byte(http2.ClientPreface), client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})...)
	s.call(out, append(preface, client.windowUpdate(0, 1<<30)...), false)
	_ = server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: h2cFrameSize})
	_ = server.framer.WriteWindowUpdate(0, 1<<20)
	s.call(in, server.take(), false)
	s.call(in, server.settingsAck(), true)
	s.call(out, client.settingsAck(), true)

	streams := []uint32{1, 3}
	for _, id := range streams {
		s.call(out, append(client.headers(id, false, h2cRequest(fmt.Sprintf("/download/%d", id))...),
			client.data(id, true, h2cRequestBody)...), false)
	}
	// the server returns the credit of the request bodies in a read of its own
	s.call(in, append(server.windowUpdate(0, 2*h2cRequestBody), server.windowUpdate(1, h2cRequestBody)...), true)
	s.call(out, client.ping(false), true)
	s.call(in, server.ping(true), true)

	var response []byte
	var frameEnds []int
	for _, id := range streams {
		response = append(response, server.headers(id, false, h2cResponse()...)...)
		frameEnds = append(frameEnds, len(response))
	}
	frames := h2cResponseBody / h2cFrameSize
	for f := 0; f < frames; f++ {
		for _, id := range streams {
			response = append(response, server.data(id, f == frames-1, h2cFrameSize)...)
			frameEnds = append(frameEnds, len(response))
		}
	}
	endsFrame := func(from, to int) bool {
		for _, e := range frameEnds {
			if from < e && e <= to {
				return true
			}
		}
		return false
	}
	// 7000 byte reads, which do not line up with the frames
	const readSize = 7000
	received := 0
	for off := 0; off < len(response); off += readSize {
		end := off + readSize
		if end > len(response) {
			end = len(response)
		}
		s.call(in, response[off:end], false)
		received += end - off
		if received >= 2*h2cFrameSize && (insideFrames || endsFrame(off, end)) {
			received = 0
			s.call(out, append(client.windowUpdate(0, 2*h2cFrameSize), client.windowUpdate(1, 2*h2cFrameSize)...), true)
		}
	}
	return s
}

// h2cEvent is one uploaded socket data event and its delivery position
type h2cEvent struct {
	call  int
	event *aclevents.SocketDataUploadEvent
}

// uploads builds the events BPF uploads for the script. With drop, the dropped calls are not uploaded:
// their data ids are consumed but never seen, and the previous data id of an upload is the data id of
// the last uploaded call of the connection, because socket_data_last_id_map is only written when a call
// is uploaded. The data id of a call is the order it was made in, so a script whose calls are reordered
// delivers the same calls under the same data ids, only in another order.
func (s *h2cScript) uploads(base uint64, drop bool) []h2cEvent {
	result := make([]h2cEvent, 0, len(s.calls))
	var lastUploaded uint64
	for i, c := range s.calls {
		dataID := uint64(c.id + 1)
		if drop && c.dropped {
			continue
		}
		result = append(result, h2cEvent{call: i, event: h2cDataEvent(c, dataID, lastUploaded, base)})
		lastUploaded = dataID
	}
	return result
}

// h2cDataEvent is the event of one socket call: every call has its own times and its own L4 counters,
// so a log that took them from the wrong call, or summed a call that it should not, shows in the result
func h2cDataEvent(c h2cCall, dataID, prevDataID, base uint64) *aclevents.SocketDataUploadEvent {
	funcName := enums.SocketFunctionNameRead
	if c.direction == enums.SocketDataDirectionEgress {
		funcName = enums.SocketFunctionNameWrite
	}
	start := base + uint64(c.at+1)*1000
	packages := uint32(1 + len(c.data)/1448)
	return &aclevents.SocketDataUploadEvent{
		Protocol0: enums.ConnectionProtocolHTTP2, Finished: 1, DataLen: uint16(len(c.data)),
		FunctionName: uint32(funcName), StartTime0: start, EndTime0: start + 300 + uint64(len(c.data)),
		ConnectionID: 1, RandomID: 1, DataID0: dataID, PrevDataID0: prevDataID, TotalSize0: uint64(len(c.data)),
		L4PackageCount: packages, L4TotalPackageSize: uint64(len(c.data)) + uint64(packages)*66,
		Direction0: c.direction, Buffer: append([]byte(nil), c.data...),
	}
}

// h2cResult is everything the analyzer hands to the sender
type h2cResult struct {
	protocolLogs    []*v3.AccessLogProtocolLogs
	protocolKernels [][]*v3.AccessLogKernelLog
	// protocolDetails are the kernel log details protocolKernels are built from
	protocolDetails [][]aclevents.SocketDetail
	kernelLogs      []*v3.AccessLogKernelLog
	// the data ids of every socket call that contributed a kernel log, in order
	reportedIDs []uint64
	metrics     protocols.HTTP2Metrics
}

type h2cNoopConsumer struct{}

func (h2cNoopConsumer) Consume(chan common.KernelLog, chan common.ProtocolLog) {}

// h2cAnalyze runs the agent's HTTP/2 analyzer over the events. analyzeEvery is the number of script
// calls between two analysis passes; it is counted on the script, so both runs analyze at the same points.
func h2cAnalyze(t *testing.T, events []h2cEvent, analyzeEvery int) *h2cResult {
	t.Helper()
	ctx := &common.AccessLogContext{
		Queue:         common.NewQueue(100000, time.Hour, h2cNoopConsumer{}),
		ConnectionMgr: h2cTestConnectionManager(),
		Config:        testAccessLogConfig(),
	}
	proto := protocols.NewHTTP2Analyzer(ctx, NewHTTP2Analyze(ctx))
	partition := protocols.NewPartitionContext(ctx, 0, []protocols.Protocol{proto})
	conn := partition.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP2, events[0].event.DataID0)
	analyze := func() {
		if err := proto.Analyze(conn, &protocols.AnalyzeHelper{}); err != nil {
			t.Fatalf("analyze: %v", err)
		}
	}
	nextPass := analyzeEvery
	for _, e := range events {
		for e.call >= nextPass {
			analyze()
			nextPass += analyzeEvery
		}
		conn.AppendData(e.event)
	}
	analyze()

	result := &h2cResult{metrics: *conn.Metrics(enums.ConnectionProtocolHTTP2).(*protocols.HTTP2Metrics)}
	kernels, protocolLogs := h2cDrainQueue(ctx.Queue)
	for _, p := range protocolLogs {
		result.protocolLogs = append(result.protocolLogs, p.ProtocolLog())
		logs := make([]*v3.AccessLogKernelLog, 0)
		for _, detail := range p.RelateKernelLogs() {
			result.reportedIDs = append(result.reportedIDs, detail.DataID())
			logs = append(logs, forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, detail))
		}
		result.protocolKernels = append(result.protocolKernels, logs)
		result.protocolDetails = append(result.protocolDetails, p.RelateKernelLogs())
	}
	for _, k := range kernels {
		result.reportedIDs = append(result.reportedIDs, k.Event().(buffer.SocketDataDetail).DataID())
		result.kernelLogs = append(result.kernelLogs, forwarder.BuildKernelLogFromEvent(k.Type(), k.Event()))
	}
	return result
}

// h2cDrainQueue takes what the analyzer queued for the sender. The queue only hands its channels to its
// consumer on a timer or when it is full, so the test reads them directly.
func h2cDrainQueue(q *common.Queue) (kernels []common.KernelLog, protocolLogs []common.ProtocolLog) {
	field := func(name string) reflect.Value {
		f := reflect.ValueOf(q).Elem().FieldByName(name)
		return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	}
	kernelChannel := field("kernelLogs").Interface().(chan common.KernelLog)
	protocolChannel := field("protocolLogs").Interface().(chan common.ProtocolLog)
	for {
		select {
		case k := <-kernelChannel:
			kernels = append(kernels, k)
		case p := <-protocolChannel:
			protocolLogs = append(protocolLogs, p)
		default:
			return kernels, protocolLogs
		}
	}
}

// h2cL4Totals sums what the backend turns into the read and write metrics
type h2cL4Totals struct {
	readRecords, readPackages, readBytes    int64
	writeRecords, writePackages, writeBytes int64
}

func (r *h2cResult) l4Totals() h2cL4Totals {
	var totals h2cL4Totals
	add := func(k *v3.AccessLogKernelLog) {
		if read := k.GetRead(); read != nil {
			totals.readRecords++
			totals.readPackages += int64(read.GetL2Metrics().GetTotalPackageCount())
			totals.readBytes += int64(read.GetL2Metrics().GetTotalPackageSize())
		}
		if write := k.GetWrite(); write != nil {
			totals.writeRecords++
			totals.writePackages += write.GetL4Metrics().GetTotalTransmitPackageCount()
			totals.writeBytes += write.GetL4Metrics().GetTotalPackageSize()
		}
	}
	for _, logs := range r.protocolKernels {
		for _, k := range logs {
			add(k)
		}
	}
	for _, k := range r.kernelLogs {
		add(k)
	}
	return totals
}

func assertSameLogs(t *testing.T, baseline, dropped *h2cResult) {
	t.Helper()
	assertSameProtos(t, "protocol logs", baseline.protocolLogs, dropped.protocolLogs)
	if len(baseline.protocolKernels) != len(dropped.protocolKernels) {
		t.Fatalf("kernel logs of protocol logs: baseline %d, dropped %d", len(baseline.protocolKernels), len(dropped.protocolKernels))
	}
	for i := range baseline.protocolKernels {
		assertSameProtos(t, fmt.Sprintf("kernel logs of protocol log %d", i), baseline.protocolKernels[i], dropped.protocolKernels[i])
	}
	assertSameProtos(t, "kernel logs without a protocol", baseline.kernelLogs, dropped.kernelLogs)
	if baseline.l4Totals() != dropped.l4Totals() {
		t.Fatalf("L4 totals differ: baseline %+v, dropped %+v", baseline.l4Totals(), dropped.l4Totals())
	}
	assertNoParserErrors(t, baseline)
	assertNoParserErrors(t, dropped)
}

// assertSameProtos requires two lists of messages to be equal, message by message
func assertSameProtos[M proto.Message](t *testing.T, what string, baseline, dropped []M) {
	t.Helper()
	if len(baseline) != len(dropped) {
		t.Fatalf("%s: baseline %d, dropped %d", what, len(baseline), len(dropped))
	}
	for i := range baseline {
		if !proto.Equal(baseline[i], dropped[i]) {
			t.Fatalf("%s, %d differs:\nbaseline: %s\ndropped:  %s", what, i, prototext.Format(baseline[i]), prototext.Format(dropped[i]))
		}
	}
}

func assertNoParserErrors(t *testing.T, r *h2cResult) {
	t.Helper()
	if m := r.metrics; m.DecodeErrors != 0 || m.FramingErrors != 0 || m.LateSkips != 0 || m.Gaps != 0 || m.DroppedStreams != 0 {
		t.Fatalf("the parser must not stumble: decode %d framing %d late %d gaps %d dropped %d",
			m.DecodeErrors, m.FramingErrors, m.LateSkips, m.Gaps, m.DroppedStreams)
	}
}

// h2cLogSummary describes the access logs of a result, one line each: the path, the body sizes and the
// status, and with full also the method and the header sizes
func h2cLogSummary(r *h2cResult, full bool) []string {
	var result []string
	for _, p := range r.protocolLogs {
		h := p.GetHttp()
		req, resp := h.GetRequest(), h.GetResponse()
		if full {
			result = append(result, fmt.Sprintf("%s %s req=%d/%d status=%d resp=%d/%d", req.GetMethod(), req.GetPath(),
				req.GetSizeOfHeadersBytes(), req.GetSizeOfBodyBytes(), resp.GetStatusCode(), resp.GetSizeOfHeadersBytes(),
				resp.GetSizeOfBodyBytes()))
		} else {
			result = append(result, fmt.Sprintf("%s body=%d status=%d resp=%d", req.GetPath(), req.GetSizeOfBodyBytes(),
				resp.GetStatusCode(), resp.GetSizeOfBodyBytes()))
		}
	}
	return result
}

// TestH2CDropUnusedFramesKeepsTheLogs is the end to end check of the dropping on the Go side: for the
// server and the client side of the measured workload, with and without the kernel log merge, and with
// frequent and rare analysis passes, removing the dropped calls changes nothing the sender receives. It
// also pins down why the kernel level totals are unchanged: a call that carries only these control
// frames never contributes a kernel log without the dropping, because no stream slice ever covers it.
func TestH2CDropUnusedFramesKeepsTheLogs(t *testing.T) {
	scripts := map[string]struct {
		script  *h2cScript
		streams int
	}{
		"server": {script: h2cServerScript(), streams: 3},
		"client": {script: h2cClientScript(false), streams: 2},
	}
	for name, s := range scripts {
		for _, merge := range []bool{true, false} {
			for _, every := range []int{7, 1000000} {
				t.Run(fmt.Sprintf("%s/merge=%t/analyzeEvery=%d", name, merge, every), func(t *testing.T) {
					common.SetMergeKernelLogs(merge)
					defer common.SetMergeKernelLogs(false)
					base := bpfNow()
					baselineEvents, droppedEvents := s.script.uploads(base, false), s.script.uploads(base, true)
					baseline := h2cAnalyze(t, baselineEvents, every)
					dropped := h2cAnalyze(t, droppedEvents, every)
					if len(baseline.protocolLogs) != s.streams {
						t.Fatalf("expected %d access logs, got %d", s.streams, len(baseline.protocolLogs))
					}
					assertSameLogs(t, baseline, dropped)

					droppedIDs := map[uint64]bool{}
					for _, c := range s.script.calls {
						if c.dropped {
							droppedIDs[uint64(c.id+1)] = true
						}
					}
					for _, id := range baseline.reportedIDs {
						if droppedIDs[id] {
							t.Fatalf("socket call %d carries only droppable frames but has a kernel log in the baseline", id)
						}
					}
					t.Logf("%d of %d socket calls dropped, %d kernel logs", len(baselineEvents)-len(droppedEvents),
						len(baselineEvents), len(baseline.reportedIDs))
				})
			}
		}
	}
}

// h2cSplitReadScript is a request and its response on the server side, where the client returns credit
// with a WINDOW_UPDATE whose 9 byte header is read, then the server writes a DATA frame, then the
// payload is read in `payloadReads` reads. It returns the script and the index of the header read.
func h2cSplitReadScript(dropped bool, payloadReads ...[]byte) (*h2cScript, int) {
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s := &h2cScript{}
	s.call(in, []byte(http2.ClientPreface), false)
	s.splitRead(in, client.settings(), false)
	s.call(out, server.settings(), false)
	s.splitRead(in, client.headers(1, false, h2cRequest("/held")...), false)
	s.splitRead(in, client.data(1, true, h2cRequestBody), false)
	s.call(out, server.headers(1, false, h2cResponse()...), false)
	s.call(out, server.data(1, false, h2cFrameSize), false)
	update := client.windowUpdate(1, h2cFrameSize)
	headerCall := len(s.calls)
	s.call(in, update[:9], dropped)
	s.call(out, server.data(1, false, h2cFrameSize), false)
	offset := 9
	for _, part := range payloadReads {
		s.call(in, update[offset:offset+len(part)], dropped)
		offset += len(part)
	}
	s.call(out, server.data(1, true, 100), false)
	return s, headerCall
}

// TestH2CSplitReadAcrossTheOtherDirection covers the split read of a control frame while the other
// direction writes in between, which is common on a server whose writer runs beside its reader. The
// reference is the same calls with the write made after the frame: what the access log must be.
//
// matched: both halves are dropped. The write in between names the call before the header as its
// previous data id, so nothing waits.
//
// held header not matched: the payload arrives in two reads of 2 bytes. BPF uploads the held header,
// with its own data id, times, counters and the previous data id of its own time, right before the
// read that did not match, which is behind the write made while the header was held; that write does
// not name the header as its previous data id.
func TestH2CSplitReadAcrossTheOtherDirection(t *testing.T) {
	matched, matchedHeader := h2cSplitReadScript(true, make([]byte, 4))
	notMatched, notMatchedHeader := h2cSplitReadScript(false, make([]byte, 2), make([]byte, 2))
	cases := []struct {
		name      string
		reference *h2cScript
		uploaded  func(base uint64) []h2cEvent
	}{
		{"matched", matched.moved(matchedHeader+1, matchedHeader+2), func(base uint64) []h2cEvent {
			return matched.uploads(base, true)
		}},
		{"held header not matched", notMatched.moved(notMatchedHeader+1, notMatchedHeader+3), func(base uint64) []h2cEvent {
			events := notMatched.uploads(base, false)
			header, write := events[notMatchedHeader], events[notMatchedHeader+1]
			write.event.PrevDataID0 = header.event.PrevDataID0
			header.call = notMatchedHeader + 2
			events[notMatchedHeader], events[notMatchedHeader+1] = write, header
			return events
		}},
	}

	for _, c := range cases {
		for _, every := range []int{1, 1000000} {
			t.Run(fmt.Sprintf("%s/analyzeEvery=%d", c.name, every), func(t *testing.T) {
				base := bpfNow()
				expected := h2cAnalyze(t, c.reference.uploads(base, false), every)
				if len(expected.protocolLogs) != 1 {
					t.Fatalf("expected 1 access log, got %d: %+v", len(expected.protocolLogs), expected.metrics)
				}
				assertSameLogs(t, expected, h2cAnalyze(t, c.uploaded(base), every))
			})
		}
	}
}

// TestH2CControlFramesInsideAFrameOfTheOtherDirection covers the client that returns credit while its
// last read stopped inside a DATA frame. Uploaded, such a write names that read as its previous data id,
// and waitForMissingEvent holds the write back until the read is parsed, which cannot happen before
// the frame is complete, while the frame cannot be completed across the write: the connection stalls
// until http2GapWaitDuration and then loses frames. That is how the analyzer treats any call one
// direction makes in the middle of a frame of the other, independent of this change. The dropped writes
// take no part in it, so with the dropping the access log is the one of the same calls with the credit
// returned after the response: the correct one.
func TestH2CControlFramesInsideAFrameOfTheOtherDirection(t *testing.T) {
	script := h2cClientScript(true)
	reference := &h2cScript{}
	var deferred []h2cCall
	for _, c := range script.calls {
		if c.dropped && c.direction == enums.SocketDataDirectionEgress {
			deferred = append(deferred, c)
			continue
		}
		reference.calls = append(reference.calls, c)
	}
	reference.calls = append(reference.calls, deferred...)
	// BPF numbers the calls of the reference in this order
	for i := range reference.calls {
		reference.calls[i].id = i
	}

	for _, every := range []int{7, 1000000} {
		t.Run(fmt.Sprintf("analyzeEvery=%d", every), func(t *testing.T) {
			base := bpfNow()
			expected := h2cAnalyze(t, reference.uploads(base, false), every)
			if len(expected.protocolLogs) != 2 {
				t.Fatalf("expected 2 access logs, got %d: %+v", len(expected.protocolLogs), expected.metrics)
			}
			assertSameLogs(t, expected, h2cAnalyze(t, script.uploads(base, true), every))
		})
	}
}

// TestH2CDroppedCallMustNotBeThePreviousDataID shows what the BPF side must never do: name a
// dropped call as the previous data id of the next upload, which is what writing
// socket_data_last_id_map for a dropped call would do. The parser then waits for a socket call that
// will never arrive and reports nothing until it gives up after http2GapWaitDuration, which would
// delay every stream of the connection and count a gap for each dropped call.
func TestH2CDroppedCallMustNotBeThePreviousDataID(t *testing.T) {
	script := h2cServerScript()
	base := bpfNow()
	broken := make([]h2cEvent, 0, len(script.calls))
	for i, c := range script.calls {
		if c.dropped {
			continue
		}
		dataID := uint64(c.id + 1)
		broken = append(broken, h2cEvent{call: i, event: h2cDataEvent(c, dataID, dataID-1, base)})
	}
	baseline := h2cAnalyze(t, script.uploads(base, false), 1000000)
	result := h2cAnalyze(t, broken, 1000000)
	if len(result.protocolLogs) >= len(baseline.protocolLogs) {
		t.Fatalf("a previous data id that names a dropped call must stall the parser, got %d of %d access logs",
			len(result.protocolLogs), len(baseline.protocolLogs))
	}
}

// TestH2CForgedControlFramePayloads covers frame payloads that are, byte for byte, droppable frames:
// DATA bodies of 9, 13, 17 and 26 bytes that are a SETTINGS ACK, a WINDOW_UPDATE, a PING and two
// WINDOW_UPDATEs, read the way Go's x/net framer reads them, so each body is a socket call of its own.
// The BPF side must upload them, since they do not start on a frame boundary: then the access log is
// the one without the dropping. The frame-blind case shows what dropping them does: the DATA frame
// takes the bytes of the frames behind it as its payload and the streams behind it are lost or
// mis-sized. Which calls BPF drops is checked in the kernel by TestH2CForgedFramesInTheKernel of the rover.
func TestH2CForgedControlFramePayloads(t *testing.T) {
	forged := h2cForgedFrames()
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s := &h2cScript{}
	s.call(in, []byte(http2.ClientPreface), false)
	s.splitRead(in, client.settings(), false)
	s.call(out, server.settings(), false)
	s.splitRead(in, client.windowUpdate(0, 1<<20), true)
	var payloadCalls []int
	stream := uint32(1)
	for _, body := range forged {
		s.splitRead(in, client.headers(stream, false, h2cRequest(fmt.Sprintf("/forged/%d", len(body)))...), false)
		_ = client.framer.WriteData(stream, true, body)
		frame := client.take()
		s.call(in, frame[:9], false)
		payloadCalls = append(payloadCalls, len(s.calls))
		s.call(in, frame[9:], false)
		s.call(out, server.headers(stream, false, h2cResponse()...), false)
		s.call(out, server.data(stream, true, 100), false)
		stream += 2
	}
	s.splitRead(in, client.headers(stream, true, h2cRequest("/after")...), false)
	s.call(out, server.headers(stream, false, h2cResponse()...), false)
	s.call(out, server.data(stream, true, 50), false)

	summary := func(r *h2cResult) []string { return h2cLogSummary(r, false) }
	expected := fmt.Sprint([]string{"/forged/9 body=9 status=200 resp=100", "/forged/13 body=13 status=200 resp=100",
		"/forged/17 body=17 status=200 resp=100", "/forged/26 body=26 status=200 resp=100", "/after body=0 status=200 resp=50"})

	base := bpfNow()
	baseline := h2cAnalyze(t, s.uploads(base, false), 1000000)
	if fmt.Sprint(summary(baseline)) != expected {
		t.Fatalf("access logs without the dropping: %v, expected %v", summary(baseline), expected)
	}
	assertSameLogs(t, baseline, h2cAnalyze(t, s.uploads(base, true), 1000000))

	// a frame-blind BPF would drop every forged body
	blind := &h2cScript{calls: append([]h2cCall(nil), s.calls...)}
	for _, i := range payloadCalls {
		blind.calls[i].dropped = true
	}
	if got := summary(h2cAnalyze(t, blind.uploads(base, true), 1000000)); fmt.Sprint(got) == expected {
		t.Fatalf("dropping the forged bodies must corrupt the access log, got %v", got)
	} else {
		t.Logf("with the forged bodies dropped the access logs are %v", got)
	}
}

// h2cForgedFrames are complete droppable frames, as the payloads of other frames: a SETTINGS ACK, a
// WINDOW_UPDATE, a PING and two WINDOW_UPDATEs. None of their bytes is an HPACK instruction that adds to
// the dynamic table, so a header block made of them cannot desynchronize the decoder.
func h2cForgedFrames() [][]byte {
	peer := newH2CEndpoint()
	return [][]byte{peer.settingsAck(), peer.windowUpdate(1, 1), peer.pingZero(),
		append(peer.windowUpdate(1, 1), peer.windowUpdate(0, 1)...)}
}

// bpfNow is the clock of bpf_ktime_get_ns
func bpfNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		panic(err)
	}
	return uint64(ts.Nano())
}

// h2cSkipDataPayload is access_log.protocol_analyze.skip_h2c_data_payload for the analyzer of h2cAnalyze:
// the tests of the skipping turn it on for both of their runs, so the parser is the same and only what
// BPF uploads differs
var h2cSkipDataPayload bool

func h2cTestConnectionManager() *common.ConnectionManager {
	mgr := &common.ConnectionManager{}
	mgr.SetH2CSwitches(false, h2cSkipDataPayload)
	return mgr
}

// withH2CSkipDataPayload turns the skipping on in the parser for the rest of the test
func withH2CSkipDataPayload(t *testing.T) {
	h2cSkipDataPayload = true
	t.Cleanup(func() { h2cSkipDataPayload = false })
}
