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

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/accesslog/sender"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The records of a per-CPU batch of skipped and tail-cut HTTP/2 calls are kept as compact records
// (events.H2CRecord) instead of the SocketDataUploadEvent each stands for. These tests split the same batches
// both ways, the compact records (events.SplitH2CBatch) and the full events the splitter made before
// (legacySplitH2CBatch), drive the agent's partition, connection and HTTP/2 analyzer with them, and require
// what goes to the backend to be byte for byte the same: the protocol logs, the kernel logs of each (built and
// encoded), the kernel logs without a protocol, and what the memory protection refused and holds.

// legacySplitH2CBatch is SplitH2CBatch as it was before the compact records: every admitted record decoded
// into a full event from the pool
func legacySplitH2CBatch(sample []byte, deliver func(data interface{}), drop func(sample []byte)) bool {
	if !events.IsBatchRecord(sample) {
		return false
	}
	n := events.BatchRecordCount(sample)
	events.CountBatch(n)
	var refused [events.UploadSampleSize]byte
	for i := 0; i < n; i++ {
		if !buffer.AcquireEvent() {
			if raw := events.BatchRecordAsUploadSample(sample, i, refused[:]); raw != nil {
				drop(raw)
			}
			continue
		}
		event := events.AcquireUploadEvent()
		if !event.DecodeBatchRecord(sample, i) {
			event.Discard()
			continue
		}
		deliver(event)
	}
	return true
}

// holdInflightMargin holds pooled buffers until the bytes in use are well above zero for the rest of the
// test: other tests of the package release events they never admitted, and InflightBytes, which the runs
// compare and the memory protection reads, stops at zero
func holdInflightMargin(t *testing.T) {
	var held [][]byte
	for buffer.InflightBytes() < 64<<20 {
		held = append(held, buffer.TakeBuffer(buffer.MaxEventBufferSize))
	}
	t.Cleanup(func() {
		for _, b := range held {
			buffer.ReleaseBufferOnly(b)
		}
	})
}

// chargeEventsLikeRecords makes the memory protection charge an event in use what it charges a compact
// record (buffer.ChargeRecord) for the rest of the test, so a run with the records and a run with the events
// they stand for hold the same bytes and are refused at the same point under a budget
func chargeEventsLikeRecords(t *testing.T) {
	old := buffer.SetEventSize(buffer.CompactRecordSize)
	t.Cleanup(func() { buffer.SetEventSize(old) })
}

type batchSplitter func(sample []byte, deliver func(data interface{}), drop func(sample []byte)) bool

// h2cRecordOutput is everything a run hands to the sender, in the forms the sender encodes it
type h2cRecordOutput struct {
	protocolLogs      [][]byte
	protocolKernels   [][][]byte
	protocolTransfers [][]forwarder.TransferLog
	protocolEncoded   [][]byte
	kernelLogs        [][]byte
	kernelTransfers   []forwarder.TransferLog
	kernelMeta        []string
	reportedIDs       []uint64
	refused           [][]byte
	metrics           string
	// inUse and inflight are what the run left held by the memory protection
	inUse, inflight int64
	// records and events are the deliveries of the splitter by type
	records, events int
}

func marshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	if m == nil || reflect.ValueOf(m).IsNil() {
		return nil
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// copyAdmittedEvent is a copy of a full event as the reader delivers it: admitted by the memory protection,
// its data in a buffer of the pool, so the accounting of both runs is the agent's; nil when refused
func copyAdmittedEvent(e *events.SocketDataUploadEvent) *events.SocketDataUploadEvent {
	if !buffer.AcquireEvent() {
		return nil
	}
	c := e.Detach()
	if data := e.BufferData(); len(data) > 0 {
		c.Buffer = buffer.TakeBuffer(len(data))
		copy(c.Buffer, data)
	} else if e.Buffer != nil {
		c.Buffer = buffer.TakeBuffer(0)
	}
	return c
}

// h2cRecordRun runs the deliveries through the agent's partition (PartitionContext.Consume) and HTTP/2
// analyzer, splitting the batches with split. analyzeEvery is counted on the script calls. The deliveries
// at the indexes in lose are lost, as a perf sample lost in the ring.
func h2cRecordRun(t *testing.T, deliveries []h2cDelivery, split batchSplitter, analyzeEvery int, lose map[int]bool) *h2cRecordOutput {
	t.Helper()
	run := newH2CRecordRunner(t, split)
	nextPass := analyzeEvery
	for i, d := range deliveries {
		for d.call >= nextPass {
			run.analyze()
			nextPass += analyzeEvery
		}
		if lose[i] {
			continue
		}
		run.deliver(i, d)
	}
	run.analyze()
	return run.finish()
}

// h2cRecordRunner is the agent's partition and HTTP/2 analyzer of one connection, fed one delivery at a time
type h2cRecordRunner struct {
	t                 *testing.T
	ctx               *common.AccessLogContext
	proto             *protocols.HTTP2Protocol
	conn              *protocols.PartitionConnection
	split             batchSplitter
	deliverData       func(data interface{})
	drop              func(raw []byte)
	agentPartition    *PartitionContext
	out               *h2cRecordOutput
	inUse0, inflight0 int64
}

func newH2CRecordRunner(t *testing.T, split batchSplitter) *h2cRecordRunner {
	t.Helper()
	r := &h2cRecordRunner{t: t, split: split, out: &h2cRecordOutput{}}
	r.ctx = &common.AccessLogContext{
		Queue:         common.NewQueue(100000, time.Hour, h2cNoopConsumer{}),
		ConnectionMgr: h2cTestConnectionManager(),
		Config:        &common.Config{},
	}
	r.inUse0, _, _, _ = buffer.MemoryStats()
	r.inflight0 = buffer.InflightBytes()
	r.proto = protocols.NewHTTP2Analyzer(r.ctx, NewHTTP2Analyze(r.ctx))
	partition := protocols.NewPartitionContext(r.ctx, 0, []protocols.Protocol{r.proto})
	r.agentPartition = NewPartitionContext(r.ctx, partition)
	r.conn = partition.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP2, 1)
	r.deliverData = func(data interface{}) {
		switch data.(type) {
		case *events.H2CRecord:
			r.out.records++
		case *events.SocketDataUploadEvent:
			r.out.events++
		default:
			t.Fatalf("the splitter delivered a %T", data)
		}
		r.agentPartition.Consume(data)
	}
	r.drop = func(raw []byte) { r.out.refused = append(r.out.refused, append([]byte(nil), raw...)) }
	return r
}

// analyzeAll is a pass of the partition over every connection it has, as its periodic tick does
func (r *h2cRecordRunner) analyzeAll() {
	r.agentPartition.ProcessEvents()
}

func (r *h2cRecordRunner) analyze() {
	if err := r.proto.Analyze(r.conn, &protocols.AnalyzeHelper{}); err != nil {
		r.t.Fatalf("analyze: %v", err)
	}
}

func (r *h2cRecordRunner) deliver(i int, d h2cDelivery) {
	if d.sample != nil {
		if !r.split(d.sample, r.deliverData, r.drop) {
			r.t.Fatalf("delivery %d is not a batch", i)
		}
	} else if e := copyAdmittedEvent(d.event); e != nil {
		r.agentPartition.Consume(e)
	} else {
		r.out.refused = append(r.out.refused, []byte(fmt.Sprintf("event %d", d.event.DataID0)))
	}
}

func (r *h2cRecordRunner) finish() *h2cRecordOutput {
	t, out := r.t, r.out
	m := r.conn.Metrics(enums.ConnectionProtocolHTTP2).(*protocols.HTTP2Metrics)
	out.metrics = fmt.Sprintf("framing=%d gaps=%d decode=%d dropped=%d late=%d", m.FramingErrors, m.Gaps, m.DecodeErrors,
		m.DroppedStreams, m.LateSkips)
	kernels, protocolLogs := h2cDrainQueue(r.ctx.Queue)
	for _, p := range protocolLogs {
		out.protocolLogs = append(out.protocolLogs, marshal(t, p.ProtocolLog()))
		var built [][]byte
		var transfers []forwarder.TransferLog
		for _, detail := range p.RelateKernelLogs() {
			out.reportedIDs = append(out.reportedIDs, detail.DataID())
			built = append(built, marshal(t, forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, detail)))
			tl, filled, ok := forwarder.BuildTransferLog(detail)
			if !filled || !ok {
				t.Fatalf("the kernel log of a detail is not filled: %t %t", filled, ok)
			}
			transfers = append(transfers, tl)
		}
		encoded, _, err := sender.EncodeTransferProtocolLog(p.RelateKernelLogs(), p.ProtocolLog())
		if err != nil {
			t.Fatal(err)
		}
		out.protocolKernels = append(out.protocolKernels, built)
		out.protocolTransfers = append(out.protocolTransfers, transfers)
		out.protocolEncoded = append(out.protocolEncoded, encoded)
	}
	for _, k := range kernels {
		out.reportedIDs = append(out.reportedIDs, k.Event().(buffer.SocketDataDetail).DataID())
		out.kernelLogs = append(out.kernelLogs, marshal(t, forwarder.BuildKernelLogFromEvent(k.Type(), k.Event())))
		tl, filled, ok := forwarder.BuildTransferLog(k.Event())
		if !filled || !ok {
			t.Fatalf("the kernel log of an event is not filled: %t %t", filled, ok)
		}
		out.kernelTransfers = append(out.kernelTransfers, tl)
		out.kernelMeta = append(out.kernelMeta, fmt.Sprintf("type=%d owned=%t", k.Type(), k.Owned()))
	}
	inUse1, _, _, _ := buffer.MemoryStats()
	out.inUse, out.inflight = inUse1-r.inUse0, buffer.InflightBytes()-r.inflight0
	return out
}

// assertSameOutput requires the compact run to hand the sender what the full event run hands it
func assertSameOutput(t *testing.T, full, compact *h2cRecordOutput) {
	t.Helper()
	if diff := outputDiff(full, compact); diff != "" {
		t.Fatal(diff)
	}
}

// outputDiff describes the first difference between two runs, "" when they handed the sender the same
func outputDiff(full, compact *h2cRecordOutput) string {
	pairs := []struct {
		what string
		a, b interface{}
	}{
		{"protocol logs", full.protocolLogs, compact.protocolLogs},
		{"kernel logs of the protocol logs", full.protocolKernels, compact.protocolKernels},
		{"transfer logs of the protocol logs", full.protocolTransfers, compact.protocolTransfers},
		{"encoded protocol logs", full.protocolEncoded, compact.protocolEncoded},
		{"kernel logs without a protocol", full.kernelLogs, compact.kernelLogs},
		{"transfer logs without a protocol", full.kernelTransfers, compact.kernelTransfers},
		{"kernel log types", full.kernelMeta, compact.kernelMeta},
		{"reported data ids", full.reportedIDs, compact.reportedIDs},
		{"refused records", full.refused, compact.refused},
		{"parser metrics", full.metrics, compact.metrics},
		{"events in use", full.inUse, compact.inUse},
		{"bytes in use", full.inflight, compact.inflight},
		{"deliveries", full.records + full.events, compact.records + compact.events},
	}
	for _, p := range pairs {
		if !reflect.DeepEqual(p.a, p.b) {
			return fmt.Sprintf("%s differ:\nfirst:  %v\nsecond: %v", p.what, p.a, p.b)
		}
	}
	return ""
}

// h2cSplitAtFrames reads a stream of frames in calls that cross the frame boundaries: every frame but the
// first is entered by a call that starts `back` bytes before its header (cycling through backs) and ends
// `into` bytes into its payload, and the call before it runs from there; so the calls in front of a DATA
// frame are cut behind back+9 bytes, and those in between lie inside a payload
func h2cSplitAtFrames(stream []byte, backs []int, into int) [][]byte {
	var starts []int
	for at := 0; at+9 <= len(stream); {
		starts = append(starts, at)
		at += 9 + (int(stream[at])<<16 | int(stream[at+1])<<8 | int(stream[at+2]))
	}
	var reads [][]byte
	cursor := 0
	for k, fs := range starts {
		begin := fs - backs[k%len(backs)]
		end := fs + 9 + into
		if k == 0 || begin <= cursor || end > len(stream) {
			continue
		}
		reads = append(reads, stream[cursor:begin], stream[begin:end])
		cursor = end
	}
	if cursor < len(stream) {
		reads = append(reads, stream[cursor:])
	}
	return reads
}

// h2cManyStreamsScript is the server side of `streams` streams at once (more than the 16 a batch interleaves
// by design): the request bodies interleaved frame by frame and read across the frames (skipped calls, calls
// cut behind 16, 9 and 12 bytes, and calls cut behind 17, which go as full events), a stream reset by the
// client, and the responses interleaved one DATA frame per write (each cut behind its header)
func h2cManyStreamsScript(streams int) *h2cScript {
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, append([]byte(http2.ClientPreface), client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})...), false)
	_ = server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: h2cFrameSize})
	_ = server.framer.WriteWindowUpdate(0, 1<<20)
	s.call(out, server.take(), false)
	s.call(in, client.windowUpdate(0, 1<<30), true)
	s.call(out, server.settingsAck(), true)
	s.call(in, client.settingsAck(), true)
	var ids []uint32
	for i := 0; i < streams; i++ {
		ids = append(ids, uint32(2*i+1))
	}
	for _, id := range ids {
		s.call(in, client.headers(id, false, h2cRequest(fmt.Sprintf("/many/%d", id))...), false)
	}
	reset := uint32(2*streams + 1)
	s.call(in, client.headers(reset, false, h2cRequest("/reset")...), false)
	s.call(in, client.rstStream(reset), false)
	var body []byte
	for f := 0; f < 4; f++ {
		for _, id := range ids {
			body = append(body, client.data(id, f == 3, 4096)...)
		}
	}
	for _, r := range h2cSplitAtFrames(body, []int{7, 0, 3, 8}, 100) {
		s.call(in, r, false)
	}
	for _, id := range ids {
		s.call(out, server.headers(id, false, h2cResponse()...), false)
	}
	for f := 0; f < 4; f++ {
		for k, id := range ids {
			s.call(out, server.data(id, f == 3, h2cFrameSize), false)
			if k%5 == 4 {
				s.call(in, client.windowUpdate(0, 5*h2cFrameSize), true)
			}
		}
	}
	return s
}

// h2cCutScript is the client side of two streams whose responses are read across the frames, entering
// every DATA frame 7, 8, 0 or 3 bytes before its header: calls cut behind 16 bytes (the most a record holds),
// 17 (a full event), 9 and 12, and the skipped calls between them
func h2cCutScript() *h2cScript {
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
		s.call(out, append(client.headers(id, false, h2cRequest(fmt.Sprintf("/cut/%d", id))...),
			client.data(id, true, h2cRequestBody)...), false)
	}
	var response []byte
	for _, id := range streams {
		response = append(response, server.headers(id, false, h2cResponse()...)...)
	}
	for f := 0; f < 8; f++ {
		for _, id := range streams {
			response = append(response, server.data(id, f == 7, h2cFrameSize)...)
		}
	}
	for k, r := range h2cSplitAtFrames(response, []int{7, 8, 0, 3}, 100) {
		s.call(in, r, false)
		if k%4 == 3 {
			s.call(out, client.windowUpdate(0, 2*h2cFrameSize), true)
		}
	}
	return s
}

type h2cRecordScript struct {
	name  string
	build func() *h2cScript
}

var h2cRecordScripts = []h2cRecordScript{
	{"server", h2cServerScript},
	{"client", func() *h2cScript { return h2cClientScript(false) }},
	{"client-inside", func() *h2cScript { return h2cClientScript(true) }},
	{"split", h2cSkipSplitScript},
	{"many-streams", func() *h2cScript { return h2cManyStreamsScript(20) }},
	{"cut", h2cCutScript},
}

// deliveryShapes counts the records with a 16-byte cut and the full events cut in front of a payload
func deliveryShapes(deliveries []h2cDelivery) (records, cut16, fullCut int) {
	for _, d := range deliveries {
		if d.sample == nil {
			if d.event.HaveReduce == 1 && d.event.Protocol0 == enums.ConnectionProtocolHTTP2 {
				fullCut++
			}
			continue
		}
		n := events.BatchRecordCount(d.sample)
		records += n
		for i := 0; i < n; i++ {
			var e events.SocketDataUploadEvent
			if events.DecodeBatchRecordInto(&e, d.sample, i, nil) && e.HaveReduce == 1 && e.DataLen == 16 {
				cut16++
			}
		}
	}
	return records, cut16, fullCut
}

// TestH2CRecordsLikeFullEvents is the equivalence of the compact records and the full events over the
// scripts (interleaved streams, more than 16 of them, resets, tail cuts up to 16 bytes and full events of the
// same connection between the records), with the dropping of BPF off and on, the kernel log merge on and
// off, batches of 1, 5 and 64 records handed over in order, late or periodically, and analysis passes after
// every call, every 7 calls or at the end.
func TestH2CRecordsLikeFullEvents(t *testing.T) {
	chargeEventsLikeRecords(t)
	withH2CSkipDataPayload(t)
	holdInflightMargin(t)
	buffer.SetEventListSlab(32)
	defer buffer.SetEventListSlab(1)
	type shape struct {
		inOrder    bool
		flushEvery int
	}
	shapes := []shape{{true, 0}, {false, 0}, {false, 13}}
	var totalCut16, totalFullCut int
	defer func() {
		if !t.Failed() && (totalCut16 == 0 || totalFullCut == 0) {
			t.Fatalf("%d records cut behind 16 bytes, %d full events cut: the shapes are not covered", totalCut16, totalFullCut)
		}
	}()
	for _, script := range h2cRecordScripts {
		var cut16, fullCut, logs int
		for _, drop := range []bool{false, true} {
			evs := script.build().h2cCutUploads(bpfNow(), drop)
			for _, batch := range []int{1, 5, 64} {
				for _, sh := range shapes {
					deliveries := h2cBatchDeliveries(evs, batch, sh.flushEvery, sh.inOrder)
					records, c16, fc := deliveryShapes(deliveries)
					if records == 0 {
						t.Fatalf("%s: no batch record", script.name)
					}
					cut16, fullCut = cut16+c16, fullCut+fc
					for _, merge := range []bool{true, false} {
						for _, every := range []int{1, 7, 1 << 30} {
							name := fmt.Sprintf("%s/drop=%t/batch=%d/inOrder=%t/flush=%d/merge=%t/every=%d", script.name, drop,
								batch, sh.inOrder, sh.flushEvery, merge, every)
							common.SetMergeKernelLogs(merge)
							full := h2cRecordRun(t, deliveries, legacySplitH2CBatch, every, nil)
							compact := h2cRecordRun(t, deliveries, events.SplitH2CBatch, every, nil)
							common.SetMergeKernelLogs(false)
							t.Run(name, func(t *testing.T) {
								assertSameOutput(t, full, compact)
								if full.records != 0 || compact.events != 0 || full.events != compact.records {
									t.Fatalf("legacy: %d records %d events, compact: %d records %d events", full.records, full.events,
										compact.records, compact.events)
								}
							})
							if compact.records != records {
								t.Fatalf("%s: %d records delivered, %d sent", name, compact.records, records)
							}
							if sh.inOrder {
								logs += len(compact.protocolLogs)
							}
						}
					}
				}
			}
		}
		t.Logf("%s: %d records cut behind 16 bytes, %d full events cut, %d protocol logs compared in order", script.name,
			cut16, fullCut, logs)
		if logs == 0 {
			t.Fatalf("%s: no protocol log", script.name)
		}
		totalCut16, totalFullCut = totalCut16+cut16, totalFullCut+fullCut
	}
}

// TestH2CRecordsLikeFullEventsWithLossAndPressure is the equivalence when a batch or a full event is lost in
// the middle of the run (the gap handling of the parser), and when the memory protection refuses records:
// the budget is set so that the events in use hold it after a few dozen, and both runs must refuse the same
// records and hold the same events and bytes in the end, which only holds when a record is released exactly
// when its event would be.
func TestH2CRecordsLikeFullEventsWithLossAndPressure(t *testing.T) {
	chargeEventsLikeRecords(t)
	withH2CSkipDataPayload(t)
	holdInflightMargin(t)
	buffer.SetEventListSlab(32)
	defer buffer.SetEventListSlab(1)
	defer buffer.SetMemoryBudget(0)
	// what one admitted event adds to the bytes in use
	before := buffer.InflightBytes()
	if !buffer.AcquireEvent() {
		t.Fatalf("no budget")
	}
	overhead := buffer.InflightBytes() - before
	buffer.ReleaseEvent(nil)
	refusedTotal := 0
	for _, script := range h2cRecordScripts {
		evs := script.build().h2cCutUploads(bpfNow(), false)
		for _, batch := range []int{5, 64} {
			deliveries := h2cBatchDeliveries(evs, batch, 13, false)
			var batches []int
			for i, d := range deliveries {
				if d.sample != nil {
					batches = append(batches, i)
				}
			}
			losses := map[string]map[int]bool{
				"none":       nil,
				"batch":      {batches[len(batches)/2]: true},
				"full-event": {},
			}
			for i := len(deliveries) / 2; i < len(deliveries); i++ {
				if deliveries[i].sample == nil {
					losses["full-event"][i] = true
					break
				}
			}
			for lossName, lose := range losses {
				for _, budgetEvents := range []int64{0, 24, 60} {
					for _, every := range []int{1, 7, 1 << 30} {
						name := fmt.Sprintf("%s/batch=%d/lose=%s/budget=%d/every=%d", script.name, batch, lossName, budgetEvents, every)
						common.SetMergeKernelLogs(true)
						run := func(split batchSplitter) *h2cRecordOutput {
							if budgetEvents > 0 {
								buffer.SetMemoryBudget(buffer.InflightBytes() + budgetEvents*overhead)
							}
							defer buffer.SetMemoryBudget(0)
							return h2cRecordRun(t, deliveries, split, every, lose)
						}
						// the refusals follow the bytes in use of the whole process: a goroutine another test left
						// running that still releases events moves them, so a comparison only counts when the
						// full event run reproduces itself around the compact one
						var full, compact *h2cRecordOutput
						for attempt := 0; ; attempt++ {
							full = run(legacySplitH2CBatch)
							compact = run(events.SplitH2CBatch)
							again := run(legacySplitH2CBatch)
							if outputDiff(full, again) == "" {
								break
							}
							if attempt == 9 {
								t.Fatalf("%s: the full event run does not reproduce itself", name)
							}
						}
						common.SetMergeKernelLogs(false)
						t.Run(name, func(t *testing.T) {
							assertSameOutput(t, full, compact)
							if full.records != 0 || compact.events != 0 || full.events != compact.records {
								t.Fatalf("legacy: %d records %d events, compact: %d records %d events", full.records, full.events,
									compact.records, compact.events)
							}
						})
						if budgetEvents > 0 {
							refusedTotal += len(compact.refused)
						}
					}
				}
			}
		}
	}
	t.Logf("%d refusals compared", refusedTotal)
	if refusedTotal == 0 {
		t.Fatalf("the memory protection refused nothing")
	}
}

// TestH2CRecordAnswersAsItsEvent: every method a consumer reads of a record answers what the event the old
// splitter decoded of it answers, before and after the release, and its detail copy is that event's
func TestH2CRecordAnswersAsItsEvent(t *testing.T) {
	var evs []*events.SocketDataUploadEvent
	for i, cut := range [][]byte{nil, {0, 0x40, 0, 0, 0, 0, 0, 0, 1}, bytes.Repeat([]byte{0xAB}, 16), {}} {
		e := &events.SocketDataUploadEvent{Protocol0: enums.ConnectionProtocolHTTP2, Finished: 1, FunctionName: uint32(3 + i),
			StartTime0: uint64(1000 * (i + 1)), EndTime0: uint64(1000*(i+1) + 77), ConnectionID: 7, RandomID: 9,
			DataID0: uint64(40 + i), PrevDataID0: uint64(39 + i), TotalSize0: 16384, L4PackageCount: uint32(10 + i),
			L4TotalPackageSize: uint64(17000 + i), Direction0: enums.SocketDataDirection(1 + i%2), LocalPort: 8080,
			RemotePort: 50000, SSL: 0, InFlight: uint16(i)}
		if cut == nil {
			e.PayloadSkipped0 = 1
		} else {
			e.HaveReduce, e.DataLen, e.Buffer = 1, uint16(len(cut)), cut
		}
		evs = append(evs, e)
	}
	sample := encodeH2CBatch(evs)
	// the records as the buffer of their connection stores them
	connBuf := buffer.NewBuffer()
	var records []*events.H2CRecord
	events.SplitH2CBatch(sample, func(data interface{}) {
		split := data.(*events.H2CRecord)
		stored := connBuf.AppendDataEvent(split).(*events.H2CRecord)
		if stored != split {
			t.Fatalf("the buffer holds a copy of the record")
		}
		records = append(records, stored)
	}, nil)
	if len(records) != len(evs) {
		t.Fatalf("%d records of %d", len(records), len(evs))
	}
	for i, r := range records {
		e := &events.SocketDataUploadEvent{}
		if !e.DecodeBatchRecord(sample, i) {
			t.Fatal("decode")
		}
		check := func(stage string) {
			t.Helper()
			type answers struct {
				Protocol                        enums.ConnectionProtocol
				ConnectionID                    string
				Data                            []byte
				Total                           uint64
				Direction                       enums.SocketDataDirection
				Start, Len, Seq                 int
				DataID, PrevDataID              uint64
				IsStart, IsFinished, Reduce     bool
				StartTime, EndTime, Time        uint64
				Skipped, BodySkipped            bool
				DecodeSeq                       uint64
				ConID, RandomID                 uint64
				Timestamp                       time.Time
				GetStart, GetEnd, L4Size        uint64
				L4Count                         uint32
				Func                            enums.SocketFunctionName
				GetProtocol                     enums.ConnectionProtocol
				SSL                             uint8
				IsSkipped, IsBodySkipped        bool
				MergeWithEvent, MergeWithRecord bool
				EventMergesIt, RecordMergesIt   bool
				Meta                            events.SocketDataUploadEvent
			}
			of := func(b interface {
				buffer.SocketDataBuffer
				events.SocketDetail
				DecodeSequence() uint64
				PayloadSkipped() bool
				BodyPayloadSkipped() bool
				CopyMetadata() buffer.SocketDataBuffer
			}) answers {
				var meta events.SocketDataUploadEvent
				if !events.DetachTo(b.CopyMetadata(), &meta) {
					t.Fatalf("the metadata copy of a %T is no event of the agent", b)
				}
				return answers{b.Protocol(), b.GenerateConnectionID(), b.BufferData(), b.TotalSize(), b.Direction(),
					b.BufferStartPosition(), b.BufferLen(), b.DataSequence(), b.DataID(), b.PrevDataID(),
					b.IsStart(), b.IsFinished(), b.HaveReduceDataAfterChunk(), b.StartTime(), b.EndTime(), b.Time(),
					b.PayloadSkipped(), b.BodyPayloadSkipped(), b.DecodeSequence(), b.GetConnectionID(),
					b.GetRandomID(), b.Timestamp(), b.GetStartTime(), b.GetEndTime(), b.GetL4TotalPackageSize(),
					b.GetL4PackageCount(), b.GetFunctionName(), b.GetProtocol(), b.GetSSL(), buffer.IsPayloadSkipped(b),
					buffer.IsBodyPayloadSkipped(b), events.CanMergeCalls(b, evs[0]), events.CanMergeCalls(b, records[0]),
					evs[0].CanMergeDetail(b), events.CanMergeCalls(records[0], b), meta}
			}
			if a, b := of(e), of(r); !reflect.DeepEqual(a, b) {
				t.Fatalf("record %d %s:\nevent  %+v\nrecord %+v", i, stage, a, b)
			}
			if a, b := e.CanMergeDetail(evs[1]), events.CanMergeCalls(e, evs[1]); a != b {
				t.Fatalf("CanMergeCalls %t, CanMergeDetail %t", b, a)
			}
			var fromEvent, fromRecord events.SocketDataUploadEvent
			e.DetachTo(&fromEvent)
			events.DetachRecordTo(r, &fromRecord)
			if !reflect.DeepEqual(fromEvent, fromRecord) {
				t.Fatalf("record %d %s: the detail copies differ:\nevent  %+v\nrecord %+v", i, stage, fromEvent, fromRecord)
			}
			// a merge of the record into a copy is the merge of its event
			a, b := evs[0].CopyForMerge(), evs[0].CopyForMerge()
			a.MergeDetail(e)
			b.MergeDetail(r)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("record %d %s: merged %+v, the event merges %+v", i, stage, b, a)
			}
			if !reflect.DeepEqual(forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, e),
				forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, r)) {
				t.Fatalf("record %d %s: kernel logs differ", i, stage)
			}
		}
		check("before the release")
		if eb, rb := e.ReleaseBuffer(), r.ReleaseBuffer(); eb != nil || rb != nil {
			t.Fatalf("record %d: a pooled buffer is released", i)
		}
		check("after the release")
		buffer.ReleaseEvent(nil) // the admission of the record
	}
	if size := unsafe.Sizeof(buffer.CompactRecord{}); size > buffer.CompactRecordSize {
		t.Fatalf("a record takes %d bytes", size)
	}
}

// TestH2CRecordDropKeepsNoCopy: a record the parser drops goes to the flush queue as it is, and its kernel
// log is what the copy of its event gives
func TestH2CRecordDropKeepsNoCopy(t *testing.T) {
	sample := h2cBenchRecords(1)
	var records []buffer.SocketDataBuffer
	connBuf := buffer.NewBuffer()
	events.SplitH2CBatch(sample, func(data interface{}) {
		records = append(records, connBuf.AppendDataEvent(data.(buffer.SocketDataBuffer)))
	}, nil)
	records = append(records, &buffer.SocketDataEventLimited{SocketDataBuffer: records[3], Size: 4})
	legacy := &common.AccessLogContext{Queue: common.NewQueue(1000, time.Hour, detachNoopConsumer{})}
	current := &common.AccessLogContext{Queue: common.NewQueue(1000, time.Hour, detachNoopConsumer{})}
	analyze := NewHTTP2Analyze(current).(protocols.HTTP2DropEventListener)
	for _, b := range records {
		forwarder.SendTransferNoProtocolEvent(legacy, events.DetachRecord(detailSource(b).(*events.H2CRecord)))
		analyze.OnDropEvent(nil, b)
	}
	want, got := drainKernelLogs(legacy.Queue), drainKernelLogs(current.Queue)
	if len(want) != len(records) || len(got) != len(want) {
		t.Fatalf("%d kernel logs, %d expected", len(got), len(want))
	}
	for i := range want {
		if got[i].Event() != events.Event(detailSource(records[i]).(*events.H2CRecord)) || got[i].Owned() {
			t.Fatalf("log %d: the record is not queued as it is", i)
		}
		wl := forwarder.BuildKernelLogFromEvent(want[i].Type(), want[i].Event())
		gl := forwarder.BuildKernelLogFromEvent(got[i].Type(), got[i].Event())
		if !proto.Equal(wl, gl) {
			t.Fatalf("log %d: kernel log %v, expected %v", i, gl, wl)
		}
		wt, _, _ := forwarder.BuildTransferLog(want[i].Event())
		gt, _, _ := forwarder.BuildTransferLog(got[i].Event())
		if wt != gt {
			t.Fatalf("log %d: transfer log %+v, expected %+v", i, gt, wt)
		}
	}
	for range sample[:events.BatchRecordCount(sample)] {
		buffer.ReleaseEvent(nil) // the admissions of the records
	}
}
