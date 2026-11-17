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
	"errors"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// errNoMessageDetail: a message none of whose socket calls is left to report it with (no buffer event, or no
// event that carries a kernel log detail)
var errNoMessageDetail = errors.New("the message has no socket call detail")

var http2Log = logger.GetLogger("accesslog", "collector", "protocols", "http2")

type http2Analyze struct {
	ctx *common.AccessLogContext
	// trace: the logs carry the tracing context of the requests (access_log.protocol_analyze.analyze_trace_context)
	trace bool
}

func NewHTTP2Analyze(ctx *common.AccessLogContext) protocols.HTTP2StreamAnalyzer {
	analyze := &http2Analyze{ctx: ctx, trace: analyzeTraceContext(ctx)}
	return analyze
}

func (a *http2Analyze) HandleWholeStream(connection *protocols.PartitionConnection, stream *protocols.HTTP2Streaming) error {
	// the second argument of CombineSlices is the original buffer the details are queried from, not a
	// part of the message: passing the request headers there dropped their events from the combined
	// buffer, so the request HEADERS write had no kernel log detail and StartTime came from the response.
	// Only the events are needed: the combined buffer itself is built for the debug log only.
	bufs := [...]*buffer.Buffer{stream.ReqHeaderBuffer, stream.ReqBodyBuffer, stream.RespHeaderBuffer, stream.RespBodyBuffer}
	var buffers []buffer.SocketDataBuffer
	if len(stream.ReqSummaries) > 0 || len(stream.RespSummaries) > 0 {
		// the details of the calls BPF summarised go where those calls would be (summaryDetails)
		buffers = withSummaries(bufs, stream.ReqSummaries, stream.RespSummaries)
	} else {
		buffers = buffer.CombinedSocketBuffers(bufs[:]...)
	}
	if len(buffers) == 0 {
		return errNoMessageDetail
	}
	if http2Log.Enable(logrus.DebugLevel) {
		totalBuffer := buffer.CombineSlices(true, nil, bufs[:]...)
		idRange := totalBuffer.BuildTotalDataIDRange()
		http2Log.Debugf("found fully HTTP2 request and response, contains %d buffer events, "+
			"data range: %d-%d(%t)",
			len(buffers), buffers[0].DataID(), idRange.To, idRange.IsToBufferReadFinished)
	}

	details := messageDetails(buffers)
	if len(details) == 0 {
		return errNoMessageDetail
	}

	streamHost := stream.ReqHeader.Get(":authority")
	if streamHost == "" {
		streamHost = stream.ReqHeader.Get(":host")
	}
	httpLog := &HTTPProtocolLog{
		HTTP: v3.AccessLogHTTPProtocol{Version: v3.AccessLogHTTPProtocolVersion_HTTP2},
		Request: v3.AccessLogHTTPProtocolRequest{
			Method:             a.ParseHTTPMethod(stream),
			Path:               stream.ReqHeader.Get(":path"),
			SizeOfHeadersBytes: uint64(stream.ReqHeaderBuffer.DataSize()),
			SizeOfBodyBytes:    uint64(stream.ReqBodyBuffer.DataSize()),
			Host:               streamHost,
		},
		Response: v3.AccessLogHTTPProtocolResponse{
			StatusCode:         int32(stream.Status),
			SizeOfHeadersBytes: uint64(stream.RespHeaderBuffer.DataSize()),
			SizeOfBodyBytes:    uint64(stream.RespBodyBuffer.DataSize()),
		},
	}
	if a.trace {
		httpLog.Request.Trace = traceInfo(stream.ReqHeader.Get, http2Log)
	}

	protocolLog := httpLog.Build(details, buffers[0].StartTime(), details[len(details)-1].GetEndTime(), connectionSNI(connection), streamHost)
	forwarder.SendTransferProtocolEvent(a.ctx, protocolLog)
	return nil
}

func (a *http2Analyze) OnProtocolBreak(connection *protocols.PartitionConnection, metrics *protocols.HTTP2Metrics) {
	buf := connection.Buffer(enums.ConnectionProtocolHTTP2)
	for _, b := range buf.TotalBuffer() {
		a.OnDropEvent(connection, b)
	}
}

// OnDropEvent reports the kernel level detail of a socket data event the HTTP/2 parser has to drop
// (late arrival or broken framing). Every data event is the only carrier of the L4 detail of its call,
// so without this the bytes of the dropped socket call would disappear from the connection metrics.
func (a *http2Analyze) OnDropEvent(_ *protocols.PartitionConnection, b buffer.SocketDataBuffer) {
	if buffer.IsSummaryGap(b) {
		// the bytes of summarised calls: their details come with the summaries (OnOrphanSummary)
		return
	}
	switch event := detailSource(b).(type) {
	case *events.H2CRecord:
		// a batch record is an allocation of its own (buffer.NewCompactRecord) that holds no pooled buffer and
		// shares nothing with other records, and the fields its kernel log is built of never change: it goes
		// as it is, no copy, and keeps only itself alive in the flush queue
		forwarder.SendTransferNoProtocolEvent(a.ctx, event)
	case *events.SocketDataUploadEvent:
		if event.Buffer == nil {
			// no buffer to pin (payload skipped or metadata only): the event goes as it is, no copy
			forwarder.SendTransferNoProtocolEvent(a.ctx, event)
		} else {
			forwarder.SendTransferNoProtocolEvent(a.ctx, event.Detach())
		}
	}
}

func (a *http2Analyze) ParseHTTPMethod(streaming *protocols.HTTP2Streaming) v3.AccessLogHTTPProtocolRequestMethod {
	method := streaming.ReqHeader.Get(":method")
	if method == "" {
		return v3.AccessLogHTTPProtocolRequestMethod_Get
	}

	return protocols.TransformHTTPMethod(strings.ToUpper(method))
}

// DrainSummaries implements protocols.HTTP2SummaryHandler: the summaries BPF still keeps of the stream
func (a *http2Analyze) DrainSummaries(connectionID, randomID uint64, streamID uint32,
	requests []protocols.HTTP2DrainRequest) []protocols.HTTP2Summary {
	if s := h2cSummaries.Load(); s != nil {
		return s.DrainStream(connectionID, randomID, streamID, requests)
	}
	return nil
}

// OnOrphanSummary implements protocols.HTTP2SummaryHandler: a summary of calls no reported stream took (a reset
// stream, a stream that never ended or that the parser dropped) goes as one kernel log, the merged detail of
// its calls
func (a *http2Analyze) OnOrphanSummary(_ *protocols.PartitionConnection, s protocols.HTTP2Summary) {
	sendOrphanSummary(a.ctx, s)
}

func sendOrphanSummary(ctx *common.AccessLogContext, s protocols.HTTP2Summary) {
	summary, ok := s.(*events.H2CSummary)
	if !ok {
		return
	}
	forwarder.SendTransferNoProtocolEvent(ctx, summary.Detail())
}

// withSummaries is the events of the parts of a stream with the details of its summaries among the events of
// its bodies: each summary in front of the first event of its body whose data id is above the data id of the
// first call of the summary (behind them all when there is none), which is where its first call would be. A
// summary stands for calls of one function and one minute, and every event of the body between its calls is of
// that function and minute too (BPF starts another summary when either changes), so the merge of the details
// gives what it gives with the calls one by one (messageDetails).
//
// The events of a part are appended straight into the result (Buffer.AppendTotalBuffer, what
// CombinedSocketBuffers of the part returns), and the details of its summaries are inserted among them, made in
// one allocation for all of them; the summaries of a part are in the order of their first calls
// (attachSummaries), so each goes behind the one before.
func withSummaries(bufs [4]*buffer.Buffer, req, resp []protocols.HTTP2Summary) []buffer.SocketDataBuffer {
	sections := [4][]protocols.HTTP2Summary{nil, req, nil, resp}
	size := len(req) + len(resp)
	for _, b := range bufs {
		size += b.TotalBufferLen()
	}
	result := make([]buffer.SocketDataBuffer, 0, size)
	details := make([]events.SocketDataUploadEvent, len(req)+len(resp))
	next := 0
	for i, b := range bufs {
		start := len(result)
		result = b.AppendTotalBuffer(result)
		// where the next summary of the part may go: behind the detail of the one before
		at := start
		for _, p := range sections[i] {
			var detail buffer.SocketDataBuffer
			if summary, ok := p.(*events.H2CSummary); ok {
				summary.DetailTo(&details[next])
				detail = &details[next]
				next++
			}
			first := p.SummaryFirstDataID()
			for at < len(result) && result[at].DataID() <= first {
				at++
			}
			result = append(result, nil)
			copy(result[at+1:], result[at:])
			result[at] = detail
			at++
		}
	}
	return result
}

func init() {
	// what the h2c follower of BPF knew of the frames of a call (h2c_frames and first_frame_off of the event, see
	// skywalking-rover/bpf/accesslog/syscalls/h2c.h H2C_FRAMES_*), for the parser's judgement of a call it drops
	protocols.SetHTTP2CallFramesSource(h2cCallFrames)
}

// h2cCallFrames reads what the follower knew of the frames of the call of the event; false when it knew nothing
func h2cCallFrames(event buffer.SocketDataBuffer) (protocols.HTTP2CallFrames, bool) {
	flags, first, ok := buffer.H2CFramesOf(event)
	if !ok || flags&buffer.H2CFramesKnown == 0 {
		return protocols.HTTP2CallFrames{}, false
	}
	offset := int(first)
	if first == 0xffff {
		offset = -1
	}
	return protocols.HTTP2CallFrames{CursorKnown: true, NoHeaderBytes: flags&buffer.H2CFramesNoHeaderBlock != 0,
		StartsInHeaderBlock: flags&buffer.H2CFramesStartsInHeaderBlock != 0, FirstFrameOffset: offset}, true
}
