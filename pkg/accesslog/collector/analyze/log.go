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
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// NamedProtocolLog is a protocol log with the names of the connection it was made of: the SNI name of its TLS
// handshake (empty without one, see SetSNIResolver) and the host the HTTP request named. The names are not sent:
// an agent reads them from the logs it sends (common.ProtocolLog), such as for a service discovery.
type NamedProtocolLog struct {
	parent common.ProtocolLog
	SNI    string
	Host   string
}

func NewNamedProtocolLog(event common.ProtocolLog, sni, host string) *NamedProtocolLog {
	return &NamedProtocolLog{
		parent: event,
		SNI:    sni,
		Host:   host,
	}
}

func (l *NamedProtocolLog) RelateKernelLogs() []events.SocketDetail {
	return l.parent.RelateKernelLogs()
}

func (l *NamedProtocolLog) ProtocolLog() *v3.AccessLogProtocolLogs {
	return l.parent.ProtocolLog()
}

// sniResolver gives the SNI name of a connection, nil when nothing gives it (SetSNIResolver)
var sniResolver atomic.Pointer[func(connection *protocols.PartitionConnection) string]

// SetSNIResolver sets what gives the SNI name of the TLS handshake of a connection to the HTTP logs of the analyzers
// (NamedProtocolLog), such as the TLS protocol of an agent; nil: none
func SetSNIResolver(resolve func(connection *protocols.PartitionConnection) string) {
	if resolve == nil {
		sniResolver.Store(nil)
		return
	}
	sniResolver.Store(&resolve)
}

// connectionSNI is the SNI name of the connection, empty when nothing gives one
func connectionSNI(connection *protocols.PartitionConnection) string {
	if resolve := sniResolver.Load(); resolve != nil {
		return (*resolve)(connection)
	}
	return ""
}

// HTTPProtocolLog holds every message of the log of an HTTP message, so building one is a single
// allocation instead of one per message: they are sent together and dropped together. The messages HTTP, Request
// and Response are filled by the analyzer, Build links them.
type HTTPProtocolLog struct {
	HTTP       v3.AccessLogHTTPProtocol
	Request    v3.AccessLogHTTPProtocolRequest
	Response   v3.AccessLogHTTPProtocolResponse
	named      NamedProtocolLog
	event      common.ProtocolEventData
	logs       v3.AccessLogProtocolLogs
	oneof      v3.AccessLogProtocolLogs_Http
	start, end forwarder.OffsetTimestamp
}

// Build links the messages filled in HTTP, Request and Response, and returns the log with the details as
// they are (merged already, see messageDetails), the times as forwarder.BuildOffsetTimestamps gives them
func (l *HTTPProtocolLog) Build(details []events.SocketDetail, startTime, endTime uint64, sni, host string) common.ProtocolLog {
	l.HTTP.StartTime = l.start.Build(startTime)
	l.HTTP.EndTime = l.end.Build(endTime)
	l.HTTP.Request, l.HTTP.Response = &l.Request, &l.Response
	l.oneof.Http = &l.HTTP
	l.logs.Protocol = &l.oneof
	l.event.KernelLogs, l.event.ProtocolLogData = details, &l.logs
	l.named.parent, l.named.SNI, l.named.Host = &l.event, sni, host
	return &l.named
}

// ToNativeEvent unwraps a buffer event to the agent's own socket data event (the limited wrapper of a
// sliced buffer keeps the original event); nil when the buffer is not backed by one
func ToNativeEvent(e buffer.SocketDataBuffer) *events.SocketDataUploadEvent {
	switch b := e.(type) {
	case *events.SocketDataUploadEvent:
		return b
	case *buffer.SocketDataEventLimited:
		return ToNativeEvent(b.SocketDataBuffer)
	}
	return nil
}

// detailSource unwraps a buffer event to the socket data event of the agent a kernel log detail is made of:
// the agent's own event or a batch record, an H2CRecord (the limited wrapper of a sliced buffer keeps the
// original); nil when the buffer is backed by neither
func detailSource(e buffer.SocketDataBuffer) buffer.SocketDataBuffer {
	switch b := e.(type) {
	case *events.SocketDataUploadEvent:
		return b
	case *events.H2CRecord:
		return b
	case *buffer.SocketDataEventLimited:
		return detailSource(b.SocketDataBuffer)
	}
	return nil
}

// sendDetachedNoProtocolEvents sends the kernel logs of the socket calls of the buffers, as copies without
// the data buffer: what SendTransferNoProtocolEvent(event.Detach()) for every call does, with the copies of a
// protocol break in one allocation, which they all leave the flush queue together with
func sendDetachedNoProtocolEvents(ctx *common.AccessLogContext, buffers []buffer.SocketDataBuffer) {
	count := 0
	for _, b := range buffers {
		if detailSource(b) != nil {
			count++
		}
	}
	if count == 0 {
		return
	}
	copies := make([]events.SocketDataUploadEvent, count)
	i := 0
	for _, b := range buffers {
		if event := detailSource(b); event != nil {
			events.DetachTo(event, &copies[i])
			forwarder.SendTransferNoProtocolEvent(ctx, &copies[i])
			i++
		}
	}
}

// messageDetailBuffer is the buffer of a message whose call has a kernel log detail in the message (detailSource),
// nil when it has none: a summary gap carries none, the summaries bring the details of the summarised calls
func messageDetailBuffer(b buffer.SocketDataBuffer) buffer.SocketDataBuffer {
	if b == nil || buffer.IsSummaryGap(b) {
		return nil
	}
	return b
}

// messageDetails is the kernel log details of the socket calls of a message, one per call: copies without
// the data buffer, so the protocol log does not pin the buffers until it is sent, and a call that belongs to
// two messages is not shared. With the merge of the kernel logs on, the calls of one operation are merged
// right away, into the copy of the first of them, instead of copying every call and then the merged one again.
// The result is what events.MergeDetails gives, so the log takes it as it is (HTTPProtocolLog.build). The
// copies are counted first so they take one allocation: they all go with the same protocol log. A batch
// record (H2CRecord) is copied straight into the event it stands for, which is the copy that event gives.
func messageDetails(buffers []buffer.SocketDataBuffer) []events.SocketDetail {
	merge := common.MergeKernelLogsEnabled()
	count := 0
	// a merge only reads the syscall and the start time of the first call of the operation
	var first events.SocketDetail
	// the chunks of one call come one after another under its data id, which may be 0: seen tells there was one
	latestDataID, seen := uint64(0), false
	for _, b := range buffers {
		if b = messageDetailBuffer(b); b == nil {
			continue
		}
		event := detailSource(b)
		if event == nil {
			panic(fmt.Errorf("cannot convert the buffer to native event, type: %s, buffer: %v", reflect.TypeOf(b), b))
		}
		dataID := event.DataID()
		if seen && latestDataID == dataID {
			continue
		}
		latestDataID, seen = dataID, true
		if merge && first != nil && events.CanMergeCalls(first, event.(events.SocketDetail)) {
			continue
		}
		first = event.(events.SocketDetail)
		count++
	}
	copies := make([]events.SocketDataUploadEvent, count)
	details := make([]events.SocketDetail, 0, count)
	var last *events.SocketDataUploadEvent
	latestDataID, seen = 0, false
	for _, b := range buffers {
		if b = messageDetailBuffer(b); b == nil {
			continue
		}
		event := detailSource(b)
		dataID := event.DataID()
		if seen && latestDataID == dataID {
			continue
		}
		latestDataID, seen = dataID, true
		if merge && last != nil && last.CanMergeDetail(event.(events.SocketDetail)) {
			last.MergeDetail(event.(events.SocketDetail))
			continue
		}
		last = &copies[len(details)]
		events.DetachTo(event, last)
		details = append(details, last)
	}
	return details
}

// analyzeTraceContext tells whether the HTTP logs carry the tracing context of their requests
// (access_log.protocol_analyze.analyze_trace_context)
func analyzeTraceContext(ctx *common.AccessLogContext) bool {
	return ctx != nil && ctx.Config != nil && ctx.Config.ProtocolAnalyze.AnalyzeTraceContext
}

// the tracing contexts that could not be analyzed, and when the last warning of one was logged
var traceErrors, lastTraceErrorLog atomic.Int64

// traceInfo is the tracing context of a request (SkyWalking sw8, Zipkin b3), from its headers, nil without one
func traceInfo(header func(key string) string, protocolLog *logger.Logger) *v3.AccessLogTraceInfo {
	context, err := tracing.AnalyzeTracingContext(header)
	if err != nil {
		// a malformed header of the application's requests: at most one warning a minute, the rest at debug
		total := traceErrors.Add(1)
		now, last := time.Now().UnixNano(), lastTraceErrorLog.Load()
		if now-last >= int64(time.Minute) && lastTraceErrorLog.CompareAndSwap(last, now) {
			protocolLog.Warnf("analyze tracing context error (%d in total): %v", total, err)
		} else {
			protocolLog.Debugf("analyze tracing context error: %v", err)
		}
		return nil
	}
	if context == nil {
		return nil
	}
	return &v3.AccessLogTraceInfo{
		TraceId:        context.TraceID(),
		TraceSegmentId: context.TraceSegmentID(),
		SpanId:         context.SpanID(),
		Provider:       context.Provider().AccessLogType,
	}
}
