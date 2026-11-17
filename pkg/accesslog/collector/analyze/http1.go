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
	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	upstreamEnums "github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var http1Log = logger.GetLogger("accesslog", "collector", "protocols", "http1")

type http1Analyze struct {
	moduleMgr *module.Manager
	ctx       *common.AccessLogContext
	// trace: the logs carry the tracing context of the requests (access_log.protocol_analyze.analyze_trace_context)
	trace bool
}

func NewHTTP1Analyze(moduleMgr *module.Manager, ctx *common.AccessLogContext) protocols.HTTP1ProtocolAnalyzer {
	analyze := &http1Analyze{moduleMgr: moduleMgr, ctx: ctx, trace: analyzeTraceContext(ctx)}
	return analyze
}

// HandleHTTPData is the analyzer for HTTP1 protocol
// difference with upstream: since the detail and data upload events combined, so no need to find the related details
func (a *http1Analyze) HandleHTTPData(metrics *protocols.HTTP1Metrics, connection *protocols.PartitionConnection,
	request *reader.Request, response *reader.Response) error {
	// the second argument of CombineSlices is the original buffer the details are queried from, not a
	// part of the message: passing the request headers there dropped their events from the combined
	// buffer, so the request write had no kernel log detail and StartTime came from the response.
	// Only the events are needed: the combined buffer itself is built for the debug log only.
	bufs := [...]*buffer.Buffer{request.HeaderBuffer(), request.BodyBuffer(), response.HeaderBuffer(), response.BodyBuffer()}
	buffers := buffer.CombinedSocketBuffers(bufs[:]...)
	if len(buffers) == 0 {
		return errNoMessageDetail
	}
	if http1Log.Enable(logrus.DebugLevel) {
		totalBuffer := buffer.CombineSlices(true, nil, bufs[:]...)
		idRange := totalBuffer.BuildTotalDataIDRange()
		http1Log.Debugf("found fully HTTP1 request and response, contains %d buffer events, "+
			"connection ID: %d, random ID: %d, data range: %d-%d(%t)",
			len(buffers), metrics.ConnectionID, metrics.RandomID, buffers[0].DataID(), idRange.To, idRange.IsToBufferReadFinished)
	}

	details := messageDetails(buffers)

	host := request.Headers().Get("Host")
	var path string
	if u := request.Original().URL; u != nil {
		path = u.Path
		if host == "" {
			host = u.Host
		}
	}
	httpLog := &HTTPProtocolLog{
		HTTP: v3.AccessLogHTTPProtocol{Version: v3.AccessLogHTTPProtocolVersion_HTTP1},
		Request: v3.AccessLogHTTPProtocolRequest{
			Method:             protocols.TransformHTTPMethod(request.Original().Method),
			Path:               path,
			SizeOfHeadersBytes: uint64(request.HeaderBuffer().DataSize()),
			SizeOfBodyBytes:    uint64(request.BodyBuffer().DataSize()),
			Host:               host,
		},
		Response: v3.AccessLogHTTPProtocolResponse{
			StatusCode:         int32(response.Original().StatusCode), //nolint:bodyclose // parsed from captured data, nothing to close
			SizeOfHeadersBytes: uint64(response.HeaderBuffer().DataSize()),
			SizeOfBodyBytes:    uint64(response.BodyBuffer().DataSize()),
		},
	}
	if a.trace {
		header := request.Original().Header
		httpLog.Request.Trace = traceInfo(header.Get, http1Log)
	}

	protocolLog := httpLog.Build(details, buffers[0].StartTime(), buffers[len(buffers)-1].EndTime(), connectionSNI(connection), host)

	forwarder.SendTransferProtocolEvent(a.ctx, protocolLog)
	return nil
}

func (a *http1Analyze) OnProtocolBreak(_ *protocols.HTTP1Metrics, connection *protocols.PartitionConnection) {
	buf := connection.Buffer(upstreamEnums.ConnectionProtocolHTTP)
	sendDetachedNoProtocolEvents(a.ctx, buf.TotalBuffer())
}
