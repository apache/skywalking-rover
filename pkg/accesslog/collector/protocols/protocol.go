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

package protocols

import (
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var registeredProtocols = make(map[enums.ConnectionProtocol]func(ctx *common.AccessLogContext) Protocol)

type ProtocolManager struct {
	protocols map[enums.ConnectionProtocol]Protocol
}

func NewProtocolManager(ctx *common.AccessLogContext) *ProtocolManager {
	protocols := make(map[enums.ConnectionProtocol]Protocol)
	for protocol, generator := range registeredProtocols {
		protocols[protocol] = generator(ctx)
	}
	return &ProtocolManager{protocols: protocols}
}

func (a *ProtocolManager) GetProtocol(protocol enums.ConnectionProtocol) Protocol {
	return a.protocols[protocol]
}

type ProtocolMetrics interface {
}

type AnalyzeHelper struct {
	ProtocolBreak bool
}

type Protocol interface {
	GenerateConnection(connectionID uint64) ProtocolMetrics
	Analyze(metrics ProtocolMetrics, buffer *buffer.Buffer, helper *AnalyzeHelper) error
}

func appendSocketDetailsFromBuffer(result []*events.SocketDetailEvent, buf *buffer.Buffer) []*events.SocketDetailEvent {
	if buf.DetailLength() == 0 {
		return result
	}
	for e := buf.Details().Front(); e != nil; e = e.Next() {
		if len(result) > 0 && result[len(result)-1] == e.Value {
			continue
		}
		result = append(result, e.Value.(*events.SocketDetailEvent))
	}
	return result
}

func analyzeTraceInfo(fetcher func(key string) string, protocolLog *logger.Logger) *v3.AccessLogTraceInfo {
	context, err := tracing.AnalyzeTracingContext(func(key string) string {
		return fetcher(key)
	})
	if err != nil {
		protocolLog.Warnf("analyze tracing context error: %v", err)
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
