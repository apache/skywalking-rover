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
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

type ProtocolManager struct {
	protocols map[enums.ConnectionProtocol]Protocol
}

func NewProtocolManager(protocols []Protocol) *ProtocolManager {
	m := make(map[enums.ConnectionProtocol]Protocol)
	for _, protocol := range protocols {
		m[protocol.ForProtocol()] = protocol
	}
	return &ProtocolManager{protocols: m}
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
	ForProtocol() enums.ConnectionProtocol
	GenerateConnection(connectionID, randomID uint64) ProtocolMetrics
	Analyze(connection *PartitionConnection, helper *AnalyzeHelper) error
}

func AppendSocketDetailsFromBuffer(result []events.SocketDetail, buf *buffer.Buffer, dataIdRange *buffer.DataIDRange,
	allDetailInclude bool) ([]events.SocketDetail, *buffer.DataIDRange, bool) {
	if buf == nil || !allDetailInclude {
		return result, dataIdRange, false
	}
	details := buf.BuildDetails()
	if details == nil || details.Len() == 0 {
		return result, dataIdRange, false
	}
	currentDataIdRange := buf.BuildTotalDataIDRange()
	if !currentDataIdRange.IsIncludeAllDetails(details) {
		return result, dataIdRange, false
	}
	for e := details.Front(); e != nil; e = e.Next() {
		if len(result) > 0 && result[len(result)-1] == e.Value {
			continue
		}
		result = append(result, e.Value.(events.SocketDetail))
	}
	if dataIdRange == nil {
		return result, currentDataIdRange, true
	}
	return result, dataIdRange.Append(currentDataIdRange), true
}

func AnalyzeTraceInfo(fetcher func(key string) string, protocolLog *logger.Logger) *v3.AccessLogTraceInfo {
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
