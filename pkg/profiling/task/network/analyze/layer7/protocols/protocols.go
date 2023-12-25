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
	"github.com/apache/skywalking-rover/pkg/logger"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
	protocol "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"golang.org/x/net/context"
)

var log = logger.GetLogger("profiling", "task", "network", "layer7", "protocols")

var registerProtocols []func() protocol.Protocol
var defaultInstances []protocol.Protocol

func init() {
	// register all protocol analyzers
	registerProtocols = make([]func() protocol.Protocol, 0)
	registerProtocols = append(registerProtocols, http1.NewHTTP1Analyzer)

	defaultInstances = make([]protocol.Protocol, 0)
	for _, p := range registerProtocols {
		defaultInstances = append(defaultInstances, p())
	}
}

type Analyzer struct {
	ctx       protocol.Context
	protocols map[enums.ConnectionProtocol]*protocol.ProtocolAnalyzer
}

func NewAnalyzer(ctx protocol.Context, config *profiling.TaskConfig) *Analyzer {
	protocols := make(map[enums.ConnectionProtocol]*protocol.ProtocolAnalyzer)
	for _, r := range registerProtocols {
		p := r()
		p.Init(config)
		analyzer := protocol.NewProtocolAnalyzer(ctx, p, config)
		protocols[p.Protocol()] = analyzer
	}
	return &Analyzer{
		ctx:       ctx,
		protocols: protocols,
	}
}

func (a *Analyzer) Start(ctx context.Context) {
	for _, p := range a.protocols {
		p.Start(ctx)
	}
}

func (a *Analyzer) ReceiveSocketDataEvent(event *events.SocketDataUploadEvent) {
	analyzer := a.protocols[event.Protocol]
	if analyzer == nil {
		log.Warnf("could not found any protocol to handle socket data, connection id: %s, protocol: %s(%d)",
			event.GenerateConnectionID(), event.Protocol.String(), event.Protocol)
		return
	}
	analyzer.ReceiveSocketData(a.ctx, event)
}

func (a *Analyzer) ReceiveSocketDetail(event *events.SocketDetailEvent) {
	analyzer := a.protocols[event.Protocol]
	if analyzer == nil {
		log.Warnf("could not found any protocol to handle socket detail, connection id: %s, protocol: %s(%d)",
			event.GenerateConnectionID(), event.Protocol.String(), event.Protocol)
		return
	}
	analyzer.ReceiveSocketDetail(a.ctx, event)
}

func (a *Analyzer) UpdateExtensionConfig(config *profiling.ExtensionConfig) {
	for _, p := range a.protocols {
		p.UpdateExtensionConfig(config)
	}
}

func (a *Analyzer) ReceiveSocketClose(event *events.SocketCloseEvent) {
	for _, p := range a.protocols {
		p.ReceiveSocketCloseEvent(event)
	}
}

type ProtocolMetrics struct {
	data map[enums.ConnectionProtocol]protocol.Metrics
}

func NewProtocolMetrics() *ProtocolMetrics {
	metrics := make(map[enums.ConnectionProtocol]protocol.Metrics)
	for _, p := range defaultInstances {
		metrics[p.Protocol()] = p.GenerateMetrics()
	}
	return &ProtocolMetrics{data: metrics}
}

func (m *ProtocolMetrics) GetProtocolMetrics(p enums.ConnectionProtocol) protocol.Metrics {
	return m.data[p]
}

func (m *ProtocolMetrics) MergeMetricsFromConnection(connection *base.ConnectionContext, data base.ConnectionMetrics) {
	otherMetrics := data.(*ProtocolMetrics)
	for p, d := range m.data {
		d.MergeMetricsFromConnection(connection, otherMetrics.GetProtocolMetrics(p))
	}
}

func (m *ProtocolMetrics) FlushMetrics(traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	for _, d := range m.data {
		d.FlushMetrics(traffic, metricsBuilder)
	}
}
