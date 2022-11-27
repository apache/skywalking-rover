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
	protocol "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1"
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
	protocols []protocol.Protocol
}

func NewAnalyzer(ctx protocol.Context, config *profiling.TaskConfig) *Analyzer {
	protocols := make([]protocol.Protocol, 0)
	for _, r := range registerProtocols {
		p := r()
		p.Init(config)
		protocols = append(protocols, p)
	}
	return &Analyzer{
		ctx:       ctx,
		protocols: protocols,
	}
}

func (a *Analyzer) ReceiveSocketDataEvent(event *protocol.SocketDataUploadEvent) {
	for _, p := range a.protocols {
		if p.ReceiveData(a.ctx, event) {
			return
		}
	}
	log.Warnf("could not found any protocol to handle socket data, connection id: %s, protocol: %s(%d), type: %s",
		event.GenerateConnectionID(), event.Protocol.String(), event.Protocol, event.MsgType.String())
}

func (a *Analyzer) UpdateExtensionConfig(config *profiling.ExtensionConfig) {
	for _, p := range a.protocols {
		p.UpdateExtensionConfig(config)
	}
}

type ProtocolMetrics struct {
	data map[string]protocol.Metrics
}

func NewProtocolMetrics() *ProtocolMetrics {
	metrics := make(map[string]protocol.Metrics)
	for _, p := range defaultInstances {
		metrics[p.Name()] = p.GenerateMetrics()
	}
	return &ProtocolMetrics{data: metrics}
}

func (m *ProtocolMetrics) GetProtocolMetrics(name string) protocol.Metrics {
	return m.data[name]
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
