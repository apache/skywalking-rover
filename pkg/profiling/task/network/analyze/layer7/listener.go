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

package layer7

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/docker/go-units"

	"github.com/apache/skywalking-rover/pkg/module"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols"
	protocol "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"github.com/zekroTJA/timedmap"
)

var ListenerName = "layer7"

const (
	ConnectionCachedTTL      = time.Minute
	ConnectionCacheFlushTime = time.Second * 20
)

type Listener struct {
	analyzer             *base.AnalyzerContext
	cachedConnections    *timedmap.TimedMap
	protocolPerCPUBuffer int

	socketDataQueue *btf.EventQueue
}

func NewListener(analyzer *base.AnalyzerContext) *Listener {
	l := &Listener{
		analyzer:          analyzer,
		cachedConnections: timedmap.New(ConnectionCacheFlushTime),
	}
	return l
}

func (l *Listener) Name() string {
	return ListenerName
}

func (l *Listener) Init(config *profiling.TaskConfig, _ *module.Manager) error {
	analyzeConfig := config.Network.ProtocolAnalyze
	perCPUBufferSize, err := units.RAMInBytes(analyzeConfig.PerCPUBufferSize)
	if err != nil {
		return err
	}
	if int(perCPUBufferSize) < os.Getpagesize() {
		return fmt.Errorf("the cpu buffer must bigger than %dB", os.Getpagesize())
	}
	if analyzeConfig.Parallels < 1 {
		return fmt.Errorf("the parallels cannot be small than 1")
	}
	if analyzeConfig.QueueSize < 1 {
		return fmt.Errorf("the queue size be small than 1")
	}

	l.protocolPerCPUBuffer = int(perCPUBufferSize)
	l.initSocketDataQueue(analyzeConfig.Parallels, analyzeConfig.QueueSize, config)
	return nil
}

func (l *Listener) GenerateMetrics() base.ConnectionMetrics {
	return protocols.NewProtocolMetrics()
}

func (l *Listener) RegisterBPFEvents(ctx context.Context, bpfLoader *bpf.Loader) {
	l.startSocketData(ctx, bpfLoader)
}

func (l *Listener) ReceiveNewConnection(*base.ConnectionContext, *events.SocketConnectEvent) {
}

func (l *Listener) ReceiveCloseConnection(ctx *base.ConnectionContext, event *events.SocketCloseEvent) {
	// cached the closed connection with TTL
	l.cachedConnections.Set(l.generateCachedConnectionKey(ctx.ConnectionID, ctx.RandomID), ctx, ConnectionCachedTTL)
	l.handleConnectionClose(event)
}

func (l *Listener) UpdateExtensionConfig(config *profiling.ExtensionConfig) {
	l.handleProfilingExtensionConfig(config)
}

func (l *Listener) PreFlushConnectionMetrics([]*base.ConnectionWithBPF, *bpf.Loader) error {
	return nil
}

func (l *Listener) PostFlushConnectionMetrics([]*base.ConnectionContext) {
}

func (l *Listener) FlushMetrics(traffics []*base.ProcessTraffic, builder *base.MetricsBuilder) {
	for _, traffic := range traffics {
		metrics := traffic.Metrics.GetMetrics(l.Name()).(*protocols.ProtocolMetrics)
		metrics.FlushMetrics(traffic, builder)
	}
}

func (l *Listener) QueryConnection(conID, randomID uint64) *base.ConnectionContext {
	// found the connection from the active connections first
	connection := l.analyzer.GetActiveConnection(conID, randomID)
	if connection != nil {
		return connection
	}

	// if not exists, then found in the cached connections
	cacheCon := l.cachedConnections.GetValue(l.generateCachedConnectionKey(conID, randomID))
	if cacheCon != nil {
		return cacheCon.(*base.ConnectionContext)
	}
	return nil
}

func (l *Listener) QueryProtocolMetrics(conMetrics *base.ConnectionMetricsContext, p enums.ConnectionProtocol) protocol.Metrics {
	metrics := conMetrics.GetMetrics(ListenerName).(*protocols.ProtocolMetrics)
	return metrics.GetProtocolMetrics(p)
}

func (l *Listener) generateCachedConnectionKey(conID, randomID uint64) string {
	return fmt.Sprintf("%d_%d", conID, randomID)
}
