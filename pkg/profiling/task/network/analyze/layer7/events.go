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

	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	analyzeBase "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

func (l *Listener) initSocketDataQueue(parallels, queueSize int, config *profiling.TaskConfig) {
	l.socketDataQueue = btf.NewEventQueue("socket data resolver", parallels, queueSize, func(num int) btf.PartitionContext {
		return NewSocketDataPartitionContext(l, config)
	})
}

func (l *Listener) startSocketData(ctx context.Context, bpfLoader *bpf.Loader) {
	// socket buffer data
	l.socketDataQueue.RegisterReceiver(bpfLoader.SocketDataUploadQueue, l.protocolPerCPUBuffer, 1, func() interface{} {
		return &analyzeBase.SocketDataUploadEvent{}
	}, func(data interface{}) int {
		return int(data.(*analyzeBase.SocketDataUploadEvent).ConnectionID)
	})

	// socket detail
	l.socketDataQueue.RegisterReceiver(bpfLoader.SocketDetailDataQueue, l.protocolPerCPUBuffer, 1, func() interface{} {
		return &analyzeBase.SocketDetailEvent{}
	}, func(data interface{}) int {
		return int(data.(*analyzeBase.SocketDetailEvent).ConnectionID)
	})

	l.socketDataQueue.Start(ctx, bpfLoader.Linker)
}

func (l *Listener) handleProfilingExtensionConfig(config *profiling.ExtensionConfig) {
	if l.socketDataQueue == nil {
		return
	}
	for _, p := range l.socketDataQueue.PartitionContexts() {
		ctx := p.(*SocketDataPartitionContext)
		ctx.analyzer.UpdateExtensionConfig(config)
	}
}

func (l *Listener) handleConnectionClose(event *analyzeBase.SocketCloseEvent) {
	if l.socketDataQueue == nil {
		return
	}
	for _, p := range l.socketDataQueue.PartitionContexts() {
		ctx := p.(*SocketDataPartitionContext)
		ctx.analyzer.ReceiveSocketClose(event)
	}
}

type SocketDataPartitionContext struct {
	analyzer *protocols.Analyzer
}

func NewSocketDataPartitionContext(l base.Context, config *profiling.TaskConfig) *SocketDataPartitionContext {
	return &SocketDataPartitionContext{
		analyzer: protocols.NewAnalyzer(l, config),
	}
}

func (p *SocketDataPartitionContext) Start(ctx context.Context) {
	p.analyzer.Start(ctx)
}

func (p *SocketDataPartitionContext) Consume(data interface{}) {
	switch v := data.(type) {
	case *analyzeBase.SocketDetailEvent:
		p.analyzer.ReceiveSocketDetail(v)
	case *analyzeBase.SocketDataUploadEvent:
		p.analyzer.ReceiveSocketDataEvent(v)
	}
}
