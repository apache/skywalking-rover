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
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"
)

func (l *Listener) initSocketDataQueue(parallels, queueSize int, config *profiling.TaskConfig) {
	l.socketDataQueue = NewEventQueue(parallels, queueSize, func() PartitionContext {
		return NewSocketDataPartitionContext(l, config)
	})
}

func (l *Listener) startSocketData(ctx context.Context, bpfLoader *bpf.Loader) {
	l.socketDataQueue.Start(ctx, bpfLoader, bpfLoader.SocketDataUploadEventQueue, 1, l.protocolPerCPUBuffer,
		func() interface{} {
			return &base.SocketDataUploadEvent{}
		}, func(data interface{}) string {
			return data.(*base.SocketDataUploadEvent).GenerateConnectionID()
		})
}

func (l *Listener) handleProfilingExtensionConfig(config *profiling.ExtensionConfig) {
	if l.socketDataQueue == nil {
		return
	}
	for _, p := range l.socketDataQueue.partitions {
		ctx := p.ctx.(*SocketDataPartitionContext)
		ctx.analyzer.UpdateExtensionConfig(config)
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

func (p *SocketDataPartitionContext) Consume(data interface{}) {
	event := data.(*base.SocketDataUploadEvent)
	p.analyzer.ReceiveSocketDataEvent(event)
}
