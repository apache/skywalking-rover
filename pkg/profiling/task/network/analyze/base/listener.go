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

package base

import (
	"context"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"
)

type AnalyzeListener interface {
	// Name of the listener
	Name() string
	// Init listener
	Init(config *base.TaskConfig, moduleManager *module.Manager) error
	// GenerateMetrics generate a metrics context
	// It would bind to a ConnectionContext or ProcessTraffic automatically
	GenerateMetrics() ConnectionMetrics

	// RegisterBPFEvents register the BPF events
	RegisterBPFEvents(ctx context.Context, bpfLoader *bpf.Loader)

	// ReceiveNewConnection call this method when receive a new connection event
	// when return a metrics then It would bind to with the connection
	ReceiveNewConnection(ctx *ConnectionContext, event *SocketConnectEvent)
	// ReceiveCloseConnection call this method when receive the connection close event
	ReceiveCloseConnection(ctx *ConnectionContext, event *SocketCloseEvent)

	// UpdateExtensionConfig for sampling
	UpdateExtensionConfig(config *base.ExtensionConfig)

	// PreFlushConnectionMetrics prepare to flush the connection metrics
	PreFlushConnectionMetrics(ccs []*ConnectionWithBPF, bpfLoader *bpf.Loader) error
	// FlushMetrics flush all metrics from connections
	FlushMetrics(traffics []*ProcessTraffic, builder *MetricsBuilder)
	// PostFlushConnectionMetrics after flushing all metrics, usually used to refresh the metrics
	PostFlushConnectionMetrics(ccs []*ConnectionContext)
}

type ConnectionWithBPF struct {
	Connection  *ConnectionContext
	ActiveInBPF *ActiveConnectionInBPF
}
