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
	"time"

	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/buffer"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/enums"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
)

type Protocol interface {
	Protocol() events.ConnectionProtocol
	GenerateMetrics() Metrics
	Init(config *profiling.TaskConfig)

	ParseProtocol(connectionID uint64, metrics Metrics, reader *buffer.Buffer) enums.ParseResult
	PackageMaxExpireDuration() time.Duration
	UpdateExtensionConfig(config *profiling.ExtensionConfig)
}

type Context interface {
	QueryConnection(connectionID, randomID uint64) *base.ConnectionContext
	QueryProtocolMetrics(conMetrics *base.ConnectionMetricsContext, protocol events.ConnectionProtocol) Metrics
}

type Metrics interface {
	base.ConnectionMetrics

	// FlushMetrics flush all metrics from traffic to the metricsBuilder
	FlushMetrics(traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder)
}
