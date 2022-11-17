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

import "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"

type Protocol interface {
	Name() string
	GenerateMetrics() Metrics

	ReceiveData(context Context, event *SocketDataUploadEvent) bool
}

type Context interface {
	QueryConnection(connectionID, randomID uint64) *base.ConnectionContext
	QueryProtocolMetrics(conMetrics *base.ConnectionMetricsContext, protocolName string) Metrics
}

type Metrics interface {
	base.ConnectionMetrics

	// FlushMetrics flush all metrics from traffic to the metricsBuilder
	FlushMetrics(traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder)
}
