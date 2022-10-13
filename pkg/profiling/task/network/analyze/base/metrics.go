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

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

// ListenerMetrics The Metrics in each listener
type ListenerMetrics interface {
	// FlushMetrics Flush the metrics of connection, and merge into self
	FlushMetrics(connection *ConnectionContext)
}

type ConnectionMetrics struct {
	data map[string]ListenerMetrics
}

func (c *AnalyzerContext) NewConnectionMetrics() *ConnectionMetrics {
	data := make(map[string]ListenerMetrics)
	for _, l := range c.listeners {
		data[l.Name()] = l.GenerateMetrics()
	}
	return &ConnectionMetrics{data: data}
}

func (c *ConnectionMetrics) GetMetrics(listenerName string) ListenerMetrics {
	return c.data[listenerName]
}

func (c *ConnectionMetrics) FlushMetrics(connection *ConnectionContext) {
	for _, metric := range c.data {
		metric.FlushMetrics(connection)
	}
}

type MetricsBuilder struct {
	prefix  string
	metrics map[metadata][]*v3.MeterData
}

func NewMetricsBuilder(prefix string) *MetricsBuilder {
	return &MetricsBuilder{
		prefix:  prefix,
		metrics: make(map[metadata][]*v3.MeterData),
	}
}

func (m *MetricsBuilder) AppendMetrics(service, instance string, metrics []*v3.MeterData) {
	meta := metadata{ServiceName: service, InstanceName: instance}
	existingMetrics := m.metrics[meta]
	if len(existingMetrics) == 0 {
		m.metrics[meta] = metrics
		return
	}
	m.metrics[meta] = append(existingMetrics, metrics...)
}

func (m *MetricsBuilder) MetricPrefix() string {
	return m.prefix
}

func (m *MetricsBuilder) Build() []*v3.MeterDataCollection {
	collections := make([]*v3.MeterDataCollection, 0)
	now := time.Now().UnixMilli()
	for meta, meters := range m.metrics {
		if len(meters) == 0 {
			continue
		}
		meters[0].Service = meta.ServiceName
		meters[0].ServiceInstance = meta.InstanceName
		meters[0].Timestamp = now
		collections = append(collections, &v3.MeterDataCollection{MeterData: meters})
	}
	return collections
}

type metadata struct {
	ServiceName  string
	InstanceName string
}
