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
	"fmt"
	"time"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/tools"

	agentv3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
	logv3 "skywalking.apache.org/repo/goapi/collect/logging/v3"
)

// ConnectionMetrics The Metrics in each listener
type ConnectionMetrics interface {
	// MergeMetricsFromConnection merge the metrics from connection, and added into self
	MergeMetricsFromConnection(connection *ConnectionContext, data ConnectionMetrics)
}

type ConnectionMetricsContext struct {
	data map[string]ConnectionMetrics
}

func (c *AnalyzerContext) NewConnectionMetrics() *ConnectionMetricsContext {
	data := make(map[string]ConnectionMetrics)
	for _, l := range c.listeners {
		data[l.Name()] = l.GenerateMetrics()
	}
	return &ConnectionMetricsContext{data: data}
}

func (c *ConnectionMetricsContext) GetMetrics(listenerName string) ConnectionMetrics {
	return c.data[listenerName]
}

func (c *ConnectionMetricsContext) MergeMetricsFromConnection(connection *ConnectionContext) {
	for name, metric := range c.data {
		metrics := connection.Metrics.GetMetrics(name)
		metric.MergeMetricsFromConnection(connection, metrics)
	}
}

type MetricsBuilder struct {
	prefix  string
	metrics map[metadata][]*agentv3.MeterData
	logs    map[metadata][]*logv3.LogData
	events  []*agentv3.SpanAttachedEvent
}

func NewMetricsBuilder(prefix string) *MetricsBuilder {
	return &MetricsBuilder{
		prefix:  prefix,
		metrics: make(map[metadata][]*agentv3.MeterData),
		logs:    make(map[metadata][]*logv3.LogData),
	}
}

func (m *MetricsBuilder) AppendMetrics(service, instance string, metrics []*agentv3.MeterData) {
	meta := metadata{Layer: "", ServiceName: service, InstanceName: instance}
	existingMetrics := m.metrics[meta]
	if len(existingMetrics) == 0 {
		m.metrics[meta] = metrics
		return
	}
	m.metrics[meta] = append(existingMetrics, metrics...)
}

func (m *MetricsBuilder) AppendLogs(service string, log *logv3.LogData) {
	meta := metadata{ServiceName: service}
	m.logs[meta] = append(m.logs[meta], log)
}

func (m *MetricsBuilder) AppendSpanAttachedEvents(events []*agentv3.SpanAttachedEvent) {
	m.events = append(m.events, events...)
}

func (m *MetricsBuilder) MetricPrefix() string {
	return m.prefix
}

func (m *MetricsBuilder) BuildBasicMeterLabels(traffic *ProcessTraffic, local api.ProcessInterface) (ConnectionRole, []*agentv3.Label) {
	curRole := traffic.Role
	// add the default role
	if curRole == ConnectionRoleUnknown {
		curRole = ConnectionRoleClient
	}
	labels := make([]*agentv3.Label, 0)

	// two pair process/address info
	labels = m.appendMeterValue(labels, fmt.Sprintf("%s_process_id", curRole.String()), local.ID())
	labels = m.appendRemoteAddressInfo(labels, traffic, curRole.Revert().String(), local)

	labels = m.appendMeterValue(labels, "side", curRole.String())

	// protocol and ssl
	labels = m.appendMeterValue(labels, "protocol", traffic.Protocol.String())
	labels = m.appendMeterValue(labels, "is_ssl", fmt.Sprintf("%t", traffic.IsSSL))
	return curRole, labels
}

func (m *MetricsBuilder) BuildMetrics() []*agentv3.MeterDataCollection {
	collections := make([]*agentv3.MeterDataCollection, 0)
	now := time.Now().UnixMilli()
	for meta, meters := range m.metrics {
		if len(meters) == 0 {
			continue
		}
		meters[0].Service = meta.ServiceName
		meters[0].ServiceInstance = meta.InstanceName
		meters[0].Timestamp = now
		collections = append(collections, &agentv3.MeterDataCollection{MeterData: meters})
	}
	return collections
}

func (m *MetricsBuilder) BuildLogs() [][]*logv3.LogData {
	result := make([][]*logv3.LogData, 0)
	now := time.Now().UnixMilli()
	for meta, logs := range m.logs {
		if len(logs) == 0 {
			continue
		}
		logs[0].Service = meta.ServiceName
		// update the timestamp
		for _, l := range logs {
			l.Timestamp = now
		}
		result = append(result, logs)
	}
	return result
}

func (m *MetricsBuilder) BuildEvents() []*agentv3.SpanAttachedEvent {
	return m.events
}

type metadata struct {
	Layer        string
	ServiceName  string
	InstanceName string
}

func (m *MetricsBuilder) appendRemoteAddressInfo(labels []*agentv3.Label, traffic *ProcessTraffic, prefix string,
	local api.ProcessInterface) []*agentv3.Label {
	if len(traffic.RemoteProcesses) != 0 {
		for _, p := range traffic.RemoteProcesses {
			// only match with same service instance
			if local.Entity().ServiceName == p.Entity().ServiceName &&
				local.Entity().InstanceName == p.Entity().InstanceName {
				return m.appendMeterValue(labels, prefix+"_process_id", p.ID())
			}
		}
	}

	if tools.IsLocalHostAddress(traffic.RemoteIP) || traffic.Analyzer.IsLocalAddressInCache(traffic.RemoteIP) {
		return m.appendMeterValue(labels, prefix+"_local", "true")
	}

	return m.appendMeterValue(labels, prefix+"_address", fmt.Sprintf("%s:%d", traffic.RemoteIP, traffic.RemotePort))
}

func (m *MetricsBuilder) appendMeterValue(labels []*agentv3.Label, name, value string) []*agentv3.Label {
	return append(labels, &agentv3.Label{
		Name:  name,
		Value: value,
	})
}
