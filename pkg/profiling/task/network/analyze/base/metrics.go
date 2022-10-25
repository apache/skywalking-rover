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

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

// ConnectionMetrics The Metrics in each listener
type ConnectionMetrics interface {
	// MergeMetricsFromConnection merge the metrics from connection, and added into self
	MergeMetricsFromConnection(connection *ConnectionContext)
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
	for _, metric := range c.data {
		metric.MergeMetricsFromConnection(connection)
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

func (m *MetricsBuilder) BuildBasicMeterLabels(traffic *ProcessTraffic, local api.ProcessInterface) (ConnectionRole, []*v3.Label) {
	curRole := traffic.Role
	// add the default role
	if curRole == ConnectionRoleUnknown {
		curRole = ConnectionRoleClient
	}
	labels := make([]*v3.Label, 0)

	// two pair process/address info
	labels = m.appendMeterValue(labels, fmt.Sprintf("%s_process_id", curRole.String()), local.ID())
	labels = m.appendRemoteAddressInfo(labels, traffic, curRole.Revert().String(), local)

	labels = m.appendMeterValue(labels, "side", curRole.String())

	// protocol and ssl
	labels = m.appendMeterValue(labels, "protocol", traffic.Protocol.String())
	labels = m.appendMeterValue(labels, "is_ssl", fmt.Sprintf("%t", traffic.IsSSL))
	return curRole, labels
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

func (m *MetricsBuilder) appendRemoteAddressInfo(labels []*v3.Label, traffic *ProcessTraffic, prefix string, local api.ProcessInterface) []*v3.Label {
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

func (m *MetricsBuilder) appendMeterValue(labels []*v3.Label, name, value string) []*v3.Label {
	return append(labels, &v3.Label{
		Name:  name,
		Value: value,
	})
}
