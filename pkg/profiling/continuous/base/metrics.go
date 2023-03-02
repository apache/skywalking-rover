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
	"time"

	"github.com/apache/skywalking-rover/pkg/process/api"

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

type MetricsAppender struct {
	prefix    string
	timestamp int64
	meters    map[serviceInstanceMetadata][]*v3.MeterData // split by service instance
}

func NewMetricsAppender(prefix string) *MetricsAppender {
	return &MetricsAppender{
		prefix:    prefix,
		timestamp: time.Now().UnixMilli(),
		meters:    make(map[serviceInstanceMetadata][]*v3.MeterData),
	}
}

func (m *MetricsAppender) AppendProcessSingleValue(name string, p api.ProcessInterface, labels map[string]string, value float64) {
	transformLabels := make([]*v3.Label, 0)
	for k, v := range labels {
		transformLabels = append(transformLabels, &v3.Label{Name: k, Value: v})
	}
	transformLabels = append(transformLabels,
		&v3.Label{Name: "process_name", Value: p.Entity().ProcessName},
		&v3.Label{Name: "layer", Value: p.Entity().Layer})
	metadata := serviceInstanceMetadata{
		service:  p.Entity().ServiceName,
		instance: p.Entity().InstanceName,
	}
	m.meters[metadata] = append(m.meters[metadata], &v3.MeterData{
		Service:         p.Entity().ServiceName,
		ServiceInstance: p.Entity().InstanceName,
		Timestamp:       m.timestamp,
		Metric: &v3.MeterData_SingleValue{
			SingleValue: &v3.MeterSingleValue{
				Name:   m.formatName(name),
				Labels: transformLabels,
				Value:  value,
			},
		},
	})
}

func (m *MetricsAppender) Flush(ctx context.Context, client v3.MeterReportServiceClient) error {
	if len(m.meters) == 0 {
		return nil
	}

	batch, err := client.CollectBatch(ctx)
	if err != nil {
		return err
	}

	for _, meters := range m.meters {
		collection := &v3.MeterDataCollection{
			MeterData: meters,
		}
		if e := batch.Send(collection); e != nil {
			_ = m.closeSteam(batch)
			return e
		}
	}
	return m.closeSteam(batch)
}

func (m *MetricsAppender) closeSteam(batch v3.MeterReportService_CollectBatchClient) error {
	_, err := batch.CloseAndRecv()
	if err != nil {
		return err
	}
	return nil
}

type serviceInstanceMetadata struct {
	service  string
	instance string
}

func (m *MetricsAppender) formatName(name string) string {
	return m.prefix + "_" + name
}
