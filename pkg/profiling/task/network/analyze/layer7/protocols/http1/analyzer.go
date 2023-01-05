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

package http1

import (
	"container/list"
	"encoding/json"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/logger"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	protocol "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"

	"github.com/sirupsen/logrus"
)

var log = logger.GetLogger("profiling", "task", "network", "layer7", "protocols", "http1")

var PackageSizeHistogramBuckets = []float64{
	// 0.25KB, 0.5KB, 1KB, 1.5KB, 2KB, 3KB, 5KB, 8KB, 10KB, 15KB, 20KB, 35KB, 50KB, 75KB, 100KB, 200KB, 500KB
	256, 512, 1048, 1536, 2048, 3072, 5120, 8192, 10240, 15360, 20480, 35840, 51200, 76800, 102400, 204800, 512000,
	// 800KB, 1M, 1.5M, 2M, 5M, 10M, 20M, 50M
	819200, 1048576, 1572864, 2097152, 5242880, 10485760, 20971520, 52428800,
}

var DurationHistogramBuckets = []float64{
	// unit ms
	1, 2, 5, 10, 15, 20, 25, 30, 40, 45, 50, 60, 65, 70, 80, 90, 100, 110, 130, 150, 170, 200, 230, 260, 290,
	330, 380, 430, 480, 500, 600, 700, 800, 900, 1000, 1100, 1300, 1500, 1800, 2000, 5000, 10000, 15000, 20000, 30000,
}

type Analyzer struct {
	// cache connection metrics if the connect event not receive or process
	cache map[string]*ConnectionMetrics

	sampleConfig *SamplingConfig
}

type ConnectionMetrics struct {
	// halfData all data event(request/response) not finished
	halfData *list.List

	clientMetrics *URIMetrics
	serverMetrics *URIMetrics
	metricsLocker sync.RWMutex
}

func NewHTTP1Analyzer() protocol.Protocol {
	return &Analyzer{
		cache: make(map[string]*ConnectionMetrics),
	}
}

func (h *Analyzer) Protocol() base.ConnectionProtocol {
	return base.ConnectionProtocolHTTP
}

func (h *Analyzer) GenerateMetrics() protocol.Metrics {
	return &ConnectionMetrics{
		halfData: list.New(),

		clientMetrics: NewHTTP1URIMetrics(),
		serverMetrics: NewHTTP1URIMetrics(),
	}
}

func (h *Analyzer) Init(config *profiling.TaskConfig) {
	h.sampleConfig = NewSamplingConfig(config)
}

func (h *Analyzer) ParseProtocol(connectionID uint64, metrics protocol.Metrics, buf *protocol.Buffer) protocol.ParseResult {
	connectionMetrics := metrics.(*ConnectionMetrics)
	messageType, err := reader.IdentityMessageType(buf)
	if err != nil {
		return protocol.ParseResultSkipPackage
	}

	var result protocol.ParseResult
	switch messageType {
	case reader.MessageTypeRequest:
		result, err = h.handleRequest(connectionMetrics, buf)
	case reader.MessageTypeResponse:
		result, err = h.handleResponse(connectionID, connectionMetrics, buf)
	case reader.MessageTypeUnknown:
		return protocol.ParseResultSkipPackage
	}

	if err != nil {
		log.Warnf("reading %v error: %v", messageType, err)
		return protocol.ParseResultSkipPackage
	} else if result != protocol.ParseResultSuccess {
		return result
	}
	return protocol.ParseResultSuccess
}

func (h *Analyzer) handleRequest(metrics *ConnectionMetrics, buf *protocol.Buffer) (protocol.ParseResult, error) {
	// parsing request
	req, r, err := reader.ReadRequest(buf)
	if err != nil {
		return protocol.ParseResultSkipPackage, err
	}
	if r != protocol.ParseResultSuccess {
		return r, nil
	}

	metrics.AppendRequestToList(req)
	return protocol.ParseResultSuccess, nil
}

func (h *Analyzer) handleResponse(connectionID uint64, metrics *ConnectionMetrics, buf *protocol.Buffer) (protocol.ParseResult, error) {
	// find the first request
	firstElement := metrics.halfData.Front()
	if firstElement == nil {
		return protocol.ParseResultSkipPackage, nil
	}
	request := metrics.halfData.Remove(firstElement).(*reader.Request)

	// parsing request
	response, r, err := reader.ReadResponse(request, buf)
	if err != nil {
		return protocol.ParseResultSkipPackage, err
	} else if r != protocol.ParseResultSuccess {
		return r, nil
	}

	// lock append metrics with read locker
	metrics.metricsLocker.RLock()
	defer metrics.metricsLocker.RUnlock()

	// append metrics
	data := metrics.clientMetrics
	side := base.ConnectionRoleClient
	if request.Direction() == base.SocketDataDirectionIngress {
		// if receive the request, that's mean is server side
		data = metrics.serverMetrics
		side = base.ConnectionRoleServer
	}
	data.Append(h.sampleConfig, request, response)

	if log.Enable(logrus.DebugLevel) {
		metricsJSON, _ := json.Marshal(data)
		log.Debugf("generated metrics, connection id: %d, side: %s, metrisc: %s", connectionID, side.String(), string(metricsJSON))
	}
	return protocol.ParseResultSuccess, nil
}

func (h *Analyzer) UpdateExtensionConfig(config *profiling.ExtensionConfig) {
	if config == nil {
		return
	}
	h.sampleConfig.UpdateRules(config.NetworkSamplings)
}

func (h *Analyzer) PackageMaxExpireDuration() time.Duration {
	return time.Minute
}

func (m *ConnectionMetrics) AppendRequestToList(req *reader.Request) {
	if m.halfData.Len() == 0 {
		m.halfData.PushFront(req)
		return
	}
	if m.halfData.Back().Value.(*reader.Request).MinDataID() < req.MinDataID() {
		m.halfData.PushBack(req)
		return
	}
	beenAdded := false
	for element := m.halfData.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(*reader.Request)
		if existEvent.MinDataID() > req.MinDataID() {
			m.halfData.InsertBefore(req, element)
			beenAdded = true
			break
		}
	}
	if !beenAdded {
		m.halfData.PushBack(req)
	}
}

func (m *ConnectionMetrics) MergeMetricsFromConnection(connection *base.ConnectionContext, data base.ConnectionMetrics) {
	other := data.(*ConnectionMetrics)
	other.metricsLocker.Lock()
	defer other.metricsLocker.Unlock()

	if other.halfData != nil {
		for element := other.halfData.Front(); element != nil; element = element.Next() {
			m.AppendRequestToList(element.Value.(*reader.Request))
		}
	}

	m.clientMetrics.MergeAndClean(other.clientMetrics)
	m.serverMetrics.MergeAndClean(other.serverMetrics)
	if log.Enable(logrus.DebugLevel) {
		clientMetrics, _ := json.Marshal(m.clientMetrics)
		serverMetrics, _ := json.Marshal(m.serverMetrics)
		log.Debugf("combine metrics: conid: %d_%d, client side metrics: %s, server side metrics: %s",
			connection.ConnectionID, connection.RandomID, clientMetrics, serverMetrics)
	}
}

func (m *ConnectionMetrics) FlushMetrics(traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	for _, p := range traffic.LocalProcesses {
		// if the remote process is profiling, then used the client side
		localMetrics := m.clientMetrics
		remoteMetrics := m.serverMetrics
		if traffic.Role == base.ConnectionRoleServer {
			localMetrics = m.serverMetrics
			remoteMetrics = m.clientMetrics
		}

		metricsCount := localMetrics.appendMetrics(traffic, p, "", metricsBuilder, false)
		if traffic.RemoteProcessIsProfiling() {
			metricsCount += remoteMetrics.appendMetrics(traffic, p, "", metricsBuilder, true)
		}
		if metricsCount <= 0 {
			continue
		}

		if log.Enable(logrus.DebugLevel) {
			// if remote process is profiling, then the metrics data need to be cut half
			log.Debugf("flush HTTP1 metrics(%s): %s, remote process is profiling: %t, client(%s), server(%s)",
				traffic.Role.String(), traffic.GenerateConnectionInfo(), traffic.RemoteProcessIsProfiling(),
				m.clientMetrics.String(), m.serverMetrics.String())
		}
	}
}
