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
	"bufio"
	"bytes"
	"container/list"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"

	"github.com/apache/skywalking-rover/pkg/logger"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	protocol "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"

	"github.com/sirupsen/logrus"
)

var log = logger.GetLogger("profiling", "task", "network", "layer7", "protocols", "http1")

var ProtocolName = "http1"

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

func (h *Analyzer) Name() string {
	return ProtocolName
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

func (h *Analyzer) ReceiveData(context protocol.Context, event *protocol.SocketDataUploadEvent) bool {
	// only handle the HTTP1 protocol
	if event.Protocol != base.ConnectionProtocolHTTP {
		return false
	}

	connectionID := event.GenerateConnectionID()
	fromAnalyzerCache := false
	var connectionMetrics *ConnectionMetrics
	connection := context.QueryConnection(event.ConnectionID, event.RandomID)
	// if connection not exists, then cached it into the analyzer context
	if connection == nil {
		connectionMetrics = h.cache[connectionID]
		fromAnalyzerCache = true
		if connectionMetrics == nil {
			connectionMetrics = h.GenerateMetrics().(*ConnectionMetrics)
			h.cache[connectionID] = connectionMetrics
		}
	} else {
		connectionMetrics = context.QueryProtocolMetrics(connection.Metrics, ProtocolName).(*ConnectionMetrics)
	}

	log.Debugf("receive connection: %s, dataid: %d, sequence: %d, finished: %d, message type: %s, direction: %s, size: %d, total size: %d",
		connectionID, event.DataID, event.Sequence, event.Finished, event.MsgType.String(), event.Direction().String(), event.DataLen, event.TotalSize0)
	// if the cache is existing in the analyzer context, then delete it
	if !fromAnalyzerCache {
		if tmp := h.cache[connectionID]; tmp != nil {
			connectionMetrics.MergeFrom(h, tmp)
			delete(h.cache, connectionID)
		}
	}

	req, resp := h.buildHTTP1(connectionMetrics.halfData, event)
	if req != nil && resp != nil {
		if err := h.analyze(context, connectionID, connectionMetrics, req, resp); err != nil {
			log.Errorf("HTTP1 analyze failure: %v", err)
			return false
		}
	} else {
		log.Debugf("connnection: %s, remaining half data list size: %d", connectionID, connectionMetrics.halfData.Len())
	}
	return true
}

func (h *Analyzer) UpdateExtensionConfig(config *profiling.ExtensionConfig) {
	if config == nil {
		return
	}
	h.sampleConfig.UpdateRules(config.NetworkSamplings)
}

func (h *Analyzer) combineAndRemoveEvent(halfConnections *list.List, firstElement *list.Element,
	lastAppender protocol.SocketDataBuffer) protocol.SocketDataBuffer {
	firstEvent := firstElement.Value.(*protocol.SocketDataUploadEvent)
	if firstEvent.Sequence == 0 && firstEvent.Finished == 1 {
		halfConnections.Remove(firstElement)
		return h.combineEventIfNeed(firstEvent, lastAppender)
	}
	next := firstElement.Next()
	halfConnections.Remove(firstElement)
	var buffer protocol.SocketDataBuffer = firstEvent
	// for-each the events until buffer finished
	for next != nil {
		event := next.Value.(*protocol.SocketDataUploadEvent)

		buffer = buffer.Combine(event)

		tmp := next.Next()
		halfConnections.Remove(next)
		next = tmp
		// combine event
		if event.Finished == 1 {
			return h.combineEventIfNeed(buffer, lastAppender)
		}
	}
	return h.combineEventIfNeed(buffer, lastAppender)
}

func (h *Analyzer) combineEventIfNeed(data, appender protocol.SocketDataBuffer) protocol.SocketDataBuffer {
	if appender != nil {
		return data.Combine(appender)
	}
	return data
}

func (h *Analyzer) buildHTTP1(halfConnections *list.List, event *protocol.SocketDataUploadEvent) (request, response protocol.SocketDataBuffer) {
	// no connections, then just add the response to the half connections to wait the request
	if halfConnections.Len() == 0 {
		halfConnections.PushBack(event)
		return nil, nil
	}

	// quick handler(only one element, and is request)
	if halfConnections.Len() == 1 {
		firstElement := halfConnections.Front()
		firstEvent := firstElement.Value.(*protocol.SocketDataUploadEvent)
		if firstEvent.IsStart() && firstEvent.Finished == 1 && event.IsStart() && event.Finished == 1 &&
			firstEvent.DataID+1 == event.DataID && firstEvent.MsgType == base.SocketMessageTypeRequest &&
			event.MsgType == base.SocketMessageTypeResponse {
			return h.combineAndRemoveEvent(halfConnections, firstElement, nil), event
		}
	}

	// push to the queue
	h.insertToList(halfConnections, event)

	// trying to find completed request and response
	return NewHTTP1BufferAnalyzer(h).Analyze(halfConnections)
}

func (h *Analyzer) insertToList(halfConnections *list.List, event *protocol.SocketDataUploadEvent) {
	if halfConnections.Len() == 0 {
		halfConnections.PushFront(event)
		return
	}
	if halfConnections.Back().Value.(*protocol.SocketDataUploadEvent).DataID < event.DataID {
		halfConnections.PushBack(event)
		return
	}
	beenAdded := false
	for element := halfConnections.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(*protocol.SocketDataUploadEvent)
		if existEvent.DataID > event.DataID {
			// data id needs order
			beenAdded = true
		} else if existEvent.DataID == event.DataID {
			if existEvent.MsgType == event.MsgType && existEvent.Sequence > event.Sequence {
				// same message type and following the sequence order
				beenAdded = true
			} else if existEvent.MsgType > event.MsgType {
				// request needs before response
				beenAdded = true
			}
		}
		if beenAdded {
			halfConnections.InsertBefore(event, element)
			break
		}
	}
	if !beenAdded {
		halfConnections.PushBack(event)
	}
}

func (h *Analyzer) analyze(_ protocol.Context, connectionID string, connectionMetrics *ConnectionMetrics,
	requestBuffer, responseBuffer protocol.SocketDataBuffer) error {
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(requestBuffer.BufferData())))
	if err != nil {
		return fmt.Errorf("parse request failure: data length: %d, total data length: %d, %v",
			len(requestBuffer.BufferData()), requestBuffer.TotalSize(), err)
	}

	response, err := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(responseBuffer.BufferData())), request)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			response, err = h.tryingToReadResponseWithoutHeaders(bufio.NewReader(bytes.NewBuffer(responseBuffer.BufferData())), request)
			if err != nil {
				return fmt.Errorf("parsing simple data error: %v", err)
			}
			if response != nil && response.Body != nil {
				defer response.Body.Close()
			}
		}
		if err != nil {
			return fmt.Errorf("parse response failure, data length: %d, total data length: %d, %v",
				len(requestBuffer.BufferData()), requestBuffer.TotalSize(), err)
		}
	}

	// lock append metrics with read locker
	connectionMetrics.metricsLocker.RLock()
	defer connectionMetrics.metricsLocker.RUnlock()

	// append metrics
	data := connectionMetrics.clientMetrics
	side := base.ConnectionRoleClient
	if requestBuffer.Direction() == base.SocketDataDirectionIngress {
		// if receive the request, that's mean is server side
		data = connectionMetrics.serverMetrics
		side = base.ConnectionRoleServer
	}
	data.Append(h.sampleConfig, request, requestBuffer, response, responseBuffer)

	if log.Enable(logrus.DebugLevel) {
		metricsJSON, _ := json.Marshal(data)
		log.Debugf("generated metrics, connection id: %s, side: %s, metrisc: %s", connectionID, side.String(), string(metricsJSON))
	}
	return nil
}

func (h *Analyzer) tryingToReadResponseWithoutHeaders(reader *bufio.Reader, request *http.Request) (*http.Response, error) {
	if reader.Size() < 16 {
		return nil, fmt.Errorf("the header length not enough")
	}
	tp := textproto.NewReader(reader)
	resp := &http.Response{
		Request: request,
	}

	line, err := tp.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("read response first line failure: %v", err)
	}
	indexByte := strings.IndexByte(line, ' ')
	if indexByte == -1 {
		return nil, fmt.Errorf("parsing response error: %s", line)
	}
	resp.Proto = line[:indexByte]
	resp.Status = strings.TrimLeft(line[indexByte+1:], " ")
	statusCode := resp.Status
	if i := strings.IndexByte(resp.Status, ' '); i != -1 {
		statusCode = resp.Status[:i]
	}
	if len(statusCode) != 3 {
		return nil, fmt.Errorf("parsing response status code failure: %v", statusCode)
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil || resp.StatusCode < 0 {
		return nil, fmt.Errorf("status code not correct: %s", statusCode)
	}
	var ok bool
	if resp.ProtoMajor, resp.ProtoMinor, ok = http.ParseHTTPVersion(resp.Proto); !ok {
		return nil, fmt.Errorf("parsing http version failure: %s", resp.Proto)
	}

	return resp, nil
}

func (h *ConnectionMetrics) MergeMetricsFromConnection(connection *base.ConnectionContext, data base.ConnectionMetrics) {
	other := data.(*ConnectionMetrics)
	other.metricsLocker.Lock()
	defer other.metricsLocker.Unlock()

	h.clientMetrics.MergeAndClean(other.clientMetrics)
	h.serverMetrics.MergeAndClean(other.serverMetrics)
	if log.Enable(logrus.DebugLevel) {
		clientMetrics, _ := json.Marshal(h.clientMetrics)
		serverMetrics, _ := json.Marshal(h.serverMetrics)
		log.Debugf("combine metrics: conid: %d_%d, client side metrics: %s, server side metrics: %s",
			connection.ConnectionID, connection.RandomID, clientMetrics, serverMetrics)
	}
}

func (h *ConnectionMetrics) FlushMetrics(traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	for _, p := range traffic.LocalProcesses {
		// if the remote process is profiling, then used the client side
		localMetrics := h.clientMetrics
		remoteMetrics := h.serverMetrics
		if traffic.Role == base.ConnectionRoleServer {
			localMetrics = h.serverMetrics
			remoteMetrics = h.clientMetrics
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
				h.clientMetrics.String(), h.serverMetrics.String())
		}
	}
}

func (h *ConnectionMetrics) MergeFrom(analyzer *Analyzer, other *ConnectionMetrics) {
	if other.halfData != nil {
		for element := other.halfData.Front(); element != nil; element = element.Next() {
			analyzer.insertToList(h.halfData, element.Value.(*protocol.SocketDataUploadEvent))
		}
	}
}
