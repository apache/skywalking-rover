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

package protocols

import (
	"bufio"
	"bytes"
	"container/list"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/metrics"
)

var HTTP1ProtocolName = "http1"

var HTTP1PackageSizeHistogramBuckets = []float64{
	// 0.25KB, 0.5KB, 1KB, 1.5KB, 2KB, 3KB, 5KB, 8KB, 10KB, 15KB, 20KB, 35KB, 50KB, 75KB, 100KB, 200KB, 500KB
	256, 512, 1048, 1536, 2048, 3072, 5120, 8192, 10240, 15360, 20480, 35840, 51200, 76800, 102400, 204800, 512000,
	// 800KB, 1M, 1.5M, 2M, 5M, 10M, 20M, 50M
	819200, 1048576, 1572864, 2097152, 5242880, 10485760, 20971520, 52428800,
}

var HTTP1DurationHistogramBuckets = []float64{
	// unit ms
	1, 2, 5, 10, 15, 20, 25, 30, 40, 45, 50, 60, 65, 70, 80, 90, 100, 110, 130, 150, 170, 200, 230, 260, 290,
	330, 380, 430, 480, 500, 600, 700, 800, 900, 1000, 1100, 1300, 1500, 1800, 2000, 5000, 10000, 15000, 20000, 30000,
}

type HTTP1Analyzer struct {
	// cache connection metrics if the connect event not receive or process
	cache map[string]*HTTP1ConnectionMetrics
}

type HTTP1ConnectionMetrics struct {
	// halfData all data event(request/response) not finished
	halfData *list.List

	combinedMetrics *HTTP1URIMetrics
	metricsLocker   sync.RWMutex
}

type HTTP1URIMetrics struct {
	requestCounter *metrics.Counter
	statusCounter  map[int]*metrics.Counter

	avgRequestPackageSize    *metrics.AvgCounter
	avgResponsePackageSize   *metrics.AvgCounter
	reqPackageSizeHistogram  *metrics.Histogram
	respPackageSizeHistogram *metrics.Histogram

	clientAvgDuration       *metrics.AvgCounter
	serverAvgDuration       *metrics.AvgCounter
	clientDurationHistogram *metrics.Histogram
	serverDurationHistogram *metrics.Histogram
}

func NewHTTP1URIMetrics() *HTTP1URIMetrics {
	return &HTTP1URIMetrics{
		requestCounter:           metrics.NewCounter(),
		statusCounter:            make(map[int]*metrics.Counter),
		avgRequestPackageSize:    metrics.NewAvgCounter(),
		avgResponsePackageSize:   metrics.NewAvgCounter(),
		reqPackageSizeHistogram:  metrics.NewHistogram(HTTP1PackageSizeHistogramBuckets),
		respPackageSizeHistogram: metrics.NewHistogram(HTTP1PackageSizeHistogramBuckets),
		clientAvgDuration:        metrics.NewAvgCounter(),
		serverAvgDuration:        metrics.NewAvgCounter(),
		clientDurationHistogram:  metrics.NewHistogram(HTTP1DurationHistogramBuckets),
		serverDurationHistogram:  metrics.NewHistogram(HTTP1DurationHistogramBuckets),
	}
}

func NewHTTP1Analyzer() Protocol {
	return &HTTP1Analyzer{
		cache: make(map[string]*HTTP1ConnectionMetrics),
	}
}

func (h *HTTP1Analyzer) Name() string {
	return HTTP1ProtocolName
}

func (h *HTTP1Analyzer) GenerateMetrics() Metrics {
	return &HTTP1ConnectionMetrics{
		halfData: list.New(),

		combinedMetrics: NewHTTP1URIMetrics(),
	}
}

func (h *HTTP1Analyzer) ReceiveData(context Context, event *SocketDataUploadEvent) bool {
	// only handle the HTTP1 protocol
	if event.Protocol != base.ConnectionProtocolHTTP {
		return false
	}

	connectionID := event.GenerateConnectionID()
	fromAnalyzerCache := false
	var connectionMetrics *HTTP1ConnectionMetrics
	connection := context.QueryConnection(event.ConnectionID, event.RandomID)
	// if connection not exists, then cached it into the analyzer context
	if connection == nil {
		connectionMetrics = h.cache[connectionID]
		fromAnalyzerCache = true
		if connectionMetrics == nil {
			connectionMetrics = h.GenerateMetrics().(*HTTP1ConnectionMetrics)
			h.cache[connectionID] = connectionMetrics
		}
	} else {
		connectionMetrics = QueryProtocolMetrics(connection.Metrics, HTTP1ProtocolName).(*HTTP1ConnectionMetrics)
	}

	log.Debugf("receive connection: %s, dataid: %d, sequence: %d, finished: %d, message type: %s, direction: %s",
		connectionID, event.DataID, event.Sequence, event.Finished, event.MsgType.String(), event.Direction().String())
	// if the cache is existing in the analyzer context, then delete it
	if !fromAnalyzerCache {
		if tmp := h.cache[connectionID]; tmp != nil {
			connectionMetrics.MergeFrom(h, tmp)
			delete(h.cache, connectionID)
		}
	}

	req, resp := h.buildHTTP1(connectionMetrics.halfData, event)
	if req != nil && resp != nil {
		if err := h.analyze(context, connectionMetrics, req, resp); err != nil {
			log.Errorf("HTTP1 analyze failure: %v", err)
			return false
		}
	} else {
		log.Debugf("connnection: %s, remaining half data list size: %d", connectionID, connectionMetrics.halfData.Len())
	}
	return true
}

func (h *HTTP1Analyzer) combineAndRemoveEvent(halfConnections *list.List, firstElement *list.Element,
	lastAppender SocketDataBuffer) SocketDataBuffer {
	firstEvent := firstElement.Value.(*SocketDataUploadEvent)
	if firstEvent.Sequence == 0 && firstEvent.Finished == 1 {
		halfConnections.Remove(firstElement)
		return h.combineEventIfNeed(firstEvent, lastAppender)
	}
	next := firstElement.Next()
	halfConnections.Remove(firstElement)
	var buffer SocketDataBuffer = firstEvent
	// for-each the events until buffer finished
	for next != nil {
		event := next.Value.(*SocketDataUploadEvent)

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

func (h *HTTP1Analyzer) combineEventIfNeed(data, appender SocketDataBuffer) SocketDataBuffer {
	if appender != nil {
		return data.Combine(appender)
	}
	return data
}

func (h *HTTP1Analyzer) buildHTTP1(halfConnections *list.List, event *SocketDataUploadEvent) (request, response SocketDataBuffer) {
	// no connections, then just add the response to the half connections to wait the request
	if halfConnections.Len() == 0 {
		halfConnections.PushBack(event)
		return nil, nil
	}

	// quick handler(only one element, and is request)
	if halfConnections.Len() == 1 {
		firstElement := halfConnections.Front()
		firstEvent := firstElement.Value.(*SocketDataUploadEvent)
		if firstEvent.IsStart() && firstEvent.IsFinished() && event.IsStart() && event.IsFinished() &&
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

func (h *HTTP1Analyzer) insertToList(halfConnections *list.List, event *SocketDataUploadEvent) {
	if halfConnections.Len() == 0 {
		halfConnections.PushFront(event)
		return
	}
	if halfConnections.Back().Value.(*SocketDataUploadEvent).DataID < event.DataID {
		halfConnections.PushBack(event)
		return
	}
	beenAdded := false
	for element := halfConnections.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(*SocketDataUploadEvent)
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

func (h *HTTP1Analyzer) analyze(_ Context, connectionMetrics *HTTP1ConnectionMetrics, requestBuffer, responseBuffer SocketDataBuffer) error {
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(requestBuffer.BufferData())))
	if err != nil {
		return fmt.Errorf("parse request failure: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(responseBuffer.BufferData())), request)
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			log.Warnf("parsing err is unexcepted EOF")
			response, err = h.tryingToReadResponseWithoutHeaders(bufio.NewReader(bytes.NewBuffer(responseBuffer.BufferData())), request)
			if err != nil {
				log.Warnf("parsing simple data error: %v", err)
			}
		}
		if err != nil {
			return fmt.Errorf("parse response failure: %v, original data: %s", err, string(responseBuffer.BufferData()))
		}
	}

	// lock append metrics with read locker
	connectionMetrics.metricsLocker.RLock()
	defer connectionMetrics.metricsLocker.RUnlock()

	// append metrics
	h.appendToMetrics(connectionMetrics.combinedMetrics, request, requestBuffer, response, responseBuffer)

	return nil
}

func (h *HTTP1Analyzer) tryingToReadResponseWithoutHeaders(reader *bufio.Reader, request *http.Request) (*http.Response, error) {
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
	if i := strings.IndexByte(line, ' '); i == -1 {
		return nil, fmt.Errorf("parsing response error: %s", line)
	} else {
		resp.Proto = line[:i]
		resp.Status = strings.TrimLeft(line[i+1:], " ")
	}
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

func (h *HTTP1Analyzer) appendToMetrics(data *HTTP1URIMetrics, _ *http.Request, reqBuffer SocketDataBuffer,
	resp *http.Response, respBuffer SocketDataBuffer) {
	data.requestCounter.Increase()
	statusCounter := data.statusCounter[resp.StatusCode]
	if statusCounter == nil {
		statusCounter = metrics.NewCounter()
		data.statusCounter[resp.StatusCode] = statusCounter
	}
	statusCounter.Increase()

	data.avgRequestPackageSize.Increase(float64(reqBuffer.TotalSize()))
	data.avgResponsePackageSize.Increase(float64(respBuffer.TotalSize()))
	data.reqPackageSizeHistogram.Increase(float64(reqBuffer.TotalSize()))
	data.respPackageSizeHistogram.Increase(float64(respBuffer.TotalSize()))

	// duration data need client and server side
	avgDuration := data.clientAvgDuration
	durationHistogram := data.clientDurationHistogram
	if reqBuffer.Direction() == base.SocketDataDirectionIngress {
		// if the request is ingress, that's mean current is server side
		avgDuration = data.serverAvgDuration
		durationHistogram = data.serverDurationHistogram
	}
	duration := time.Duration(respBuffer.Time() - reqBuffer.Time())
	durationInMS := float64(duration.Milliseconds())
	avgDuration.Increase(durationInMS)
	durationHistogram.Increase(durationInMS)
}

func (h *HTTP1ConnectionMetrics) MergeMetricsFromConnection(connection *base.ConnectionContext) {
	other := QueryProtocolMetrics(connection.Metrics, HTTP1ProtocolName).(*HTTP1ConnectionMetrics)
	other.metricsLocker.Lock()
	defer other.metricsLocker.Unlock()

	h.combinedMetrics.MergeAndClean(other.combinedMetrics)
}

func (h *HTTP1ConnectionMetrics) FlushMetrics(traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	connectionMetrics := QueryProtocolMetrics(traffic.Metrics, HTTP1ProtocolName).(*HTTP1ConnectionMetrics)
	for _, p := range traffic.LocalProcesses {
		collection := make([]*v3.MeterData, 0)
		combinedMetrics := connectionMetrics.combinedMetrics
		collection = h.appendMetrics(collection, traffic, p, "", combinedMetrics, metricsBuilder)
		if len(collection) == 0 {
			continue
		}

		if log.Enable(logrus.DebugLevel) {
			// if remote process is profiling, then the metrics data need to be cut half
			log.Debugf("flush HTTP1 metrics(%s): %s, remote process is profiling: %t, "+
				"client request count: %d, avg request size: %f, "+
				"avg response size: %f, client avg duration: %f, server avg duration: %f",
				traffic.Role.String(), traffic.GenerateConnectionInfo(), traffic.RemoteProcessIsProfiling(),
				combinedMetrics.requestCounter.Get(), combinedMetrics.avgRequestPackageSize.Calculate(),
				combinedMetrics.avgResponsePackageSize.Calculate(),
				combinedMetrics.clientAvgDuration.Calculate(), combinedMetrics.serverAvgDuration.Calculate())
		}

		metricsBuilder.AppendMetrics(p.Entity().ServiceName, p.Entity().InstanceName, collection)
	}
}

func (h *HTTP1ConnectionMetrics) appendMetrics(collections []*v3.MeterData, traffic *base.ProcessTraffic,
	local api.ProcessInterface, url string, http1Metrics *HTTP1URIMetrics, metricsBuilder *base.MetricsBuilder) []*v3.MeterData {
	role, labels := metricsBuilder.BuildBasicMeterLabels(traffic, local)
	prefix := metricsBuilder.MetricPrefix()

	collections = h.buildMetrics(collections, prefix, "request_counter", labels, url, traffic,
		h.cutHalfMetricsIfNeed(traffic, http1Metrics.requestCounter))
	for status, counter := range http1Metrics.statusCounter {
		statusLabels := append(labels, &v3.Label{Name: "code", Value: fmt.Sprintf("%d", status)})
		collections = h.buildMetrics(collections, prefix, "response_status_counter", statusLabels, url, traffic,
			h.cutHalfMetricsIfNeed(traffic, counter))
	}

	collections = h.buildMetrics(collections, prefix, "request_package_size_avg", labels, url, traffic, http1Metrics.avgRequestPackageSize)
	collections = h.buildMetrics(collections, prefix, "response_package_size_avg", labels, url, traffic, http1Metrics.avgResponsePackageSize)
	collections = h.buildMetrics(collections, prefix, "request_package_size_histogram", labels, url, traffic,
		h.cutHalfMetricsIfNeed(traffic, http1Metrics.reqPackageSizeHistogram))
	collections = h.buildMetrics(collections, prefix, "response_package_size_histogram", labels, url, traffic,
		h.cutHalfMetricsIfNeed(traffic, http1Metrics.respPackageSizeHistogram))

	avgDuration := http1Metrics.clientAvgDuration
	durationHistogram := http1Metrics.clientDurationHistogram
	if role == base.ConnectionRoleServer {
		avgDuration = http1Metrics.serverAvgDuration
		durationHistogram = http1Metrics.serverDurationHistogram
	}
	collections = h.buildMetrics(collections, prefix, fmt.Sprintf("%s_duration_avg", role.String()), labels, url,
		traffic, avgDuration)
	collections = h.buildMetrics(collections, prefix, fmt.Sprintf("%s_duration_histogram", role.String()), labels, url,
		traffic, durationHistogram)
	return collections
}

func (h *HTTP1ConnectionMetrics) cutHalfMetricsIfNeed(traffic *base.ProcessTraffic, data metrics.Metrics) metrics.Metrics {
	if traffic.RemoteProcessIsProfiling() {
		return data.CusHalfOfMetrics()
	}
	return data
}

func (h *HTTP1ConnectionMetrics) buildMetrics(collection []*v3.MeterData, prefix, name string, basicLabels []*v3.Label,
	url string, traffic *base.ProcessTraffic, data metrics.Metrics) []*v3.MeterData {
	// if remote process is also profiling, then needs to be calculated half of metrics
	if traffic.RemoteProcessIsProfiling() {
		data = data.CusHalfOfMetrics()
	}
	labels := basicLabels
	var meterName string
	if url != "" {
		labels = append(labels, &v3.Label{Name: "url", Value: url})
		meterName = fmt.Sprintf("%shttp1_%s_%s", prefix, "url", name)
	} else {
		meterName = fmt.Sprintf("%shttp1_%s", prefix, name)
	}
	return data.AppendMeter(collection, meterName, labels)
}

func (h *HTTP1ConnectionMetrics) MergeFrom(analyzer *HTTP1Analyzer, other *HTTP1ConnectionMetrics) {
	if other.halfData != nil {
		for element := other.halfData.Front(); element != nil; element = element.Next() {
			analyzer.insertToList(h.halfData, element.Value.(*SocketDataUploadEvent))
		}
	}
}

func (u *HTTP1URIMetrics) MergeAndClean(other *HTTP1URIMetrics) {
	u.requestCounter.MergeAndClean(other.requestCounter)
	for k, v := range other.statusCounter {
		if existing := u.statusCounter[k]; existing != nil {
			existing.MergeAndClean(v)
		} else {
			u.statusCounter[k] = v
		}
	}

	u.avgRequestPackageSize.MergeAndClean(other.avgRequestPackageSize)
	u.avgResponsePackageSize.MergeAndClean(other.avgResponsePackageSize)
	u.reqPackageSizeHistogram.MergeAndClean(other.reqPackageSizeHistogram)
	u.respPackageSizeHistogram.MergeAndClean(other.respPackageSizeHistogram)
	u.clientAvgDuration.MergeAndClean(other.clientAvgDuration)
	u.serverAvgDuration.MergeAndClean(other.serverAvgDuration)
	u.clientDurationHistogram.MergeAndClean(other.clientDurationHistogram)
	u.serverDurationHistogram.MergeAndClean(other.serverDurationHistogram)
}
