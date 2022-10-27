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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
	logv3 "skywalking.apache.org/repo/goapi/collect/logging/v3"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/metrics"
	"github.com/apache/skywalking-rover/pkg/tools"
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

var SlowTraceTopNSize = 10

type HTTP1Analyzer struct {
	// cache connection metrics if the connect event not receive or process
	cache map[string]*HTTP1ConnectionMetrics
}

type HTTP1ConnectionMetrics struct {
	// halfData all data event(request/response) not finished
	halfData *list.List

	clientMetrics *HTTP1URIMetrics
	serverMetrics *HTTP1URIMetrics
	metricsLocker sync.RWMutex
}

type HTTP1URIMetrics struct {
	RequestCounter *metrics.Counter
	StatusCounter  map[int]*metrics.Counter

	AvgRequestPackageSize    *metrics.AvgCounter
	AvgResponsePackageSize   *metrics.AvgCounter
	ReqPackageSizeHistogram  *metrics.Histogram
	RespPackageSizeHistogram *metrics.Histogram

	avgDuration       *metrics.AvgCounter
	durationHistogram *metrics.Histogram

	slowTraces *metrics.TopN
}

func NewHTTP1URIMetrics() *HTTP1URIMetrics {
	return &HTTP1URIMetrics{
		RequestCounter:           metrics.NewCounter(),
		StatusCounter:            make(map[int]*metrics.Counter),
		AvgRequestPackageSize:    metrics.NewAvgCounter(),
		AvgResponsePackageSize:   metrics.NewAvgCounter(),
		ReqPackageSizeHistogram:  metrics.NewHistogram(HTTP1PackageSizeHistogramBuckets),
		RespPackageSizeHistogram: metrics.NewHistogram(HTTP1PackageSizeHistogramBuckets),
		avgDuration:              metrics.NewAvgCounter(),
		durationHistogram:        metrics.NewHistogram(HTTP1DurationHistogramBuckets),
		slowTraces:               metrics.NewTopN(SlowTraceTopNSize),
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

		clientMetrics: NewHTTP1URIMetrics(),
		serverMetrics: NewHTTP1URIMetrics(),
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

func (h *HTTP1Analyzer) analyze(_ Context, connectionID string, connectionMetrics *HTTP1ConnectionMetrics,
	requestBuffer, responseBuffer SocketDataBuffer) error {
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
	h.appendToMetrics(data, request, requestBuffer, response, responseBuffer)

	if log.Enable(logrus.DebugLevel) {
		metricsJSON, _ := json.Marshal(data)
		log.Debugf("generated metrics, connection id: %s, side: %s, metrisc: %s", connectionID, side.String(), string(metricsJSON))
	}
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

func (h *HTTP1Analyzer) appendToMetrics(data *HTTP1URIMetrics, req *http.Request, reqBuffer SocketDataBuffer,
	resp *http.Response, respBuffer SocketDataBuffer) {
	data.RequestCounter.Increase()
	statusCounter := data.StatusCounter[resp.StatusCode]
	if statusCounter == nil {
		statusCounter = metrics.NewCounter()
		data.StatusCounter[resp.StatusCode] = statusCounter
	}
	statusCounter.Increase()

	data.AvgRequestPackageSize.Increase(float64(reqBuffer.TotalSize()))
	data.AvgResponsePackageSize.Increase(float64(respBuffer.TotalSize()))
	data.ReqPackageSizeHistogram.Increase(float64(reqBuffer.TotalSize()))
	data.RespPackageSizeHistogram.Increase(float64(respBuffer.TotalSize()))

	duration := time.Duration(respBuffer.Time() - reqBuffer.Time())
	durationInMS := float64(duration.Milliseconds())
	data.avgDuration.Increase(durationInMS)
	data.durationHistogram.Increase(durationInMS)

	h.increaseSlowTraceTopN(data.slowTraces, duration, req, resp, reqBuffer, respBuffer)
}

func (h *HTTP1Analyzer) increaseSlowTraceTopN(slowTraceTopN *metrics.TopN, duration time.Duration,
	request *http.Request, _ *http.Response, reqBuffer, respBuffer SocketDataBuffer) {
	tracingContext, err := AnalyzeTracingContext(func(key string) string {
		return request.Header.Get(key)
	})
	if err != nil {
		log.Warnf("analyze tracing context error: %v", err)
		return
	}
	if tracingContext == nil {
		return
	}

	// remove the query parameters
	uri := request.RequestURI
	if i := strings.Index(uri, "?"); i > 0 {
		uri = uri[0:i]
	}
	trace := &HTTP1Trace{Trace: tracingContext, RequestURI: uri, RequestBuffer: reqBuffer, ResponseBuffer: respBuffer}
	slowTraceTopN.AddRecord(trace, duration.Milliseconds())
}

func (h *HTTP1ConnectionMetrics) MergeMetricsFromConnection(connection *base.ConnectionContext) {
	other := QueryProtocolMetrics(connection.Metrics, HTTP1ProtocolName).(*HTTP1ConnectionMetrics)
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

func (h *HTTP1ConnectionMetrics) FlushMetrics(traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	connectionMetrics := QueryProtocolMetrics(traffic.Metrics, HTTP1ProtocolName).(*HTTP1ConnectionMetrics)
	for _, p := range traffic.LocalProcesses {
		// if the remote process is profiling, then used the client side
		localMetrics := connectionMetrics.clientMetrics
		remoteMetrics := connectionMetrics.serverMetrics
		if traffic.Role == base.ConnectionRoleServer {
			localMetrics = connectionMetrics.serverMetrics
			remoteMetrics = connectionMetrics.clientMetrics
		}

		metricsCount := h.appendMetrics(traffic, p, "", localMetrics, metricsBuilder, false)
		if traffic.RemoteProcessIsProfiling() {
			metricsCount += h.appendMetrics(traffic, p, "", remoteMetrics, metricsBuilder, true)
		}
		if metricsCount <= 0 {
			continue
		}

		if log.Enable(logrus.DebugLevel) {
			// if remote process is profiling, then the metrics data need to be cut half
			log.Debugf("flush HTTP1 metrics(%s): %s, remote process is profiling: %t, client(%s), server(%s)"+
				traffic.Role.String(), traffic.GenerateConnectionInfo(), traffic.RemoteProcessIsProfiling(),
				connectionMetrics.clientMetrics.String(), connectionMetrics.serverMetrics.String())
		}
	}
}

func (h *HTTP1ConnectionMetrics) appendMetrics(traffic *base.ProcessTraffic,
	local api.ProcessInterface, url string, http1Metrics *HTTP1URIMetrics, metricsBuilder *base.MetricsBuilder, durationOnly bool) int {
	collections := make([]*v3.MeterData, 0)
	role, labels := metricsBuilder.BuildBasicMeterLabels(traffic, local)
	prefix := metricsBuilder.MetricPrefix()

	collections = h.buildMetrics(collections, prefix, fmt.Sprintf("%s_duration_avg", role.String()), labels, url,
		traffic, http1Metrics.avgDuration)
	collections = h.buildMetrics(collections, prefix, fmt.Sprintf("%s_duration_histogram", role.String()), labels, url,
		traffic, http1Metrics.durationHistogram)
	if durationOnly {
		return len(collections)
	}

	collections = h.buildMetrics(collections, prefix, "request_counter", labels, url, traffic, http1Metrics.RequestCounter)
	for status, counter := range http1Metrics.StatusCounter {
		statusLabels := append(labels, &v3.Label{Name: "code", Value: fmt.Sprintf("%d", status)})
		collections = h.buildMetrics(collections, prefix, "response_status_counter", statusLabels, url, traffic, counter)
	}

	collections = h.buildMetrics(collections, prefix, "request_package_size_avg", labels, url, traffic, http1Metrics.AvgRequestPackageSize)
	collections = h.buildMetrics(collections, prefix, "response_package_size_avg", labels, url, traffic, http1Metrics.AvgResponsePackageSize)
	collections = h.buildMetrics(collections, prefix, "request_package_size_histogram", labels, url, traffic, http1Metrics.ReqPackageSizeHistogram)
	collections = h.buildMetrics(collections, prefix, "response_package_size_histogram", labels, url, traffic, http1Metrics.RespPackageSizeHistogram)

	metricsBuilder.AppendMetrics(local.Entity().ServiceName, local.Entity().InstanceName, collections)
	logsCount := http1Metrics.slowTraces.AppendData(local, traffic, metricsBuilder)
	return len(collections) + logsCount
}

func (h *HTTP1ConnectionMetrics) buildMetrics(collection []*v3.MeterData, prefix, name string, basicLabels []*v3.Label,
	url string, _ *base.ProcessTraffic, data metrics.Metrics) []*v3.MeterData {
	// if remote process is also profiling, then needs to be calculated half of metrics
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
	u.RequestCounter.MergeAndClean(other.RequestCounter)
	for k, v := range other.StatusCounter {
		if existing := u.StatusCounter[k]; existing != nil {
			existing.MergeAndClean(v)
		} else {
			u.StatusCounter[k] = v
		}
	}

	u.AvgRequestPackageSize.MergeAndClean(other.AvgRequestPackageSize)
	u.AvgResponsePackageSize.MergeAndClean(other.AvgResponsePackageSize)
	u.ReqPackageSizeHistogram.MergeAndClean(other.ReqPackageSizeHistogram)
	u.RespPackageSizeHistogram.MergeAndClean(other.RespPackageSizeHistogram)
	u.avgDuration.MergeAndClean(other.avgDuration)
	u.durationHistogram.MergeAndClean(other.durationHistogram)
	u.slowTraces.MergeAndClean(other.slowTraces)
}

func (u *HTTP1URIMetrics) String() string {
	return fmt.Sprintf("request count: %d, avg request size: %f, avg response size: %f, avg duration: %f, slow trace count: %d",
		u.RequestCounter.Get(), u.AvgRequestPackageSize.Calculate(), u.AvgResponsePackageSize.Calculate(),
		u.avgDuration.Calculate(), u.slowTraces.List.Len())
}

type HTTP1Trace struct {
	Trace          TracingContext
	RequestURI     string
	RequestBuffer  SocketDataBuffer
	ResponseBuffer SocketDataBuffer
}

func (h *HTTP1Trace) Flush(duration int64, process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	logData := &logv3.LogData{}
	logData.Service = process.Entity().ServiceName
	logData.ServiceInstance = process.Entity().InstanceName
	logData.Layer = process.Entity().Layer

	logData.Tags = &logv3.LogTags{Data: make([]*commonv3.KeyStringValuePair, 0)}
	logData.Tags.Data = append(logData.Tags.Data, &commonv3.KeyStringValuePair{Key: "LOG_KIND", Value: "NET_PROFILING_SAMPLED_TRACE"})

	// trace context
	traceContext := &logv3.TraceContext{}
	traceContext.TraceId = h.Trace.TraceID()
	logData.TraceContext = traceContext

	// body
	logBody := &logv3.LogDataBody{Type: "json"}
	body := &HTTP1SlowTraceLogBody{
		Latency:       duration,
		TraceProvider: h.Trace.Provider(),
		DetectPoint:   traffic.Role.String(),
		Component:     traffic.Protocol.String(),
		SSL:           traffic.IsSSL,
		URI:           h.RequestURI,
		Reason:        "slow",
	}
	if traffic.Role == base.ConnectionRoleClient {
		body.ClientProcess = &HTTP1SlowTraceLogProcess{ProcessID: process.ID()}
		body.ServerProcess = NewHTTP1SlowTRaceLogRemoteProcess(traffic, process)
	} else {
		body.ServerProcess = &HTTP1SlowTraceLogProcess{ProcessID: process.ID()}
		body.ClientProcess = NewHTTP1SlowTRaceLogRemoteProcess(traffic, process)
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		log.Warnf("format the slow trace log body failure: %v", err)
		return
	}
	logBody.Content = &logv3.LogDataBody_Json{Json: &logv3.JSONLog{Json: string(bodyJSON)}}
	logData.Body = logBody

	metricsBuilder.AppendLogs(process.Entity().ServiceName, logData)
}

type HTTP1SlowTraceLogBody struct {
	URI           string                    `json:"uri"`
	Reason        string                    `json:"reason"`
	Latency       int64                     `json:"latency"`
	TraceProvider string                    `json:"trace_provider"`
	ClientProcess *HTTP1SlowTraceLogProcess `json:"client_process"`
	ServerProcess *HTTP1SlowTraceLogProcess `json:"server_process"`
	DetectPoint   string                    `json:"detect_point"`
	Component     string                    `json:"component"`
	SSL           bool                      `json:"ssl"`
}

type HTTP1SlowTraceLogProcess struct {
	ProcessID string `json:"process_id"`
	Local     bool   `json:"local"`
	Address   string `json:"address"`
}

func NewHTTP1SlowTRaceLogRemoteProcess(traffic *base.ProcessTraffic, local api.ProcessInterface) *HTTP1SlowTraceLogProcess {
	if len(traffic.RemoteProcesses) != 0 {
		for _, p := range traffic.RemoteProcesses {
			// only match with same service instance
			if local.Entity().ServiceName == p.Entity().ServiceName &&
				local.Entity().InstanceName == p.Entity().InstanceName {
				return &HTTP1SlowTraceLogProcess{ProcessID: p.ID()}
			}
		}
	}

	if tools.IsLocalHostAddress(traffic.RemoteIP) || traffic.Analyzer.IsLocalAddressInCache(traffic.RemoteIP) {
		return &HTTP1SlowTraceLogProcess{Local: true}
	}

	return &HTTP1SlowTraceLogProcess{Address: fmt.Sprintf("%s:%d", traffic.RemoteIP, traffic.RemotePort)}
}
