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
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html/charset"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	protocol "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/metrics"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	"github.com/docker/go-units"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
	logv3 "skywalking.apache.org/repo/goapi/collect/logging/v3"
)

var (
	transportRequest  = "Request"
	transportResponse = "Response"
)

type URIMetrics struct {
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

func NewHTTP1URIMetrics() *URIMetrics {
	return &URIMetrics{
		RequestCounter:           metrics.NewCounter(),
		StatusCounter:            make(map[int]*metrics.Counter),
		AvgRequestPackageSize:    metrics.NewAvgCounter(),
		AvgResponsePackageSize:   metrics.NewAvgCounter(),
		ReqPackageSizeHistogram:  metrics.NewHistogram(PackageSizeHistogramBuckets),
		RespPackageSizeHistogram: metrics.NewHistogram(PackageSizeHistogramBuckets),
		avgDuration:              metrics.NewAvgCounter(),
		durationHistogram:        metrics.NewHistogram(DurationHistogramBuckets),
		slowTraces:               metrics.NewTopN(SlowTraceTopNSize),
	}
}

func (u *URIMetrics) Append(req *http.Request, reqBuffer protocol.SocketDataBuffer, resp *http.Response, respBuffer protocol.SocketDataBuffer) {
	u.RequestCounter.Increase()
	statusCounter := u.StatusCounter[resp.StatusCode]
	if statusCounter == nil {
		statusCounter = metrics.NewCounter()
		u.StatusCounter[resp.StatusCode] = statusCounter
	}
	statusCounter.Increase()

	u.AvgRequestPackageSize.Increase(float64(reqBuffer.TotalSize()))
	u.AvgResponsePackageSize.Increase(float64(respBuffer.TotalSize()))
	u.ReqPackageSizeHistogram.Increase(float64(reqBuffer.TotalSize()))
	u.RespPackageSizeHistogram.Increase(float64(respBuffer.TotalSize()))

	duration := time.Duration(respBuffer.EndTime() - reqBuffer.StartTime())
	durationInMS := float64(duration.Milliseconds())
	u.avgDuration.Increase(durationInMS)
	u.durationHistogram.Increase(durationInMS)

	u.increaseSlowTraceTopN(u.slowTraces, duration, req, resp, reqBuffer, respBuffer)
}

func (u *URIMetrics) appendMetrics(traffic *base.ProcessTraffic,
	local api.ProcessInterface, url string, metricsBuilder *base.MetricsBuilder, durationOnly bool) int {
	collections := make([]*v3.MeterData, 0)
	role, labels := metricsBuilder.BuildBasicMeterLabels(traffic, local)
	prefix := metricsBuilder.MetricPrefix()

	collections = u.buildMetrics(collections, prefix, fmt.Sprintf("%s_duration_avg", role.String()), labels, url,
		traffic, u.avgDuration)
	collections = u.buildMetrics(collections, prefix, fmt.Sprintf("%s_duration_histogram", role.String()), labels, url,
		traffic, u.durationHistogram)
	if durationOnly {
		return len(collections)
	}

	collections = u.buildMetrics(collections, prefix, "request_counter", labels, url, traffic, u.RequestCounter)
	for status, counter := range u.StatusCounter {
		statusLabels := append(labels, &v3.Label{Name: "code", Value: fmt.Sprintf("%d", status)})
		collections = u.buildMetrics(collections, prefix, "response_status_counter", statusLabels, url, traffic, counter)
	}

	collections = u.buildMetrics(collections, prefix, "request_package_size_avg", labels, url, traffic, u.AvgRequestPackageSize)
	collections = u.buildMetrics(collections, prefix, "response_package_size_avg", labels, url, traffic, u.AvgResponsePackageSize)
	collections = u.buildMetrics(collections, prefix, "request_package_size_histogram", labels, url, traffic, u.ReqPackageSizeHistogram)
	collections = u.buildMetrics(collections, prefix, "response_package_size_histogram", labels, url, traffic, u.RespPackageSizeHistogram)

	metricsBuilder.AppendMetrics(local.Entity().ServiceName, local.Entity().InstanceName, collections)
	logsCount := u.slowTraces.AppendData(local, traffic, metricsBuilder)
	return len(collections) + logsCount
}

func (u *URIMetrics) buildMetrics(collection []*v3.MeterData, prefix, name string, basicLabels []*v3.Label,
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

func (u *URIMetrics) MergeAndClean(other *URIMetrics) {
	u.RequestCounter.MergeAndClean(other.RequestCounter)
	for k, v := range other.StatusCounter {
		cur := u.StatusCounter[k]
		if cur == nil {
			cur = metrics.NewCounter()
			u.StatusCounter[k] = cur
		}
		cur.MergeAndClean(v)
	}

	u.AvgRequestPackageSize.MergeAndClean(other.AvgRequestPackageSize)
	u.AvgResponsePackageSize.MergeAndClean(other.AvgResponsePackageSize)
	u.ReqPackageSizeHistogram.MergeAndClean(other.ReqPackageSizeHistogram)
	u.RespPackageSizeHistogram.MergeAndClean(other.RespPackageSizeHistogram)
	u.avgDuration.MergeAndClean(other.avgDuration)
	u.durationHistogram.MergeAndClean(other.durationHistogram)
	u.slowTraces.MergeAndClean(other.slowTraces)
}

func (u *URIMetrics) String() string {
	return fmt.Sprintf("request count: %d, avg request size: %f, avg response size: %f, avg duration: %f, slow trace count: %d, response counters: %v",
		u.RequestCounter.Get(), u.AvgRequestPackageSize.Calculate(), u.AvgResponsePackageSize.Calculate(),
		u.avgDuration.Calculate(), u.slowTraces.List.Len(), u.StatusCounter)
}

func (u *URIMetrics) increaseSlowTraceTopN(slowTraceTopN *metrics.TopN, duration time.Duration,
	request *http.Request, response *http.Response, reqBuffer, respBuffer protocol.SocketDataBuffer) {
	tracingContext, err := protocol.AnalyzeTracingContext(func(key string) string {
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
	trace := &Trace{Trace: tracingContext, RequestURI: uri, RequestBuffer: reqBuffer, ResponseBuffer: respBuffer, Request: request, Response: response}
	slowTraceTopN.AddRecord(trace, duration.Milliseconds())
}

type Trace struct {
	Trace          protocol.TracingContext
	RequestURI     string
	RequestBuffer  protocol.SocketDataBuffer
	Request        *http.Request
	ResponseBuffer protocol.SocketDataBuffer
	Response       *http.Response
}

func (h *Trace) Flush(duration int64, process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
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
	body := &SlowTraceLogBody{
		Latency:       duration,
		TraceProvider: h.Trace.Provider().Name,
		DetectPoint:   traffic.Role.String(),
		Component:     traffic.Protocol.String(),
		SSL:           traffic.IsSSL,
		URI:           h.RequestURI,
		Reason:        "slow",
	}
	if traffic.Role == base.ConnectionRoleClient {
		body.ClientProcess = &SlowTraceLogProcess{ProcessID: process.ID()}
		body.ServerProcess = NewHTTP1SlowTRaceLogRemoteProcess(traffic, process)
	} else {
		body.ServerProcess = &SlowTraceLogProcess{ProcessID: process.ID()}
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

	// append full http content
	h.AppendHTTPEvents(process, traffic, metricsBuilder)
}

func (h *Trace) AppendHTTPEvents(process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	events := make([]*v3.SpanAttachedEvent, 0)
	events = h.appendHTTPEvent(events, process, traffic, transportRequest, h.Request.Header, h.Request.Body, h.RequestBuffer)
	events = h.appendHTTPEvent(events, process, traffic, transportResponse, h.Response.Header, h.Response.Body, h.ResponseBuffer)

	metricsBuilder.AppendSpanAttachedEvents(events)
}

func (h *Trace) appendHTTPEvent(events []*v3.SpanAttachedEvent, process api.ProcessInterface, traffic *base.ProcessTraffic,
	tp string, header http.Header, body io.Reader, buffer protocol.SocketDataBuffer) []*v3.SpanAttachedEvent {
	content, err := h.transformHTTPRequest(header, body, buffer)
	if err != nil {
		log.Warnf("transform http %s erorr: %v", tp, err)
		return events
	}

	event := &v3.SpanAttachedEvent{}
	event.StartTime = host.TimeToInstant(buffer.StartTime())
	event.EndTime = host.TimeToInstant(buffer.EndTime())
	event.Event = fmt.Sprintf("HTTP %s Sampling", tp)
	event.Tags = make([]*commonv3.KeyStringValuePair, 0)
	event.Tags = append(event.Tags,
		// content data
		&commonv3.KeyStringValuePair{Key: "data size", Value: units.BytesSize(float64(buffer.TotalSize()))},
		&commonv3.KeyStringValuePair{Key: "data content", Value: content},
		&commonv3.KeyStringValuePair{Key: "data direction", Value: buffer.Direction().String()},
		&commonv3.KeyStringValuePair{Key: "data type", Value: tp},
		// connection
		&commonv3.KeyStringValuePair{Key: "connection role", Value: traffic.Role.String()},
		// entity
		&commonv3.KeyStringValuePair{Key: "service name", Value: process.Entity().ServiceName},
		&commonv3.KeyStringValuePair{Key: "service instance name", Value: process.Entity().InstanceName},
		&commonv3.KeyStringValuePair{Key: "process name", Value: process.Entity().ProcessName},
	)

	// current event needs bind to the upstream
	if buffer.Direction() == base.SocketDataDirectionIngress && tp == transportRequest ||
		buffer.Direction() == base.SocketDataDirectionEgress && tp == transportResponse {
		event.Tags = append(event.Tags, &commonv3.KeyStringValuePair{Key: "bind to upstream span", Value: "true"})
	}
	event.Summary = make([]*commonv3.KeyIntValuePair, 0)
	event.TraceContext = &v3.SpanAttachedEvent_SpanReference{
		TraceId:        h.Trace.TraceID(),
		TraceSegmentId: h.Trace.TraceSegmentID(),
		SpanId:         h.Trace.SpanID(),
		Type:           h.Trace.Provider().Type,
	}
	return append(events, event)
}

// nolint
func (h *Trace) transformHTTPRequest(header http.Header, body io.Reader, buffer protocol.SocketDataBuffer) (string, error) {
	var needGzip, isPlain, isUtf8 = header.Get("Content-Encoding") == "gzip", true, true
	contentType := header.Get("Content-Type")
	if contentType != "" {
		isPlain = strings.HasPrefix(contentType, "text/") || contentType == "application/json"
		if _, params, err := mime.ParseMediaType(contentType); err == nil {
			if cs, ok := params["charset"]; ok {
				isUtf8 = cs == "utf-8"
			}
		}
	}

	if !needGzip && isPlain && isUtf8 {
		return string(buffer.BufferData()), nil
	}

	// re-read the buffer and skip to the body position
	buf := bufio.NewReaderSize(bytes.NewBuffer(buffer.BufferData()), len(buffer.BufferData()))
	response, err := http.ReadResponse(buf, nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	// no text plain, no need to print the data
	headerString := string(buffer.BufferData()[:len(buffer.BufferData())-buf.Buffered()])
	if !isPlain {
		return fmt.Sprintf("%s[not plain, current content type: %s]", headerString, contentType), nil
	}

	data := body
	if needGzip {
		data, err = gzip.NewReader(response.Body)
		if err != nil {
			return "", err
		}
	}
	if !isUtf8 {
		data, err = charset.NewReader(data, contentType)
		if err != nil {
			return "", err
		}
	}

	realData, err := io.ReadAll(data)
	if err != nil {
		if err != io.ErrUnexpectedEOF {
			return "", err
		}
		realData = append(realData, []byte("[chunked]")...)
	}
	return fmt.Sprintf("%s%s", headerString, string(realData)), nil
}

type SlowTraceLogBody struct {
	URI           string               `json:"uri"`
	Reason        string               `json:"reason"`
	Latency       int64                `json:"latency"`
	TraceProvider string               `json:"trace_provider"`
	ClientProcess *SlowTraceLogProcess `json:"client_process"`
	ServerProcess *SlowTraceLogProcess `json:"server_process"`
	DetectPoint   string               `json:"detect_point"`
	Component     string               `json:"component"`
	SSL           bool                 `json:"ssl"`
}

type SlowTraceLogProcess struct {
	ProcessID string `json:"process_id"`
	Local     bool   `json:"local"`
	Address   string `json:"address"`
}

func NewHTTP1SlowTRaceLogRemoteProcess(traffic *base.ProcessTraffic, local api.ProcessInterface) *SlowTraceLogProcess {
	if len(traffic.RemoteProcesses) != 0 {
		for _, p := range traffic.RemoteProcesses {
			// only match with same service instance
			if local.Entity().ServiceName == p.Entity().ServiceName &&
				local.Entity().InstanceName == p.Entity().InstanceName {
				return &SlowTraceLogProcess{ProcessID: p.ID()}
			}
		}
	}

	if tools.IsLocalHostAddress(traffic.RemoteIP) || traffic.Analyzer.IsLocalAddressInCache(traffic.RemoteIP) {
		return &SlowTraceLogProcess{Local: true}
	}

	return &SlowTraceLogProcess{Address: fmt.Sprintf("%s:%d", traffic.RemoteIP, traffic.RemotePort)}
}
