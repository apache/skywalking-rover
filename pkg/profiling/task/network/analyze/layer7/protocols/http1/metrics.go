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
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
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

	sampler *Sampler
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
		sampler:                  NewSampler(),
	}
}

func (u *URIMetrics) Append(sampleConfig *SamplingConfig,
	req *http.Request, reqBuffer protocol.SocketDataBuffer, resp *http.Response, respBuffer protocol.SocketDataBuffer) {
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

	u.sampler.AppendMetrics(sampleConfig, duration, req, resp, reqBuffer, respBuffer)
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
		statusLabels := make([]*v3.Label, len(labels))
		copy(statusLabels, labels)
		statusLabels = append(statusLabels, &v3.Label{Name: "code", Value: fmt.Sprintf("%d", status)})
		collections = u.buildMetrics(collections, prefix, "response_status_counter", statusLabels, url, traffic, counter)
	}

	collections = u.buildMetrics(collections, prefix, "request_package_size_avg", labels, url, traffic, u.AvgRequestPackageSize)
	collections = u.buildMetrics(collections, prefix, "response_package_size_avg", labels, url, traffic, u.AvgResponsePackageSize)
	collections = u.buildMetrics(collections, prefix, "request_package_size_histogram", labels, url, traffic, u.ReqPackageSizeHistogram)
	collections = u.buildMetrics(collections, prefix, "response_package_size_histogram", labels, url, traffic, u.RespPackageSizeHistogram)

	metricsBuilder.AppendMetrics(local.Entity().ServiceName, local.Entity().InstanceName, collections)

	logsCount := u.sampler.BuildMetrics(local, traffic, metricsBuilder)
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
	u.sampler.MergeAndClean(other.sampler)
}

func (u *URIMetrics) String() string {
	return fmt.Sprintf("request count: %d, avg request size: %f, avg response size: %f, avg duration: %f, response counters: %v, sampler: %s",
		u.RequestCounter.Get(), u.AvgRequestPackageSize.Calculate(), u.AvgResponsePackageSize.Calculate(),
		u.avgDuration.Calculate(), u.StatusCounter, u.sampler.String())
}

type Trace struct {
	Trace          protocol.TracingContext
	RequestURI     string
	RequestBuffer  protocol.SocketDataBuffer
	Request        *http.Request
	ResponseBuffer protocol.SocketDataBuffer
	Response       *http.Response
	Type           string
	Settings       *profiling.NetworkDataCollectingSettings
	TaskConfig     *profiling.HTTPSamplingConfig
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
	body := &SamplingTraceLogBody{
		Latency:       duration,
		TraceProvider: h.Trace.Provider().Name,
		DetectPoint:   traffic.Role.String(),
		Component:     traffic.Protocol.String(),
		SSL:           traffic.IsSSL,
		URI:           h.RequestURI,
		Reason:        h.Type,
		Status:        h.Response.StatusCode,
	}
	if traffic.Role == base.ConnectionRoleClient {
		body.ClientProcess = &SamplingTraceLogProcess{ProcessID: process.ID()}
		body.ServerProcess = NewHTTP1SampledTraceLogRemoteProcess(traffic, process)
	} else {
		body.ServerProcess = &SamplingTraceLogProcess{ProcessID: process.ID()}
		body.ClientProcess = NewHTTP1SampledTraceLogRemoteProcess(traffic, process)
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
	if h.Settings != nil && h.Settings.RequireCompleteRequest {
		events = h.appendHTTPEvent(events, process, traffic, transportRequest, h.Request.Header,
			h.Request.Body, h.RequestBuffer, h.Settings.MaxRequestSize)
	}
	if h.Settings != nil && h.Settings.RequireCompleteResponse {
		events = h.appendHTTPEvent(events, process, traffic, transportResponse, h.Response.Header,
			h.Response.Body, h.ResponseBuffer, h.Settings.MaxResponseSize)
	}

	metricsBuilder.AppendSpanAttachedEvents(events)
}

func (h *Trace) appendHTTPEvent(events []*v3.SpanAttachedEvent, process api.ProcessInterface, traffic *base.ProcessTraffic,
	tp string, header http.Header, body io.Reader, buffer protocol.SocketDataBuffer, maxSize int32) []*v3.SpanAttachedEvent {
	content, err := h.transformHTTPBody(tp, header, body, buffer, maxSize)
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
		&commonv3.KeyStringValuePair{Key: "data_size", Value: units.BytesSize(float64(buffer.TotalSize()))},
		&commonv3.KeyStringValuePair{Key: "data_content", Value: content},
		&commonv3.KeyStringValuePair{Key: "data_direction", Value: buffer.Direction().String()},
		&commonv3.KeyStringValuePair{Key: "data_type", Value: strings.ToLower(tp)},
		// connection
		&commonv3.KeyStringValuePair{Key: "connection_role", Value: traffic.Role.String()},
		// entity
		&commonv3.KeyStringValuePair{Key: "service_name", Value: process.Entity().ServiceName},
		&commonv3.KeyStringValuePair{Key: "service_instance_name", Value: process.Entity().InstanceName},
		&commonv3.KeyStringValuePair{Key: "process_name", Value: process.Entity().ProcessName},
	)

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
func (h *Trace) transformHTTPBody(tp string, header http.Header, _ io.Reader, buffer protocol.SocketDataBuffer, maxSize int32) (string, error) {
	var needGzip, isPlain, isUtf8 = header.Get("Content-Encoding") == "gzip", true, true
	contentType := header.Get("Content-Type")
	if contentType == "" {
		if tp == transportRequest {
			contentType = h.TaskConfig.DefaultRequestEncoding
		} else {
			contentType = h.TaskConfig.DefaultResponseEncoding
		}
		contentType = fmt.Sprintf("text/html; charset=%s", contentType)
	}

	isPlain = strings.HasPrefix(contentType, "text/") || contentType == "application/json"
	if _, params, err := mime.ParseMediaType(contentType); err == nil {
		if cs, ok := params["charset"]; ok {
			isUtf8 = strings.ToLower(cs) == "utf-8"
		}
	}

	if !needGzip && isPlain && isUtf8 {
		resultSize := len(buffer.BufferData())
		if maxSize > 0 && resultSize > int(maxSize) {
			resultSize = int(maxSize)
		}
		return string(buffer.BufferData()[0:resultSize]), nil
	}

	// re-read the buffer and skip to the body position
	buf := bufio.NewReaderSize(bytes.NewBuffer(buffer.BufferData()), len(buffer.BufferData()))
	var httpBody io.ReadCloser
	if tp == transportRequest {
		req, err := http.ReadRequest(buf)
		if err != nil {
			return "", err
		}
		httpBody = req.Body
	} else {
		response, err := http.ReadResponse(buf, nil)
		if err != nil {
			return "", err
		}
		httpBody = response.Body
	}
	defer httpBody.Close()

	// no text plain, no need to print the data
	headerLen := len(buffer.BufferData()) - buf.Buffered()
	if maxSize > 0 && int(maxSize) < headerLen {
		return string(buffer.BufferData()[:maxSize]), nil
	}
	headerString := string(buffer.BufferData()[:headerLen])
	if !isPlain {
		return fmt.Sprintf("%s[not plain, current content type: %s]", headerString, contentType), nil
	}
	// nobody
	if buf.Buffered() == 0 {
		return headerString, nil
	}

	data := httpBody
	var err error
	if needGzip {
		data, err = gzip.NewReader(httpBody)
		if err != nil {
			return "", err
		}
	}
	if !isUtf8 {
		data, err = newCharsetReader(data, contentType)
		if err != nil {
			return "", err
		}
	}

	realData, err := io.ReadAll(data)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}
	resultSize := len(realData)
	if maxSize > 0 && (resultSize+headerLen) > int(maxSize) {
		resultSize = int(maxSize) - headerLen
	}
	return fmt.Sprintf("%s%s", headerString, string(realData[0:resultSize])), nil
}

type charsetReadWrapper struct {
	reader io.Reader
}

func newCharsetReader(r io.Reader, contentType string) (*charsetReadWrapper, error) {
	reader, err := charset.NewReader(r, contentType)
	if err != nil {
		return nil, err
	}
	return &charsetReadWrapper{reader: reader}, nil
}

func (c *charsetReadWrapper) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func (c *charsetReadWrapper) Close() error {
	return nil
}

type SamplingTraceLogBody struct {
	URI           string                   `json:"uri"`
	Reason        string                   `json:"reason"`
	Latency       int64                    `json:"latency"`
	TraceProvider string                   `json:"trace_provider"`
	ClientProcess *SamplingTraceLogProcess `json:"client_process"`
	ServerProcess *SamplingTraceLogProcess `json:"server_process"`
	DetectPoint   string                   `json:"detect_point"`
	Component     string                   `json:"component"`
	SSL           bool                     `json:"ssl"`
	Status        int                      `json:"status"`
}

type SamplingTraceLogProcess struct {
	ProcessID string `json:"process_id"`
	Local     bool   `json:"local"`
	Address   string `json:"address"`
}

func NewHTTP1SampledTraceLogRemoteProcess(traffic *base.ProcessTraffic, local api.ProcessInterface) *SamplingTraceLogProcess {
	if len(traffic.RemoteProcesses) != 0 {
		for _, p := range traffic.RemoteProcesses {
			// only match with same service instance
			if local.Entity().ServiceName == p.Entity().ServiceName &&
				local.Entity().InstanceName == p.Entity().InstanceName {
				return &SamplingTraceLogProcess{ProcessID: p.ID()}
			}
		}
	}

	if tools.IsLocalHostAddress(traffic.RemoteIP) || traffic.Analyzer.IsLocalAddressInCache(traffic.RemoteIP) {
		return &SamplingTraceLogProcess{Local: true}
	}

	return &SamplingTraceLogProcess{Address: fmt.Sprintf("%s:%d", traffic.RemoteIP, traffic.RemotePort)}
}
