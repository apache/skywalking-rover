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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/process/api"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/metrics"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	protocol "github.com/apache/skywalking-rover/pkg/tools/tracing"

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

func (u *URIMetrics) Append(sampleConfig *SamplingConfig, req *reader.Request, resp *reader.Response) {
	u.RequestCounter.Increase()
	statusCode := resp.Original().StatusCode
	statusCounter := u.StatusCounter[statusCode]
	if statusCounter == nil {
		statusCounter = metrics.NewCounter()
		u.StatusCounter[statusCode] = statusCounter
	}
	statusCounter.Increase()

	requestTotalSize := req.ContentTotalSize()
	responseTotalSize := resp.ContentTotalSize()
	u.AvgRequestPackageSize.Increase(float64(requestTotalSize))
	u.AvgResponsePackageSize.Increase(float64(responseTotalSize))
	u.ReqPackageSizeHistogram.Increase(float64(requestTotalSize))
	u.RespPackageSizeHistogram.Increase(float64(responseTotalSize))

	duration := time.Duration(resp.EndTime() - req.StartTime())
	durationInMS := float64(duration.Milliseconds())
	u.avgDuration.Increase(durationInMS)
	u.durationHistogram.Increase(durationInMS)

	u.sampler.AppendMetrics(sampleConfig, duration, req, resp)
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
	Trace      protocol.Context
	RequestURI string
	Request    *reader.Request
	Response   *reader.Response
	Type       string
	Settings   *profiling.NetworkDataCollectingSettings
	TaskConfig *profiling.HTTPSamplingConfig
}

func (h *Trace) Flush(duration int64, process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	logData := &logv3.LogData{}
	logData.Service = process.Entity().ServiceName
	logData.ServiceInstance = process.Entity().InstanceName
	logData.Layer = process.Entity().Layer

	logData.Tags = &logv3.LogTags{Data: make([]*commonv3.KeyStringValuePair, 0)}
	logData.Tags.Data = append(logData.Tags.Data, &commonv3.KeyStringValuePair{Key: "LOG_KIND", Value: "NET_PROFILING_SAMPLED_TRACE"})

	// trace common
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
		Status:        h.Response.Original().StatusCode,
	}
	if traffic.Role == enums.ConnectionRoleClient {
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

	// append full http content and syscall
	h.AppendHTTPEvents(process, traffic, metricsBuilder)
}

func (h *Trace) AppendHTTPEvents(process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) {
	attaches := make([]*v3.SpanAttachedEvent, 0)
	if h.Settings != nil && h.Settings.RequireCompleteRequest {
		attaches = h.appendHTTPEvent(attaches, process, traffic, transportRequest, h.Request.MessageOpt, h.TaskConfig.DefaultRequestEncoding,
			h.Settings.MaxRequestSize)
		attaches = h.appendSyscallEvents(attaches, process, traffic, h.Request.MessageOpt)
	}
	if h.Settings != nil && h.Settings.RequireCompleteResponse {
		attaches = h.appendHTTPEvent(attaches, process, traffic, transportResponse, h.Response.MessageOpt, h.TaskConfig.DefaultResponseEncoding,
			h.Settings.MaxResponseSize)
		attaches = h.appendSyscallEvents(attaches, process, traffic, h.Response.MessageOpt)
	}

	metricsBuilder.AppendSpanAttachedEvents(attaches)
}

func (h *Trace) appendHTTPEvent(attaches []*v3.SpanAttachedEvent, process api.ProcessInterface, traffic *base.ProcessTraffic,
	tp string, message *reader.MessageOpt, defaultBodyEncoding string, maxSize int32) []*v3.SpanAttachedEvent {
	content, err := message.TransformReadableContent(defaultBodyEncoding, int(maxSize))
	if err != nil {
		log.Warnf("transform http %s erorr: %v", tp, err)
		return attaches
	}

	event := &v3.SpanAttachedEvent{}
	event.StartTime = host.TimeToInstant(message.StartTime())
	event.EndTime = host.TimeToInstant(message.EndTime())
	event.Event = fmt.Sprintf("HTTP %s Sampling", tp)
	event.Tags = make([]*commonv3.KeyStringValuePair, 0)
	event.Tags = append(event.Tags,
		// content data
		&commonv3.KeyStringValuePair{Key: "data_size", Value: units.BytesSize(float64(message.ContentTotalSize()))},
		&commonv3.KeyStringValuePair{Key: "data_content", Value: content},
		&commonv3.KeyStringValuePair{Key: "data_direction", Value: message.Direction().String()},
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
		Type:           h.Trace.Provider().SpanAttachType,
	}
	return append(attaches, event)
}

func (h *Trace) appendSyscallEvents(attachEvents []*v3.SpanAttachedEvent, process api.ProcessInterface, traffic *base.ProcessTraffic,
	message *reader.MessageOpt) []*v3.SpanAttachedEvent {
	headerDetails := message.HeaderBuffer().Details()
	bodyDetails := message.BodyBuffer().Details()
	dataIDCache := make(map[uint64]bool)
	for e := headerDetails.Front(); e != nil; e = e.Next() {
		event := e.Value.(*events.SocketDetailEvent)
		dataIDCache[event.DataID()] = true
		attachEvents = h.appendPerDetailEvent(attachEvents, process, traffic, event, message.HeaderBuffer())
	}
	for e := bodyDetails.Front(); e != nil; e = e.Next() {
		event := e.Value.(*events.SocketDetailEvent)
		if dataIDCache[event.DataID()] {
			continue
		}
		attachEvents = h.appendPerDetailEvent(attachEvents, process, traffic, event, message.BodyBuffer())
	}
	return attachEvents
}

func (h *Trace) appendPerDetailEvent(attaches []*v3.SpanAttachedEvent, process api.ProcessInterface, _ *base.ProcessTraffic,
	detail *events.SocketDetailEvent, buf *buffer.Buffer) []*v3.SpanAttachedEvent {
	event := &v3.SpanAttachedEvent{}
	dataBuffer := buf.FindFirstDataBuffer(detail.DataID())
	if dataBuffer == nil {
		return attaches
	}
	event.StartTime = host.TimeToInstant(dataBuffer.StartTime())
	event.EndTime = host.TimeToInstant(dataBuffer.EndTime())
	event.Event = fmt.Sprintf("Syscall %s", detail.FuncName.String())
	event.Tags = make([]*commonv3.KeyStringValuePair, 0)
	event.Tags = append(event.Tags,
		// content data
		&commonv3.KeyStringValuePair{Key: "package_size", Value: units.BytesSize(float64(detail.TotalPackageSize))},
		&commonv3.KeyStringValuePair{Key: "package_count", Value: fmt.Sprintf("%d", detail.PackageCount)},
		&commonv3.KeyStringValuePair{Key: "network_name", Value: host.NetworkName(int(detail.IfIndex))},
		&commonv3.KeyStringValuePair{Key: "network_index", Value: fmt.Sprintf("%d", detail.IfIndex)},
		// entity
		&commonv3.KeyStringValuePair{Key: "service_name", Value: process.Entity().ServiceName},
		&commonv3.KeyStringValuePair{Key: "service_instance_name", Value: process.Entity().InstanceName},
		&commonv3.KeyStringValuePair{Key: "process_name", Value: process.Entity().ProcessName},
	)

	if detail.RTTTime > 0 {
		event.Tags = append(event.Tags,
			&commonv3.KeyStringValuePair{Key: "avg_rtt_time", Value: fmt.Sprintf("%dns", int(detail.RTTTime)/int(detail.RTTCount))})
	}

	event.Summary = make([]*commonv3.KeyIntValuePair, 0)
	event.TraceContext = &v3.SpanAttachedEvent_SpanReference{
		TraceId:        h.Trace.TraceID(),
		TraceSegmentId: h.Trace.TraceSegmentID(),
		SpanId:         h.Trace.SpanID(),
		Type:           h.Trace.Provider().SpanAttachType,
	}
	return append(attaches, event)
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
