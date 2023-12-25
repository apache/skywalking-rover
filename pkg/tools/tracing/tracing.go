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

package tracing

import (
	"encoding/base64"
	"fmt"
	"strings"

	accesslogv3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
	agentv3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

type Provider int

var (
	ProviderSkyWalking Provider = 1
	ProviderZipkin              = 2
)

type Context interface {
	TraceID() string
	TraceSegmentID() string
	SpanID() string
	Provider() *TraceContextProvider
}

type TraceContextProvider struct {
	SpanAttachType agentv3.SpanAttachedEvent_SpanReferenceType
	AccessLogType  accesslogv3.AccessLogTraceInfoProvider
	Name           string
}

type SkyWalkingTracingContext struct {
	TraceID0              string
	SegmentID0            string
	SpanID0               string
	ParentService         string
	ParentServiceInstance string
	ParentEndpoint        string
	AddressUsedAtClient   string
}

type ZipkinTracingContext struct {
	TraceID0 string
	SpanID0  string
}

func (w *SkyWalkingTracingContext) TraceID() string {
	return w.TraceID0
}

func (w *SkyWalkingTracingContext) TraceSegmentID() string {
	return w.SegmentID0
}

func (w *SkyWalkingTracingContext) SpanID() string {
	return w.SpanID0
}

func (w *SkyWalkingTracingContext) Provider() *TraceContextProvider {
	return &TraceContextProvider{
		SpanAttachType: agentv3.SpanAttachedEvent_SKYWALKING,
		AccessLogType:  accesslogv3.AccessLogTraceInfoProvider_SkyWalking,
		Name:           "skywalking",
	}
}

func AnalyzeTracingContext(fetcher func(key string) string) (Context, error) {
	// skywalking v3
	if sw8Header := fetcher("sw8"); sw8Header != "" {
		return analyzeSkyWalking8TracingContext(sw8Header)
	}

	// zipkin
	if zipkinSingleContext := fetcher("b3"); zipkinSingleContext != "" {
		if ctx := analyzeZipkinTracingContextWithSingleData(zipkinSingleContext); ctx != nil {
			return ctx, nil
		}
	}
	if zipkinTraceID := fetcher("x-b3-traceid"); zipkinTraceID != "" {
		if spanID := fetcher("x-b3-spanid"); spanID != "" {
			return analyzeZipkinTracingContextWithSpecificData(zipkinTraceID, spanID), nil
		}
	}
	return nil, nil
}

func analyzeSkyWalking8TracingContext(val string) (*SkyWalkingTracingContext, error) {
	parts := strings.Split(val, "-")
	if len(parts) != 8 {
		return nil, fmt.Errorf("sw8 analyze error, value: %s", val)
	}
	var err error
	ctx := &SkyWalkingTracingContext{}
	ctx.TraceID0, err = decodeBase64StringValue(err, parts[1])
	ctx.SegmentID0, err = decodeBase64StringValue(err, parts[2])
	ctx.SpanID0 = parts[3]
	ctx.ParentService, err = decodeBase64StringValue(err, parts[4])
	ctx.ParentServiceInstance, err = decodeBase64StringValue(err, parts[5])
	ctx.ParentEndpoint, err = decodeBase64StringValue(err, parts[6])
	ctx.AddressUsedAtClient, err = decodeBase64StringValue(err, parts[7])

	if err != nil {
		return nil, err
	}
	return ctx, nil
}

func analyzeZipkinTracingContextWithSpecificData(traceID, spanID string) *ZipkinTracingContext {
	return &ZipkinTracingContext{TraceID0: traceID, SpanID0: spanID}
}

func analyzeZipkinTracingContextWithSingleData(singleData string) *ZipkinTracingContext {
	info := strings.Split(singleData, "-")
	if len(info) < 2 {
		return nil
	}
	return &ZipkinTracingContext{TraceID0: info[0], SpanID0: info[1]}
}

func (w *ZipkinTracingContext) TraceID() string {
	return w.TraceID0
}

func (w *ZipkinTracingContext) TraceSegmentID() string {
	return ""
}

func (w *ZipkinTracingContext) SpanID() string {
	return w.SpanID0
}

func (w *ZipkinTracingContext) Provider() *TraceContextProvider {
	return &TraceContextProvider{
		SpanAttachType: agentv3.SpanAttachedEvent_ZIPKIN,
		AccessLogType:  accesslogv3.AccessLogTraceInfoProvider_Zipkin,
		Name:           "zipkin",
	}
}

func decodeBase64StringValue(err error, val string) (string, error) {
	if err != nil {
		return "", err
	}
	result, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return "", err
	}
	return string(result), nil
}
