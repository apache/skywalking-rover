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

package analyze

import (
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// testAccessLogConfig is the access log config the analyzers of the tests are made with
var testAccessLogConfig = func() *common.Config { return &common.Config{} }

// withTraceContext makes the analyzers of the test analyze the tracing context of the requests, or not
func withTraceContext(t *testing.T, on bool) {
	t.Helper()
	before := testAccessLogConfig
	testAccessLogConfig = func() *common.Config {
		c := &common.Config{}
		c.ProtocolAnalyze.AnalyzeTraceContext = on
		return c
	}
	t.Cleanup(func() { testAccessLogConfig = before })
}

const (
	// the sw8 header of a request: trace "trace-1", segment "segment-1", span 3
	testSW8 = "1-dHJhY2UtMQ==-c2VnbWVudC0x-3-c2VydmljZQ==-aW5zdGFuY2U=-L2VuZHBvaW50-bG9jYWxob3N0OjgwODA="
	// the b3 single header of a request: trace "463ac35c9f6413ad", span "a2fb4a1d1a96d312"
	testB3 = "463ac35c9f6413ad-a2fb4a1d1a96d312-1"
)

func requestTrace(l *v3.AccessLogProtocolLogs) *v3.AccessLogTraceInfo {
	return l.GetHttp().GetRequest().GetTrace()
}

// TestHTTP1TraceContext: with access_log.protocol_analyze.analyze_trace_context on, the HTTP/1 logs carry the sw8 and
// the b3 context of their requests; off, none
func TestHTTP1TraceContext(t *testing.T) {
	exchanges := [][2]string{
		{"GET /sw8 HTTP/1.1\r\nHost: s\r\nsw8: " + testSW8 + "\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{"GET /b3 HTTP/1.1\r\nHost: s\r\nb3: " + testB3 + "\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{"GET /none HTTP/1.1\r\nHost: s\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
	}
	t.Run("on", func(t *testing.T) {
		withTraceContext(t, true)
		logs := http1AnalyzeExchanges(t, exchanges).protocolLogs
		if len(logs) != 3 {
			t.Fatalf("%d logs", len(logs))
		}
		if tr := requestTrace(logs[0]); tr == nil || tr.TraceId != "trace-1" || tr.TraceSegmentId != "segment-1" || tr.SpanId != "3" ||
			tr.Provider != v3.AccessLogTraceInfoProvider_SkyWalking {
			t.Fatalf("sw8: %v", tr)
		}
		if tr := requestTrace(logs[1]); tr == nil || tr.TraceId != "463ac35c9f6413ad" || tr.SpanId != "a2fb4a1d1a96d312" ||
			tr.Provider != v3.AccessLogTraceInfoProvider_Zipkin {
			t.Fatalf("b3: %v", tr)
		}
		if tr := requestTrace(logs[2]); tr != nil {
			t.Fatalf("no context: %v", tr)
		}
	})
	t.Run("off", func(t *testing.T) {
		withTraceContext(t, false)
		logs := http1AnalyzeExchanges(t, exchanges).protocolLogs
		if len(logs) != 3 {
			t.Fatalf("%d logs", len(logs))
		}
		for i, l := range logs {
			if tr := requestTrace(l); tr != nil {
				t.Fatalf("log %d: %v", i, tr)
			}
		}
	})
}

// TestHTTP2TraceContext: with access_log.protocol_analyze.analyze_trace_context on, the HTTP/2 logs carry the sw8
// context of their requests; off, none
func TestHTTP2TraceContext(t *testing.T) {
	script := func() *h2cScript {
		s := &h2cScript{}
		client, server := newH2CEndpoint(), newH2CEndpoint()
		in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
		s.call(in, []byte(http2.ClientPreface), false)
		s.call(in, client.settings(), false)
		s.call(out, server.settings(), false)
		s.call(in, client.headers(1, true, append(h2cRequest("/traced"), hpack.HeaderField{Name: "sw8", Value: testSW8})...), false)
		s.call(out, server.headers(1, true, h2cResponse()...), false)
		s.call(in, client.headers(3, true, h2cRequest("/plain")...), false)
		s.call(out, server.headers(3, true, h2cResponse()...), false)
		return s
	}
	for _, on := range []bool{true, false} {
		withTraceContext(t, on)
		logs := h2cAnalyze(t, script().uploads(bpfNow(), false), 1<<30).protocolLogs
		if len(logs) != 2 {
			t.Fatalf("on=%t: %d logs", on, len(logs))
		}
		var traced, plain *v3.AccessLogProtocolLogs
		for _, l := range logs {
			if l.GetHttp().GetRequest().GetPath() == "/traced" {
				traced = l
			} else {
				plain = l
			}
		}
		if traced == nil || plain == nil {
			t.Fatalf("on=%t: logs %v", on, logs)
		}
		tr := requestTrace(traced)
		if on && (tr == nil || tr.TraceId != "trace-1" || tr.TraceSegmentId != "segment-1" || tr.SpanId != "3") {
			t.Fatalf("on: %v", tr)
		}
		if !on && tr != nil {
			t.Fatalf("off: %v", tr)
		}
		if tr := requestTrace(plain); tr != nil {
			t.Fatalf("on=%t, no context: %v", on, tr)
		}
	}
}
