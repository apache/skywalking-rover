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

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// TestHTTP2HandleWholeStreamIncompleteNoPanic: a stream that reaches HandleWholeStream without a socket call to
// report it with (no buffer, or buffers without events) is an error, not a panic
func TestHTTP2HandleWholeStreamIncompleteNoPanic(t *testing.T) {
	a := NewHTTP2Analyze(nil)
	for name, stream := range map[string]*protocols.HTTP2Streaming{
		"all buffers absent":                      {},
		"present but empty request header buffer": {ReqHeaderBuffer: buffer.NewBuffer()},
	} {
		if err := a.HandleWholeStream(nil, stream); err == nil {
			t.Fatalf("%s: a stream without a socket call is reported", name)
		}
	}
}

// h2cExchangeLogs gives the logs of streams 1, 3, 5... made of the request headers and the response headers of
// each exchange, both ending their side of the stream (no body)
func h2cExchangeLogs(t *testing.T, exchanges [][2][]hpack.HeaderField) []*v3.AccessLogProtocolLogs {
	t.Helper()
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, []byte(http2.ClientPreface), false)
	s.call(in, client.settings(), false)
	s.call(out, server.settings(), false)
	for i, e := range exchanges {
		stream := uint32(2*i + 1)
		s.call(in, client.headers(stream, true, e[0]...), false)
		s.call(out, server.headers(stream, true, e[1]...), false)
	}
	return h2cAnalyze(t, s.uploads(bpfNow(), false), 1<<30).protocolLogs
}

// TestHTTP2HandleWholeStreamReportsWhenBodiless: a stream of request and response headers only (a GET answered
// with a 204 that ends on the HEADERS frame) is reported, with no body
func TestHTTP2HandleWholeStreamReportsWhenBodiless(t *testing.T) {
	logs := h2cExchangeLogs(t, [][2][]hpack.HeaderField{{
		{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/"},
			{Name: ":authority", Value: "example"}},
		{{Name: ":status", Value: "204"}},
	}})
	if len(logs) != 1 {
		t.Fatalf("%d logs", len(logs))
	}
	h := logs[0].GetHttp()
	if h.GetResponse().GetStatusCode() != 204 || h.GetRequest().GetPath() != "/" || h.GetRequest().GetHost() != "example" ||
		h.GetRequest().GetSizeOfBodyBytes() != 0 || h.GetResponse().GetSizeOfBodyBytes() != 0 {
		t.Fatalf("log: %v", h)
	}
}

// TestHTTP2ParseHTTPMethod: an absent method is GET, a lower case one is upper cased, an unknown one is GET
func TestHTTP2ParseHTTPMethod(t *testing.T) {
	cases := []struct {
		method string
		expect v3.AccessLogHTTPProtocolRequestMethod
	}{
		{"", v3.AccessLogHTTPProtocolRequestMethod_Get},
		{"post", v3.AccessLogHTTPProtocolRequestMethod_Post},
		{"patch", v3.AccessLogHTTPProtocolRequestMethod_Patch},
		{"weird", v3.AccessLogHTTPProtocolRequestMethod_Get},
	}
	var exchanges [][2][]hpack.HeaderField
	for _, c := range cases {
		request := []hpack.HeaderField{{Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/" + c.method},
			{Name: ":authority", Value: "example"}}
		if c.method != "" {
			request = append(request, hpack.HeaderField{Name: ":method", Value: c.method})
		}
		exchanges = append(exchanges, [2][]hpack.HeaderField{request, {{Name: ":status", Value: "200"}}})
	}
	logs := h2cExchangeLogs(t, exchanges)
	if len(logs) != len(cases) {
		t.Fatalf("%d logs", len(logs))
	}
	for _, c := range cases {
		found := false
		for _, l := range logs {
			if l.GetHttp().GetRequest().GetPath() == "/"+c.method {
				found = true
				if got := l.GetHttp().GetRequest().GetMethod(); got != c.expect {
					t.Fatalf("method %q: %v, expected %v", c.method, got, c.expect)
				}
			}
		}
		if !found {
			t.Fatalf("method %q: no log", c.method)
		}
	}
}
