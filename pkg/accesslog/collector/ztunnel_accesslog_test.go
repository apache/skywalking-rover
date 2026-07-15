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

package collector

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExtractLogField(t *testing.T) {
	cases := []struct{ name, s, key, want string }{
		{"space terminated", `x src.addr=1.2.3.4:5 y`, "src.addr=", "1.2.3.4:5"},
		{"tab terminated", "x\tsrc.addr=1.2.3.4:5\ty", "src.addr=", "1.2.3.4:5"},
		{"end of string", `x src.addr=1.2.3.4:5`, "src.addr=", "1.2.3.4:5"},
		{"missing key", `x dst.addr=9`, "src.addr=", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractLogField(c.s, c.key); got != c.want {
				t.Fatalf("extractLogField(%q, %q) = %q, want %q", c.s, c.key, got, c.want)
			}
		})
	}
}

func TestHandleAccessLogLine(t *testing.T) {
	srcKey := func(z *ZTunnelCollector) string { return z.buildSrcOnlyCacheKey("10.0.0.5", 45000) }

	t.Run("json outbound connection complete fills the src-only mapping", func(t *testing.T) {
		z := NewZTunnelCollector(time.Minute)
		z.handleAccessLogLine(`2024-01-01T00:00:00Z stdout F {"src.addr":"10.0.0.5:45000",` +
			`"dst.hbone_addr":"10.244.0.20:9080","direction":"outbound","message":"connection complete"}` + "\n")
		obj, ok := z.ipMappingCache.Get(srcKey(z))
		if !ok {
			t.Fatal("expected a src-only mapping to be cached")
		}
		addr := obj.(*ZTunnelLoadBalanceAddress)
		if addr.IP != "10.244.0.20" || addr.Port != 9080 || addr.Source != sourceAccessLog {
			t.Fatalf("unexpected cached mapping: %+v", addr)
		}
		if z.accessLogParsedCount.Load() != 1 {
			t.Fatalf("accessLogParsedCount = %d, want 1", z.accessLogParsedCount.Load())
		}
	})

	t.Run("dst.hbone_addr is preferred but falls back to dst.addr", func(t *testing.T) {
		z := NewZTunnelCollector(time.Minute)
		z.handleAccessLogLine(`2024-01-01T00:00:00Z stdout F {"src.addr":"10.0.0.5:45000",` +
			`"dst.addr":"10.244.0.30:9080","direction":"outbound","message":"connection opened"}` + "\n")
		obj, ok := z.ipMappingCache.Get(srcKey(z))
		if !ok || obj.(*ZTunnelLoadBalanceAddress).IP != "10.244.0.30" {
			t.Fatal("expected the dst.addr fallback to be used when dst.hbone_addr is absent")
		}
	})

	t.Run("plain istio key=value format is parsed", func(t *testing.T) {
		z := NewZTunnelCollector(time.Minute)
		z.handleAccessLogLine("2024-01-01T00:00:00Z stdout F 2024-01-01\tinfo\taccess\tconnection complete " +
			"src.addr=10.0.0.5:45000 dst.hbone_addr=10.244.0.20:9080 direction=\"outbound\"\n")
		if _, ok := z.ipMappingCache.Get(srcKey(z)); !ok {
			t.Fatal("expected the plain-format access log line to be parsed")
		}
	})

	t.Run("docker json-file runtime format is parsed", func(t *testing.T) {
		z := NewZTunnelCollector(time.Minute)
		// the legacy docker json-file runtime wraps each line as {"log":"<payload>\n","stream":..,"time":..}
		inner := `{"src.addr":"10.0.0.5:45000","dst.hbone_addr":"10.244.0.20:9080",` +
			`"direction":"outbound","message":"connection complete"}`
		wrapper, err := json.Marshal(map[string]string{"log": inner + "\n", "stream": "stdout", "time": "2024-01-01T00:00:00Z"})
		if err != nil {
			t.Fatal(err)
		}
		z.handleAccessLogLine(string(wrapper) + "\n")
		obj, ok := z.ipMappingCache.Get(srcKey(z))
		if !ok || obj.(*ZTunnelLoadBalanceAddress).IP != "10.244.0.20" {
			t.Fatal("expected the docker json-file wrapped access log line to be parsed")
		}
	})

	// none of these malformed / non-matching lines should panic or create a cache entry
	reject := []struct{ name, line string }{
		{"partial CRI line (P not F)", `2024-01-01T00:00:00Z stdout P {"src.addr":"10.0.0.5:45000","dst.addr":"10.244.0.20:9080","direction":"outbound","message":"connection complete"}`},
		{"too few CRI fields", `2024-01-01T00:00:00Z stdout`},
		{"inbound direction", `2024-01-01T00:00:00Z stdout F {"src.addr":"10.0.0.5:45000","dst.addr":"10.244.0.20:9080","direction":"inbound","message":"connection complete"}`},
		{"not a connection message", `2024-01-01T00:00:00Z stdout F {"src.addr":"10.0.0.5:45000","dst.addr":"10.244.0.20:9080","direction":"outbound","message":"hello"}`},
		{"loopback pod dropped", `2024-01-01T00:00:00Z stdout F {"src.addr":"10.0.0.5:45000","dst.addr":"127.0.0.1:9080","direction":"outbound","message":"connection complete"}`},
		{"truncated json", `2024-01-01T00:00:00Z stdout F {"src.addr":"10.0.0.5:45000"`},
		{"missing addresses", `2024-01-01T00:00:00Z stdout F {"direction":"outbound","message":"connection complete"}`},
		{"empty payload", `2024-01-01T00:00:00Z stdout F `},
	}
	for _, c := range reject {
		t.Run("reject "+c.name, func(t *testing.T) {
			z := NewZTunnelCollector(time.Minute)
			z.handleAccessLogLine(c.line + "\n")
			if z.ipMappingCache.Len() != 0 {
				t.Fatalf("expected no cache entry for a rejected line: %q", c.line)
			}
		})
	}

	t.Run("does not overwrite a live uprobe mapping", func(t *testing.T) {
		z := NewZTunnelCollector(time.Minute)
		key := z.buildSrcOnlyCacheKey("10.0.0.5", 45000)
		z.ipMappingCache.Set(key, &ZTunnelLoadBalanceAddress{IP: "10.244.0.99", Port: 9080, Source: sourceConnectionResult}, time.Minute)
		z.handleAccessLogLine(`2024-01-01T00:00:00Z stdout F {"src.addr":"10.0.0.5:45000",` +
			`"dst.addr":"10.244.0.20:9080","direction":"outbound","message":"connection complete"}` + "\n")
		obj, _ := z.ipMappingCache.Get(key)
		addr := obj.(*ZTunnelLoadBalanceAddress)
		if addr.IP != "10.244.0.99" || addr.Source != sourceConnectionResult {
			t.Fatalf("the access-log fallback must not overwrite a live uprobe mapping, got %+v", addr)
		}
	})
}
