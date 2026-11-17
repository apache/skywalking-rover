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
	"strings"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// TestHTTP1BodilessResponsesDoNotSwallowTheConnection: a response that cannot carry a body (the
// response to HEAD, 1xx, 204, 304) must be reported as it is, even when it announces a
// Content-Length. Consuming the announced body would eat the following messages of the keep-alive
// connection and no access log would be produced for them anymore.
func TestHTTP1BodilessResponsesDoNotSwallowTheConnection(t *testing.T) {
	for _, tt := range []struct{ name, request, response string }{
		{"head", "HEAD /h HTTP/1.1\r\nHost: h\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"},
		{"not-modified", "GET /n HTTP/1.1\r\nHost: h\r\n\r\n", "HTTP/1.1 304 Not Modified\r\nContent-Length: 1000\r\n\r\n"},
		{"no-content", "DELETE /d HTTP/1.1\r\nHost: h\r\n\r\n", "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newHTTP1TestConn(t)
			c.feed(enums.SocketDataDirectionIngress, []byte(tt.request), 6)
			c.feed(enums.SocketDataDirectionEgress, []byte(tt.response), 6)
			c.analyze()
			for i := 0; i < 2; i++ {
				c.feed(enums.SocketDataDirectionIngress, http1Request("/api/next", 16), 6)
				c.feed(enums.SocketDataDirectionEgress, http1Response(16), 6)
				c.analyze()
			}
			if len(c.analyzer.handled) != 3 {
				t.Fatalf("the bodiless response must not swallow the connection, handled: %v", c.analyzer.handled)
			}
			if !strings.HasSuffix(c.analyzer.handled[0], "resp=0") {
				t.Fatalf("the response has no body by definition, got %q", c.analyzer.handled[0])
			}
			if c.pending() != 0 {
				t.Fatalf("%d events still pending", c.pending())
			}
		})
	}
}

// TestHTTP1RequestHeadersInTwoSocketCalls: the events the headers were read from must be released
// before the body consumer starts. They are in front of the body in the connection buffer, and every
// analyze round restarts at the front of it, so a leftover header event is parsed again together
// with the live data and the message behind it is skipped.
func TestHTTP1RequestHeadersInTwoSocketCalls(t *testing.T) {
	c := newHTTP1TestConn(t)
	c.feed(enums.SocketDataDirectionIngress, []byte("POST /split HTTP/1.1\r\nHost: h\r\n"), 6)
	c.feed(enums.SocketDataDirectionIngress, []byte("Content-Length: 5\r\n\r\nhello"), 6)
	c.feed(enums.SocketDataDirectionEgress, http1Response(8), 6)
	c.analyze()
	if len(c.analyzer.handled) != 1 {
		t.Fatalf("the exchange was not handled: %v", c.analyzer.handled)
	}
	if c.pending() != 0 {
		t.Fatalf("%d events still pending after the exchange", c.pending())
	}
	// the connection keeps working
	c.feed(enums.SocketDataDirectionIngress, http1Request("/api/next", 16), 6)
	c.feed(enums.SocketDataDirectionEgress, http1Response(16), 6)
	c.analyze()
	if len(c.analyzer.handled) != 2 || c.pending() != 0 {
		t.Fatalf("the next exchange failed: %v pending=%d", c.analyzer.handled, c.pending())
	}
}

// TestHTTP1PendingBodyStopsAtTheOtherDirection: when an event of a body is lost, the data of the
// other direction must not be consumed as the rest of the body
func TestHTTP1PendingBodyStopsAtTheOtherDirection(t *testing.T) {
	c := newHTTP1TestConn(t)
	// the request announces 100000 body bytes but only a part of them arrives
	c.feed(enums.SocketDataDirectionIngress, http1Request("/api/lost", 100000)[:1024], 6)
	c.analyze()
	c.feed(enums.SocketDataDirectionEgress, http1Response(16), 6)
	c.analyze()
	if len(c.analyzer.handled) != 1 {
		t.Fatalf("the exchange must be reported instead of the response being eaten as body: %v", c.analyzer.handled)
	}
}
