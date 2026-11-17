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
	"fmt"
	"testing"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// feedSkipped delivers one socket call that BPF uploaded without its content because it lies inside an
// HTTP/1 body (skip_http1_body_payload_bpf): data_len 0, the size of the call as the total size
func (c *http1TestConn) feedSkipped(direction enums.SocketDataDirection, size int) {
	c.dataID++
	c.conn.AppendData(&aclevents.SocketDataUploadEvent{
		Protocol0: enums.ConnectionProtocolHTTP, Direction0: direction, Finished: 1, PayloadSkipped0: 1,
		StartTime0: bpfNow(), EndTime0: bpfNow(), ConnectionID: 1, RandomID: 1, DataID0: c.dataID,
		PrevDataID0: c.dataID - 1, TotalSize0: uint64(size),
	})
}

// TestHTTP1BodySkippedByBPF: the calls of Content-Length bodies BPF uploaded without their content count
// into the body sizes as the calls with their bytes do, the messages behind them are read in step, and the
// skipped calls stay calls of the body (for the kernel log details)
func TestHTTP1BodySkippedByBPF(t *testing.T) {
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	for _, every := range []int{1, 2, 1000} {
		c := newHTTP1TestConn(t)
		step := 0
		maybeAnalyze := func() {
			step++
			if step%every == 0 {
				c.analyze()
			}
		}
		for i := 0; i < 3; i++ {
			// the request head with the first body bytes, then two calls inside the body
			c.feed(in, http1Request("/upload", 30000)[:len(http1Request("/upload", 0))+1000], 6)
			maybeAnalyze()
			c.feedSkipped(in, 20000)
			maybeAnalyze()
			c.feedSkipped(in, 9000)
			maybeAnalyze()
			// the response head alone, a skipped call, and the last bytes with their content
			head := http1Response(40960)
			c.feed(out, head[:len(head)-40960], 6)
			maybeAnalyze()
			c.feedSkipped(out, 40000)
			maybeAnalyze()
			c.feed(out, make([]byte, 960), 6)
			maybeAnalyze()
		}
		c.analyze()
		want := "[POST /upload -> 200 req=30000 resp=40960 POST /upload -> 200 req=30000 resp=40960 POST /upload -> 200 req=30000 resp=40960]"
		if fmt.Sprint(c.analyzer.handled) != want {
			t.Fatalf("every %d: %v", every, c.analyzer.handled)
		}
		if c.pending() != 0 {
			t.Fatalf("every %d: %d events left", every, c.pending())
		}
		// the response body: the skipped call and the last one
		if len(c.analyzer.details) != 2 || c.analyzer.details[0].TotalSize() != 40000 {
			t.Fatalf("every %d: the body calls are %d", every, len(c.analyzer.details))
		}
	}
}
