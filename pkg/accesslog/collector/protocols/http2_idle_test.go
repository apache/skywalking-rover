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
	"time"
)

// openTestStream opens a stream created at the given time, as handleHeaderBlock does
func openTestStream(m *HTTP2Metrics, id uint32, created time.Time) *HTTP2Streaming {
	streaming := &HTTP2Streaming{age: http2Aged{created: created}}
	m.addStream(id, streaming)
	return streaming
}

// TestHTTP2DropIdleStreams drops exactly the streams and pending header blocks created more than
// maxHTTP2StreamIdleTime ago, never one that finished, and keeps the age lists in step with the maps
func TestHTTP2DropIdleStreams(t *testing.T) {
	r := &HTTP2Protocol{}
	m := r.GenerateConnection(1, 1).(*HTTP2Metrics)
	now := time.Now()
	old := now.Add(-maxHTTP2StreamIdleTime - time.Second)
	for id := uint32(1); id <= 9; id += 2 {
		openTestStream(m, id, old)
	}
	for id := uint32(11); id <= 15; id += 2 {
		openTestStream(m, id, now)
	}
	// a finished old stream and an RST one leave the list as well
	m.deleteStream(3)
	m.deleteStream(7)
	m.setPending(5, &http2PendingHeaders{age: http2Aged{created: old}})
	m.setPending(21, &http2PendingHeaders{age: http2Aged{created: old}})
	m.setPending(23, &http2PendingHeaders{age: http2Aged{created: now}})
	// replacing a pending block unlinks the one it replaces
	m.setPending(23, &http2PendingHeaders{age: http2Aged{created: now}})
	r.dropIdleStreams(m)
	var open []uint32
	for a := m.streamAges.head; a != nil; a = a.next {
		open = append(open, a.id)
		if m.Streams[a.id] == nil || &m.Streams[a.id].age != a {
			t.Fatalf("stream %d is linked but not open", a.id)
		}
	}
	if fmt.Sprint(open) != "[11 13 15]" || len(m.Streams) != 3 {
		t.Fatalf("open streams %v (%d in the map), expected [11 13 15]", open, len(m.Streams))
	}
	var pending []uint32
	for a := m.pendingAges.head; a != nil; a = a.next {
		pending = append(pending, a.id)
	}
	if fmt.Sprint(pending) != "[23]" || len(m.pendingHeaders) != 1 {
		t.Fatalf("pending blocks %v (%d in the map), expected [23]", pending, len(m.pendingHeaders))
	}
	m.deleteStream(13)
	m.deleteStream(11)
	m.deleteStream(15)
	if m.streamAges.head != nil || m.streamAges.tail != nil {
		t.Fatalf("the age list is not empty once every stream is gone")
	}
}
