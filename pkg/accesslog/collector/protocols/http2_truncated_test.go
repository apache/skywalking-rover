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
	"bytes"
	"testing"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// feedTruncated delivers one socket call the way BPF does when the call is larger than the upload
// budget: the uploaded chunks, the last of them flagged finished with data left behind, and the real
// length of the call in TotalSize. A 256KB DATA frame written in one syscall arrives exactly so.
func (c *http2TestConn) feedTruncated(direction enums.SocketDataDirection, uploaded []byte, chunk, realLength int) {
	c.dataID++
	dataID, prevDataID, start := c.dataID, c.dataID-1, bpfNow()
	seq := uint16(0)
	for off := 0; off < len(uploaded); off += chunk {
		end := off + chunk
		if end > len(uploaded) {
			end = len(uploaded)
		}
		ev := &aclevents.SocketDataUploadEvent{
			Protocol0: enums.ConnectionProtocolHTTP2, Direction0: direction, Sequence0: seq,
			DataLen: uint16(end - off), StartTime0: start, EndTime0: start,
			ConnectionID: 1, RandomID: 1, DataID0: dataID, PrevDataID0: prevDataID,
			TotalSize0: uint64(realLength),
		}
		if end == len(uploaded) {
			// the upload budget ran out here: the chunk is the last one of the call and the rest of
			// the call was transferred by the kernel but not uploaded
			ev.Finished = 1
			ev.HaveReduce = 1
		}
		copy(ev.Buffer[:], uploaded[off:end])
		c.conn.AppendData(ev)
		seq++
	}
}

// TestHTTP2LargeDataFrameTruncatedByBPF is the case that made h2c unusable with large bodies: Go
// sends a 256KB body as one DATA frame in one write, BPF uploads the first 120KB, and the frame can
// never be completed from the uploaded bytes. The stream must still be reported, with the real body
// size, instead of waiting for a remainder that does not exist.
func TestHTTP2LargeDataFrameTruncatedByBPF(t *testing.T) {
	const bodySize = 262144
	const uploadLimit = 6 * 20480

	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()

	client.preface()
	client.settings()
	client.headers(1, true, requestFields("/download")...)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)

	server.settings()
	server.headers(1, false, responseFields("200")...)
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)

	// the response body: one DATA frame of 256KB written in one syscall, of which BPF uploaded the
	// first 120KB before its chunk budget ran out
	server.data(1, true, bytes.Repeat([]byte("b"), bodySize))
	frame := server.take()
	c.feedTruncated(enums.SocketDataDirectionEgress, frame[:uploadLimit], 20480, len(frame))
	c.analyze()

	if len(c.analyzer.streams) != 1 {
		t.Fatalf("the truncated stream was not reported: got %d streams", len(c.analyzer.streams))
	}
	s := c.analyzer.streams[0]
	if s.status != 200 || s.req[":path"] != "/download" {
		t.Fatalf("stream reported with the wrong metadata: %+v", s)
	}
	if s.respBody != bodySize {
		t.Errorf("response body = %d, want the real length %d", s.respBody, bodySize)
	}
}
