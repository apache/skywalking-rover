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
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// peekSample is the raw sample of the socket data event of a receive made with MSG_PEEK that peeked at the bytes of
// the event e (the layout of bpf/accesslog/include/socket_data_event.h; BPF sends no bytes with a peek, the sample
// carries them to show they are not read)
func peekSample(t *testing.T, e *events.SocketDataUploadEvent, dataID uint64) []byte {
	t.Helper()
	data := e.BufferData()
	wire := struct {
		Protocol0                          enums.ConnectionProtocol
		HaveReduce, L4PackageCount, Finish uint8
		Sequence0, DataLen                 uint16
		FunctionName                       uint32
		SSL, H2CFrames0                    uint8
		InFlight                           uint16
		StartTime0, EndTime0, ConnectionID uint64
		RandomID, DataID0, PrevDataID0     uint64
		TotalSize0, L4TotalPackageSize     uint64
		Direction0                         enums.SocketDataDirection
		PayloadSkipped0                    uint8
		LocalPort, RemotePort, DataIDSpan  uint16
		SumBefore, SumStream               uint32
		SumFrames, FirstFrameOff           uint16
	}{Protocol0: enums.ConnectionProtocolHTTP2, L4PackageCount: 1, Finish: 1, DataLen: uint16(len(data)),
		FunctionName: uint32(enums.SocketFunctionNameRecvfrom), StartTime0: e.StartTime0, EndTime0: e.EndTime0,
		ConnectionID: e.ConnectionID, RandomID: e.RandomID, DataID0: dataID, PrevDataID0: e.PrevDataID0,
		TotalSize0: uint64(len(data)), L4TotalPackageSize: uint64(len(data)), Direction0: e.Direction0,
		PayloadSkipped0: events.PayloadPeek, FirstFrameOff: 0xffff}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, &wire); err != nil {
		t.Fatal(err)
	}
	b.Write(data)
	return b.Bytes()
}

// TestPeekAtAHeaderBlockIsNotParsed: a receive that peeks at a HEADERS frame before the receive that consumes it is
// reported as the kernel log of its call alone: the header block is decoded once, so the dynamic table of HPACK
// stays in step and every stream is reported as without the peek
func TestPeekAtAHeaderBlockIsNotParsed(t *testing.T) {
	withH2CSkipDataPayload(t)
	s := &h2cScript{}
	client, server := newH2CEndpoint(), newH2CEndpoint()
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	s.call(in, []byte(http2.ClientPreface), false)
	s.call(in, client.settings(), false)
	s.call(out, server.settings(), false)
	// the second request indexes the header fields the first one added to the dynamic table
	for _, stream := range []uint32{1, 3, 5} {
		s.call(in, client.headers(stream, true, h2cRequest("/peek")...), false)
		s.call(out, server.headers(stream, true, h2cResponse()...), false)
	}
	uploads := s.uploads(bpfNow(), false)

	run := func(peek bool) (protocolLogs []string, peekLogs int) {
		r := newH2CRecordRunner(t, events.SplitH2CBatch)
		for i, u := range uploads {
			if peek && u.event.Direction0 == in && i >= 3 {
				// the server peeks at the request before it receives it
				var e events.SocketDataUploadEvent
				reader := btf.NewReader(peekSample(t, u.event, 1<<40+uint64(i)))
				e.ReadFrom(reader)
				if err := reader.HasError(); err != nil || !e.Peek() {
					t.Fatalf("peek: %v, %+v", err, e)
				}
				if c := copyAdmittedEvent(&e); c != nil {
					r.agentPartition.Consume(c)
				}
			}
			if c := copyAdmittedEvent(u.event); c != nil {
				r.agentPartition.Consume(c)
			}
			r.analyze()
		}
		kernels, protocols := h2cDrainQueue(r.ctx.Queue)
		for _, p := range protocols {
			protocolLogs = append(protocolLogs, string(marshal(t, p.ProtocolLog())))
		}
		for _, k := range kernels {
			if e, ok := k.Event().(*events.SocketDataUploadEvent); ok && e.DataID0 >= 1<<40 &&
				e.GetFunctionName() == enums.SocketFunctionNameRecvfrom {
				peekLogs++
			}
		}
		return protocolLogs, peekLogs
	}
	without, _ := run(false)
	with, peeks := run(true)
	if len(without) != 3 || len(with) != len(without) {
		t.Fatalf("%d logs without the peeks, %d with", len(without), len(with))
	}
	for i := range without {
		if with[i] != without[i] {
			t.Fatalf("log %d differs with the peeks", i)
		}
	}
	if peeks != 3 {
		t.Fatalf("%d kernel logs of the peeks", peeks)
	}
}
