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

// Benchmarks for protocol_analyze.trigger_events: how much analysis a trigger value costs for the same
// traffic. Run with: go test -run XXX -bench BenchmarkTrigger -benchtime 10x ./pkg/accesslog/collector/protocols/
package protocols

import (
	"fmt"
	"testing"
	"time"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	cmap "github.com/orcaman/concurrent-map"
)

// benchTrigger feeds a fixed number of HTTP/1 request/response pairs spread over `conns` connections of
// one partition and reports the analysis passes and the wall time for a trigger setting.
func benchTrigger(b *testing.B, trigger int64, conns, pairs int) {
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		analyzer := &recordingHTTP1{}
		proto := NewHTTP1Analyzer(nil, analyzer)
		p := &PartitionContext{triggerEvents: trigger, connections: cmap.New()}
		for c := 1; c <= conns; c++ {
			p.connections.Set(fmt.Sprintf("%d_1", c), &PartitionConnection{
				connectionID:       uint64(c),
				randomID:           1,
				dataBuffers:        map[enums.ConnectionProtocol]*buffer.Buffer{enums.ConnectionProtocolHTTP: buffer.NewBuffer()},
				protocol:           map[enums.ConnectionProtocol]uint64{enums.ConnectionProtocolHTTP: 0},
				protocolAnalyzer:   map[enums.ConnectionProtocol]Protocol{enums.ConnectionProtocolHTTP: proto},
				protocolMetrics:    map[enums.ConnectionProtocol]ProtocolMetrics{enums.ConnectionProtocolHTTP: proto.GenerateConnection(uint64(c), 1)},
				lastCheckCloseTime: time.Now(),
			})
		}
		req := http1Request("/api/stress", 1024)
		resp := http1Response(1024)
		dataID := uint64(0)
		passes := 0
		feed := func(con *PartitionConnection, dir enums.SocketDataDirection, data []byte) {
			dataID++
			ev := &aclevents.SocketDataUploadEvent{
				Protocol0: enums.ConnectionProtocolHTTP, Direction0: dir, Sequence0: 0,
				DataLen: uint16(len(data)), StartTime0: bpfNow(), EndTime0: bpfNow(), Finished: 1,
				ConnectionID: con.connectionID, RandomID: 1, DataID0: dataID, PrevDataID0: dataID - 1,
				TotalSize0: uint64(len(data)),
			}
			copy(ev.Buffer[:], data)
			con.AppendData(ev)
			if p.NoteDataEvent() {
				passes++
				p.processEventsOfNewData()
			}
		}
		b.StartTimer()
		for i := 0; i < pairs; i++ {
			con, _ := p.connections.Get(fmt.Sprintf("%d_1", i%conns+1))
			c := con.(*PartitionConnection)
			feed(c, enums.SocketDataDirectionIngress, req)
			feed(c, enums.SocketDataDirectionEgress, resp)
		}
		p.ProcessEvents() // the periodic tick
		passes++
		b.StopTimer()
		if n == 0 {
			b.ReportMetric(float64(passes), "passes")
			b.ReportMetric(float64(len(analyzer.handled)), "messages")
		}
		b.StartTimer()
	}
}

func BenchmarkTrigger0(b *testing.B)    { benchTrigger(b, 0, 30, 2000) }
func BenchmarkTrigger50(b *testing.B)   { benchTrigger(b, 50, 30, 2000) }
func BenchmarkTrigger200(b *testing.B)  { benchTrigger(b, 200, 30, 2000) }
func BenchmarkTrigger1000(b *testing.B) { benchTrigger(b, 1000, 30, 2000) }
func BenchmarkTrigger4000(b *testing.B) { benchTrigger(b, 4000, 30, 2000) }
