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
	"fmt"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

const (
	overloadBody = 256 << 10
	overloadRead = 8 << 10
)

// overloadConn produces the calls the server side of a keep-alive connection sees: a 256KB request read
// 8KB at a time, then a 1KB response written at once
type overloadConn struct {
	id       uint64
	dataID   uint64
	pending  [][]byte
	ingress  int
	messages int
}

func (c *overloadConn) next() ([]byte, enums.SocketDataDirection) {
	if len(c.pending) == 0 {
		c.messages++
		req := []byte(fmt.Sprintf("POST /c%d/m%d HTTP/1.1\r\nHost: stress\r\nContent-Length: %d\r\n\r\n", c.id, c.messages,
			overloadBody) + strings.Repeat("a", overloadBody))
		for off := 0; off < len(req); off += overloadRead {
			c.pending = append(c.pending, req[off:min(off+overloadRead, len(req))])
		}
		c.ingress = len(c.pending)
		c.pending = append(c.pending, []byte("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"+strings.Repeat("b", 1024)))
	}
	data := c.pending[0]
	c.pending = c.pending[1:]
	direction := enums.SocketDataDirectionIngress
	if c.ingress <= 0 {
		direction = enums.SocketDataDirectionEgress
	}
	c.ingress--
	c.dataID++
	return data, direction
}

// overloadRun drives the agent's partition with the agent's events (pooled buffers, metadata copies for
// the kernel logs) through overload rounds (`offered` calls between two analysis passes against a budget
// of `budget` events) and then rounds below the budget. It returns the complete protocol logs of both
// phases and the messages started in them.
func overloadRun(_ *testing.T, budgetEvents int64, offered, overloadRounds, recoveryRounds int) (overDone, overStarted, recDone, recStarted int) {
	ctx := &common.AccessLogContext{
		Queue:         common.NewQueue(1000000, time.Hour, h2cNoopConsumer{}),
		ConnectionMgr: h2cTestConnectionManager(),
		Config:        &common.Config{},
	}
	analyzer := protocols.NewHTTP1Analyzer(ctx, NewHTTP1Analyze(nil, ctx))
	partition := NewPartitionContext(ctx, protocols.NewPartitionContext(ctx, 0, []protocols.Protocol{analyzer}))
	// the default charge of an event is the rover's 20KB array: count the pooled 8KB buffer on top
	buffer.SetMemoryBudget(budgetEvents * (21760 + 64 + overloadRead))
	defer buffer.SetMemoryBudget(0)

	random := rand.New(rand.NewSource(3))
	conns := make([]*overloadConn, 40)
	for i := range conns {
		conns[i] = &overloadConn{id: uint64(i + 1)}
	}
	complete := func() int {
		_, logs := h2cDrainQueue(ctx.Queue)
		n := 0
		for _, l := range logs {
			http := l.ProtocolLog().GetHttp()
			if http != nil && http.Request.SizeOfBodyBytes == overloadBody && http.Response.StatusCode == 200 &&
				len(l.RelateKernelLogs()) == overloadBody/overloadRead+2 {
				n++
			}
		}
		return n
	}
	started := func() int {
		n := 0
		for _, c := range conns {
			n += c.messages
		}
		return n
	}
	round := func(calls int) {
		for i := 0; i < calls; i++ {
			c := conns[random.Intn(len(conns))]
			data, direction := c.next()
			if !buffer.AcquireEvent() {
				protocols.NoteProtectionDrop(c.id, c.id, enums.ConnectionProtocolHTTP, false, c.dataID, 0,
					protocols.IsHTTP1RequestLine(data))
				continue
			}
			ev := &events.SocketDataUploadEvent{Protocol0: enums.ConnectionProtocolHTTP, Direction0: direction,
				Finished: 1, L4PackageCount: 1, DataLen: uint16(len(data)), StartTime0: bpfNow(), EndTime0: bpfNow(),
				ConnectionID: c.id, RandomID: c.id, DataID0: c.dataID, PrevDataID0: c.dataID - 1,
				TotalSize0: uint64(len(data)), FunctionName: 1}
			ev.Buffer = buffer.TakeBuffer(len(data))
			copy(ev.Buffer, data)
			partition.Consume(ev)
		}
		partition.AnalyzeNewData()
	}
	for i := 0; i < overloadRounds; i++ {
		round(offered)
		overDone += complete()
	}
	overStarted = started()
	for i := 0; i < recoveryRounds; i++ {
		round(offered / 4)
		recDone += complete()
	}
	recStarted = started() - overStarted
	for _, c := range conns {
		partition.GetConnectionContext(c.id, c.id, enums.ConnectionProtocolHTTP, 1).ReleasePendingData()
	}
	return
}

// TestGapHandlingWithAgentEvents: under overload the protocol logs that come out are whole (every call of
// the message as a kernel log), after it every message completes, and the events in use go back to
// where they were
func TestGapHandlingWithAgentEvents(t *testing.T) {
	inUse, _, _, _ := buffer.MemoryStats()
	overDone, overStarted, recDone, recStarted := overloadRun(t, 600, 2000, 40, 40)
	t.Logf("agent events: %d of %d messages complete under overload (the budget holds 30%% of a round), %d of %d after",
		overDone, overStarted, recDone, recStarted)
	if overDone == 0 {
		t.Fatal("nothing completed under overload")
	}
	// the messages in flight at the end of the run are the only ones missing
	if recDone < recStarted-2*40 {
		t.Fatalf("only %d of %d messages completed after the overload", recDone, recStarted)
	}
	if after, _, _, _ := buffer.MemoryStats(); after != inUse {
		t.Fatalf("events in use %d after the connections were released, %d before", after, inUse)
	}
}
