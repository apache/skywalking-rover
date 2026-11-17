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

package sender

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"google.golang.org/protobuf/proto"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// kernelStep is one kernel log a runner appends: an event of a log type, or (message set) a message built
// elsewhere, which AppendKernelLog takes in both batches
type kernelStep struct {
	conn    int
	tp      common.LogType
	event   events.Event
	message func() *v3.AccessLogKernelLog
}

// randomKernelSteps is a flush worth of kernel logs over a few connections: kernel transfer events of every
// function (some without a log), runs of one operation that merge and runs that cross a minute or an
// interface, with connect and close logs and read or write messages (a builder without filler) between them
func randomKernelSteps(rnd *rand.Rand, n int) []kernelStep {
	funcs := []enums.SocketFunctionName{
		enums.SocketFunctionNameRead, enums.SocketFunctionNameReadv, enums.SocketFunctionNameRecvfrom,
		enums.SocketFunctionNameWrite, enums.SocketFunctionNameWritev, enums.SocketFunctionNameSendMsg,
		enums.SocketFunctionNameClose, 0,
	}
	corpus := corpusKernelLogs()
	var steps []kernelStep
	clock := testBootOffset + uint64(55*time.Second)
	for i := 0; i < n; i++ {
		conn := 1 + rnd.Intn(3)
		switch k := rnd.Intn(20); {
		case k == 0:
			c := corpus[13+rnd.Intn(6)] // connect, accept or close
			steps = append(steps, kernelStep{conn: conn, message: func() *v3.AccessLogKernelLog { return cloneKernelLog(c) }})
		case k == 1:
			c := corpus[rnd.Intn(13)] // a read or a write
			steps = append(steps, kernelStep{conn: conn, message: func() *v3.AccessLogKernelLog { return cloneKernelLog(c) }})
		default:
			// a run of one operation: the same function mostly, sometimes another, the clock crossing minutes
			f := funcs[rnd.Intn(len(funcs))]
			for run := 1 + rnd.Intn(5); run > 0; run-- {
				ev := transferEvent(rnd.Intn(1000), f)
				clock += uint64(rnd.Intn(3)) * uint64(time.Second)
				ev.StartTime0, ev.EndTime0 = clock, clock+uint64(rnd.Intn(5000))
				if rnd.Intn(8) == 0 {
					ev.EndTime0 = clock - 100 // an end before the end of the previous call
				}
				if rnd.Intn(10) == 0 {
					ev.StartTime0 += uint64(time.Minute) // a call of another minute
				}
				if rnd.Intn(10) == 0 {
					ev.L4PackageCount = ^uint32(0) // sums that wrap
				}
				steps = append(steps, kernelStep{conn: conn, tp: common.LogTypeKernelTransfer, event: ev})
			}
		}
	}
	return steps
}

func cloneKernelLog(k *v3.AccessLogKernelLog) *v3.AccessLogKernelLog {
	b, err := deterministic.Marshal(k)
	if err != nil {
		panic(err)
	}
	var c v3.AccessLogKernelLog
	if err := proto.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return &c
}

// TestAppendKernelEventLikeTheBuiltLogs: a batch the kernel logs are appended to as events encodes, merged or
// not, the bytes of the batch their built messages are appended to
func TestAppendKernelEventLikeTheBuiltLogs(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	conns := map[int]*common.ConnectionInfo{1: testConnection(1), 2: testConnection(2), 3: testConnection(3)}
	for round := 0; round < 200; round++ {
		steps := randomKernelSteps(rnd, 1+rnd.Intn(60))
		for _, merge := range []bool{false, true} {
			built, direct := newBatchLogs(), newBatchLogs()
			if merge {
				built.EnableKernelLogMerge()
				direct.EnableKernelLogMerge()
			}
			builtCount, directCount := 0, 0
			for _, s := range steps {
				conn := conns[s.conn]
				if s.message != nil {
					built.AppendKernelLog(conn, s.message())
					direct.AppendKernelLog(conn, s.message())
					builtCount++
					directCount++
					continue
				}
				if k := forwarder.BuildKernelLogFromEvent(s.tp, s.event); k != nil {
					built.AppendKernelLog(conn, k)
					builtCount++
				}
				if direct.AppendKernelEvent(conn, s.tp, s.event) {
					directCount++
				}
			}
			what := fmt.Sprintf("round %d merge=%t", round, merge)
			if builtCount != directCount || built.LogCount() != direct.LogCount() {
				t.Fatalf("%s: %d/%d appended, %d/%d logs", what, directCount, builtCount, direct.LogCount(), built.LogCount())
			}
			built.seal()
			direct.seal()
			for id, conn := range conns {
				b, d := built.logs[conn], direct.logs[conn]
				if (b == nil) != (d == nil) {
					t.Fatalf("%s: connection %d only in one batch", what, id)
				}
				if b == nil {
					continue
				}
				if got, want := bytes.Join(d.kernels, nil), bytes.Join(b.kernels, nil); len(d.kernels) != len(b.kernels) || !bytes.Equal(got, want) {
					t.Fatalf("%s: connection %d: %d kernel logs %x, built %d %x", what, id, len(d.kernels), got, len(b.kernels), want)
				}
			}
		}
	}
}

// TestTryMergeTransferLogLikeTheMessages: folding TransferLog values gives the bytes of folding their messages
func TestTryMergeTransferLogLikeTheMessages(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	for i := 0; i < 2000; i++ {
		steps := randomKernelSteps(rnd, 2)
		var evs []events.Event
		for _, s := range steps {
			if s.event != nil {
				evs = append(evs, s.event)
			}
		}
		if len(evs) < 2 {
			continue
		}
		dt, _, dok := forwarder.BuildTransferLog(evs[0])
		st, _, sok := forwarder.BuildTransferLog(evs[1])
		if !dok || !sok {
			continue
		}
		dm := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, evs[0])
		sm := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, evs[1])
		if forwarder.TryMergeTransferLog(&dt, &st) != forwarder.TryMergeKernelLog(dm, sm) {
			t.Fatalf("case %d: merged differently", i)
		}
		var e1, e2 wireEncoder
		e1.transferLog(messageKernelLogsField, &dt)
		e2.kernelLog(messageKernelLogsField, dm)
		if !bytes.Equal(e1.buf, e2.buf) {
			t.Fatalf("case %d: %x, the message %x", i, e1.buf, e2.buf)
		}
	}
}

// TestTransferLogMessageEncodesLikeTheTransferLog: the message a TransferLog becomes for a mixed merge writes
// the bytes of the TransferLog
func TestTransferLogMessageEncodesLikeTheTransferLog(t *testing.T) {
	for i, d := range transferDetails() {
		tl, _, ok := forwarder.BuildTransferLog(d)
		if !ok {
			continue
		}
		var e1, e2 wireEncoder
		e1.transferLog(messageKernelLogsField, &tl)
		e2.kernelLog(messageKernelLogsField, transferLogMessage(&tl))
		if !bytes.Equal(e1.buf, e2.buf) {
			t.Fatalf("detail %d: message %x, TransferLog %x", i, e2.buf, e1.buf)
		}
	}
}
