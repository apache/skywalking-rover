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

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// withL24Store sets a store with the L2 to L4 details of about two thirds of the calls of connection 1 (random id 1)
// with the data ids 1 to maxID, as the tests' transferEvent makes them, on one of three interfaces (0 included), but those
// of the corpus' merged logs
func withL24Store(t *testing.T, rnd *rand.Rand, maxID int) {
	t.Helper()
	store := events.NewL24Store(1<<20, time.Hour, time.Hour)
	for id := 1; id <= maxID; id++ {
		// (the calls 101 to 106 of the corpus are merged into two logs by corpusKernelLogs: one interface)
		if rnd.Intn(3) == 0 || (id > 100 && id <= 106) {
			continue
		}
		v := func() uint64 { return uint64(rnd.Int63n(1 << 40)) }
		m := events.L24Metrics{
			L4Duration: v(), L3Duration: v(), L3RcvDuration: v(), L3LocalDuration: v(), L3OutputDuration: v(),
			L3ResolveMacDuration: v(), L3NetFilterDuration: v(), L2Duration: v(), L2ReadySendDuration: v(),
			L2SendDuration: v(), L2PackageToQueueDuration: v(), L2RcvPackageFromQueueDuration: v(),
			IfIndex: uint32(rnd.Intn(3)), L3ResolveMacCount: uint32(rnd.Intn(3)), L3NetFilterCount: uint32(rnd.Intn(5)),
			L2EnterQueueCount: uint32(rnd.Intn(4)), L4RetransmitPackageCount: uint32(rnd.Intn(3)),
		}
		if rnd.Intn(4) != 0 {
			m.L4TransmitPackageCount = uint32(1 + rnd.Intn(40))
			m.L4TransmitPackageSize = uint64(rnd.Int63n(1 << 31))
		}
		store.Put(events.L24Key{ConnectionID: 1, RandomID: 1, DataID: uint64(id)}, &m)
	}
	events.SetL24Store(store)
	t.Cleanup(func() { events.SetL24Store(nil) })
}

// TestL24KernelEventsLikeTheBuiltLogs: with the L2 to L4 details of the calls, a batch the kernel logs are appended to
// as events encodes, merged or not, the bytes of the batch their built messages are appended to: the TransferLog of a
// call and its fold give the messages of its log and their merge (by the interface, with every metric summed)
func TestL24KernelEventsLikeTheBuiltLogs(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))
	withL24Store(t, rnd, 1000)
	conns := map[int]*common.ConnectionInfo{1: testConnection(1), 2: testConnection(2), 3: testConnection(3)}
	merged := 0
	for round := 0; round < 200; round++ {
		steps := randomKernelSteps(rnd, 1+rnd.Intn(60))
		for _, merge := range []bool{false, true} {
			built, direct := newBatchLogs(), newBatchLogs()
			if merge {
				built.EnableKernelLogMerge()
				direct.EnableKernelLogMerge()
			}
			builtCount := 0
			for _, s := range steps {
				conn := conns[s.conn]
				if s.message != nil {
					built.AppendKernelLog(conn, s.message())
					direct.AppendKernelLog(conn, s.message())
					builtCount++
					continue
				}
				if k := forwarder.BuildKernelLogFromEvent(s.tp, s.event); k != nil {
					built.AppendKernelLog(conn, k)
					builtCount++
				}
				direct.AppendKernelEvent(conn, s.tp, s.event)
			}
			what := fmt.Sprintf("round %d merge=%t", round, merge)
			if built.LogCount() != direct.LogCount() {
				t.Fatalf("%s: %d logs, built %d", what, direct.LogCount(), built.LogCount())
			}
			built.seal()
			direct.seal()
			if merge {
				merged += builtCount - built.LogCount()
			}
			for id, conn := range conns {
				b, d := built.logs[conn], direct.logs[conn]
				if (b == nil) != (d == nil) {
					t.Fatalf("%s: connection %d only in one batch", what, id)
				}
				if b == nil {
					continue
				}
				if got, want := bytes.Join(d.kernels, nil), bytes.Join(b.kernels, nil); !bytes.Equal(got, want) {
					t.Fatalf("%s: connection %d: kernel logs %x, built %x", what, id, got, want)
				}
			}
		}
	}
	if merged == 0 {
		t.Fatal("no log was merged")
	}
}

// TestL24TransferLogsEncodedAsTheBuiltLogs: the kernel logs of a protocol log with the L2 to L4 details of their calls,
// written straight from the details, are the bytes of the built logs
func TestL24TransferLogsEncodedAsTheBuiltLogs(t *testing.T) {
	withL24Store(t, rand.New(rand.NewSource(5)), 100000)
	details := transferDetails()
	withDetails := 0
	for _, d := range details {
		if _, ok := events.LookupL24(d); ok {
			withDetails++
		}
	}
	if withDetails == 0 {
		t.Fatal("no detail has L2 to L4 details")
	}
	for _, covered := range []bool{true, false} {
		wireEncodingCovered = covered
		for i, d := range details {
			assertTransferEncodedLikeTheBuiltLogs(t, fmt.Sprintf("covered=%t detail %d", covered, i), []events.SocketDetail{d}, nil)
		}
		for i, p := range corpusProtocolLogs() {
			assertTransferEncodedLikeTheBuiltLogs(t, fmt.Sprintf("covered=%t protocol log %d", covered, i), details, p)
		}
	}
	wireEncodingCovered = true
}

// TestProtocolKernelLogMerge: with EnableProtocolKernelLogMerge the kernel logs of a protocol log are encoded as the
// merge of the built logs (forwarder.MergeKernelLogs: one record per operation and interface, every metric summed),
// written straight or through the messages; without it, one by one
func TestProtocolKernelLogMerge(t *testing.T) {
	rnd := rand.New(rand.NewSource(9))
	withL24Store(t, rnd, 1000)
	conn := testConnection(1)
	merges := 0
	for round := 0; round < 300; round++ {
		var details []events.SocketDetail
		clock := testBootOffset + uint64(50*time.Second)
		funcs := []enums.SocketFunctionName{enums.SocketFunctionNameRead, enums.SocketFunctionNameWrite,
			enums.SocketFunctionNameWritev, enums.SocketFunctionNameClose}
		f := funcs[rnd.Intn(len(funcs))]
		for i := 1 + rnd.Intn(12); i > 0; i-- {
			if rnd.Intn(4) == 0 {
				f = funcs[rnd.Intn(len(funcs))]
			}
			e := transferEvent(rnd.Intn(1000), f)
			clock += uint64(rnd.Intn(4)) * uint64(time.Second)
			e.StartTime0, e.EndTime0 = clock, clock+uint64(rnd.Intn(3000))
			details = append(details, e)
		}
		protocol := corpusProtocolLogs()[rnd.Intn(len(corpusProtocolLogs()))]
		for _, covered := range []bool{true, false} {
			wireEncodingCovered = covered
			kernels := forwarder.MergeKernelLogs(builtKernelLogs(details))
			want, err := deterministic.Marshal(&v3.EBPFAccessLogMessage{KernelLogs: kernels, ProtocolLog: protocol})
			if err != nil {
				t.Fatal(err)
			}
			batch := newBatchLogs()
			batch.EnableProtocolKernelLogMerge()
			count := batch.AppendTransferProtocolLog(conn, details, protocol)
			if len(kernels) == 0 {
				if count != 0 {
					t.Fatalf("round %d: %d logs of none", round, count)
				}
				continue
			}
			got := batch.logs[conn].protocols[0]
			if count != len(kernels) || !bytes.Equal(got, want) {
				t.Fatalf("round %d covered=%t: %d logs %x, the merged %d %x", round, covered, count, got, len(kernels), want)
			}
			merges += len(builtKernelLogs(details)) - len(kernels)
		}
	}
	wireEncodingCovered = true
	if merges == 0 {
		t.Fatal("nothing was merged")
	}
}
