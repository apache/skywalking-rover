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
	"testing"

	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// TestH2CSumTakeInTheKernel takes summaries from a real hash map of h2c_sum_map's shape, with the mode the probe
// picks on this kernel (lookup-and-delete from Linux 5.14, a lookup and a delete before) and with the lookup and
// the delete forced, and requires the same summaries, the entries gone, and the probe key never made
func TestH2CSumTakeInTheKernel(t *testing.T) {
	requireBPF(t)
	for _, forced := range []bool{false, true} {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: events.SummaryKeySize,
			ValueSize: events.SummaryValueSize, MaxEntries: 64})
		if err != nil {
			t.Fatalf("create the map: %v", err)
		}
		s := NewH2CSummaries(m, nil, nil, func(*events.H2CSummary) {})
		ops := s.ops.(*ebpfSumOps)
		if forced {
			ops.mode.Store(sumOpsLookupDelete)
		}
		put := func(stream uint32, d enums.SocketDataDirection, epoch uint8, first, bytes uint64) {
			var k [events.SummaryKeySize]byte
			var v [events.SummaryValueSize]byte
			events.EncodeSummaryKey(k[:], 7, 8, stream, d, epoch)
			events.EncodeSummaryValue(v[:], &events.H2CSummary{FirstDataID0: first, Bytes: bytes, Calls: 3})
			if err := m.Put(k[:], v[:]); err != nil {
				t.Fatal(err)
			}
		}
		in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
		put(3, in, 0, 10, 100)
		put(3, in, 1, 20, 50)
		put(3, out, 0, 30, 70)
		got := s.DrainStream(7, 8, 3, []protocols.HTTP2DrainRequest{{Direction: in, Missing: 150}, {Direction: out, Missing: 70}})
		var total uint64
		for _, sum := range got {
			total += sum.SummaryBytes()
		}
		if len(got) != 3 || total != 220 {
			t.Fatalf("forced=%t: %d summaries of %d bytes, want 3 of 220", forced, len(got), total)
		}
		var key [events.SummaryKeySize]byte
		var value [events.SummaryValueSize]byte
		if it := m.Iterate(); it.Next(&key, &value) {
			t.Fatalf("forced=%t: an entry is left", forced)
		}
		// nothing more to take
		if again := s.DrainStream(7, 8, 3, []protocols.HTTP2DrainRequest{{Direction: in, Missing: 1}}); len(again) != 0 {
			t.Fatalf("forced=%t: took %d summaries twice", forced, len(again))
		}
		mode := ops.mode.Load()
		// the mode logged is what the probe found on this kernel: lookup-and-delete from Linux 5.14
		t.Logf("forced=%t: mode %d (1 lookup-and-delete, 2 lookup then delete), kernel probe found lookup-and-delete: %t",
			forced, mode, mode == sumOpsLookupAndDelete)
		if forced && mode != sumOpsLookupDelete {
			t.Fatalf("the forced mode changed to %d", mode)
		}
		if !forced && mode == sumOpsUnprobed {
			t.Fatalf("not probed")
		}
		m.Close()
	}
}
