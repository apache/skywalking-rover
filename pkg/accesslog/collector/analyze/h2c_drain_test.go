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
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"math/rand"
	"reflect"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// fakeSumMap is h2c_sum_map for the drain tests: the entries by key, and the takes it saw
type fakeSumMap struct {
	entries map[[events.SummaryKeySize]byte][events.SummaryValueSize]byte
	takes   int
}

func (f *fakeSumMap) lookupAndDelete(key, value unsafe.Pointer) error {
	f.takes++
	k := *(*[events.SummaryKeySize]byte)(key)
	v, ok := f.entries[k]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	*(*[events.SummaryValueSize]byte)(value) = v
	return nil
}

func (f *fakeSumMap) put(stream uint32, d enums.SocketDataDirection, epoch uint8, first, bytes uint64) {
	var k [events.SummaryKeySize]byte
	var v [events.SummaryValueSize]byte
	events.EncodeSummaryKey(k[:], 7, 8, stream, d, epoch)
	events.EncodeSummaryValue(v[:], &events.H2CSummary{FirstDataID0: first, Bytes: bytes, Calls: 1})
	f.entries[k] = v
}

func newFakeSummaries() (*H2CSummaries, *fakeSumMap) {
	f := &fakeSumMap{entries: make(map[[events.SummaryKeySize]byte][events.SummaryValueSize]byte)}
	return &H2CSummaries{ops: f, closed: make(map[[2]uint64]struct{})}, f
}

func drainBytes(sums []protocols.HTTP2Summary) (total uint64, ids []uint64) {
	for _, s := range sums {
		total += s.SummaryBytes()
		ids = append(ids, s.SummaryFirstDataID())
	}
	return total, ids
}

// TestDrainStreamCurrentEpochFirst: the entry of the current epoch is taken first, and the other epoch is not
// looked up when it brought exactly the missing bytes
func TestDrainStreamCurrentEpochFirst(t *testing.T) {
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	for _, epoch := range []uint32{0, 1} {
		s, f := newFakeSummaries()
		s.epoch.Store(epoch)
		f.put(3, in, uint8(epoch), 100, 5000)
		got := s.DrainStream(7, 8, 3, []protocols.HTTP2DrainRequest{{Direction: in, Missing: 5000}})
		if total, _ := drainBytes(got); total != 5000 || f.takes != 1 {
			t.Fatalf("epoch %d: %d bytes in %d takes, want 5000 in 1", epoch, total, f.takes)
		}
	}

	// a stream across a flip: both entries are needed, in both directions
	s, f := newFakeSummaries()
	s.epoch.Store(1)
	f.put(5, in, 0, 10, 300)
	f.put(5, in, 1, 20, 700)
	f.put(5, out, 1, 30, 50)
	got := s.DrainStream(7, 8, 5, []protocols.HTTP2DrainRequest{{Direction: in, Missing: 1000}, {Direction: out, Missing: 50}})
	if total, _ := drainBytes(got); total != 1050 || len(f.entries) != 0 || f.takes != 3 {
		t.Fatalf("across a flip: %d bytes, %d entries left, %d takes", total, len(f.entries), f.takes)
	}

	// a first entry that brings fewer bytes than missing (the rest is in a BPF batch on its way, or the other
	// epoch): the other epoch is looked up
	s, f = newFakeSummaries()
	f.put(9, in, 0, 10, 300)
	got = s.DrainStream(7, 8, 9, []protocols.HTTP2DrainRequest{{Direction: in, Missing: 1000}})
	if total, _ := drainBytes(got); total != 300 || f.takes != 2 {
		t.Fatalf("incomplete: %d bytes in %d takes", total, f.takes)
	}

	// Missing 0 (a reset stream: not known): both epochs
	s, f = newFakeSummaries()
	f.put(11, in, 0, 10, 300)
	f.put(11, in, 1, 40, 30)
	got = s.DrainStream(7, 8, 11, []protocols.HTTP2DrainRequest{{Direction: in}, {Direction: out}})
	if total, _ := drainBytes(got); total != 330 || f.takes != 4 {
		t.Fatalf("unknown missing: %d bytes in %d takes", total, f.takes)
	}
}

// TestDrainStreamLeavesTheRestForTheFlush: the other epoch is not looked up when the first entry completed the
// direction, so an entry there (it must never happen) stays for the epoch flush
func TestDrainStreamLeavesTheRestForTheFlush(t *testing.T) {
	in := enums.SocketDataDirectionIngress
	s, f := newFakeSummaries()
	f.put(13, in, 0, 100, 5000)
	f.put(13, in, 1, 200, 1)
	got := s.DrainStream(7, 8, 13, []protocols.HTTP2DrainRequest{{Direction: in, Missing: 5000}})
	if total, _ := drainBytes(got); total != 5000 || len(f.entries) != 1 || f.takes != 1 {
		t.Fatalf("%d bytes, %d entries left, %d takes", total, len(f.entries), f.takes)
	}
}

// TestDrainStreamDecodes: a drained summary carries the key, the value and the reason, as the take before
func TestDrainStreamDecodes(t *testing.T) {
	s, f := newFakeSummaries()
	f.put(21, enums.SocketDataDirectionEgress, 0, 77, 123)
	got := s.DrainStream(7, 8, 21, []protocols.HTTP2DrainRequest{{Direction: enums.SocketDataDirectionEgress, Missing: 123}})
	if len(got) != 1 {
		t.Fatalf("got %d summaries", len(got))
	}
	sum := got[0].(*events.H2CSummary)
	if sum.ConnectionID != 7 || sum.RandomID != 8 || sum.StreamID != 21 || sum.Direction0 != enums.SocketDataDirectionEgress ||
		sum.FirstDataID0 != 77 || sum.Bytes != 123 || sum.Reason != events.SummaryReasonStreamDrain {
		t.Fatalf("decoded %+v", sum)
	}
}

// TestDrainStreamAllocations: a drain that finds nothing allocates nothing (no key slice, no summary)
func TestDrainStreamAllocations(t *testing.T) {
	s, _ := newFakeSummaries()
	reqs := []protocols.HTTP2DrainRequest{{Direction: enums.SocketDataDirectionIngress, Missing: 10}}
	if n := testing.AllocsPerRun(200, func() { s.DrainStream(7, 8, 99, reqs) }); n != 0 {
		t.Fatalf("an empty drain allocates %v times", n)
	}
}

// oldWithSummaries is withSummaries as it was before the events were appended into the result straight
func oldWithSummaries(bufs [4]*buffer.Buffer, req, resp []protocols.HTTP2Summary) []buffer.SocketDataBuffer {
	sections := [4][]protocols.HTTP2Summary{nil, req, nil, resp}
	var parts [4][]buffer.SocketDataBuffer
	size := len(req) + len(resp)
	for i, b := range bufs {
		parts[i] = buffer.CombinedSocketBuffers(b)
		size += len(parts[i])
	}
	detail := func(s protocols.HTTP2Summary) buffer.SocketDataBuffer {
		if summary, ok := s.(*events.H2CSummary); ok {
			return summary.Detail()
		}
		return nil
	}
	result := make([]buffer.SocketDataBuffer, 0, size)
	for i := range bufs {
		pending := sections[i]
		for _, e := range parts[i] {
			for len(pending) > 0 && pending[0].SummaryFirstDataID() < e.DataID() {
				result = append(result, detail(pending[0]))
				pending = pending[1:]
			}
			result = append(result, e)
		}
		for _, p := range pending {
			result = append(result, detail(p))
		}
	}
	return result
}

// TestWithSummariesMatchesBefore: the events and the summary details come in the same order with the same values
func TestWithSummariesMatchesBefore(t *testing.T) {
	for seed := int64(0); seed < 500; seed++ {
		rnd := rand.New(rand.NewSource(seed))
		var bufs [4]*buffer.Buffer
		id := uint64(1)
		var reqIDs, respIDs []uint64
		for i := range bufs {
			if rnd.Intn(5) == 0 {
				continue // no such part
			}
			b := buffer.NewBuffer()
			for n := rnd.Intn(6); n > 0; n-- {
				id += uint64(1 + rnd.Intn(4))
				b.AppendDataEvent(&events.SocketDataUploadEvent{DataID0: id, DataLen: 9, Finished: 1, TotalSize0: 9})
				if i == 1 && rnd.Intn(2) == 0 {
					reqIDs = append(reqIDs, id-1)
				}
				if i == 3 && rnd.Intn(2) == 0 {
					respIDs = append(respIDs, id-1)
				}
			}
			bufs[i] = b
		}
		mk := func(ids []uint64) []protocols.HTTP2Summary {
			var out []protocols.HTTP2Summary
			for k, first := range ids {
				out = append(out, &events.H2CSummary{FirstDataID0: first, Bytes: uint64(100 + k), Calls: 2, StartTime0: first * 10})
			}
			if rnd.Intn(4) == 0 {
				out = append(out, &events.H2CSummary{FirstDataID0: id + 100, Bytes: 1})
			}
			return out
		}
		req, resp := mk(reqIDs), mk(respIDs)
		want, got := oldWithSummaries(bufs, req, resp), withSummaries(bufs, req, resp)
		if len(want) != len(got) {
			t.Fatalf("seed %d: %d events, want %d", seed, len(got), len(want))
		}
		for i := range want {
			if !reflect.DeepEqual(want[i], got[i]) {
				t.Fatalf("seed %d: event %d is %+v, want %+v", seed, i, got[i], want[i])
			}
		}
		if len(want) > 0 {
			if a, b := messageDetails(want), messageDetails(got); !reflect.DeepEqual(a, b) {
				t.Fatalf("seed %d: the details differ", seed)
			}
		}
	}
}
