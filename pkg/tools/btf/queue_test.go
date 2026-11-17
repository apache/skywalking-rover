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

package btf

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

// TestEventBatcherKeepsThePartitionOrder: the events of a partition reach it in the order they were read,
// in runs of at most the batch size, and a flush hands over every partial run
func TestEventBatcherKeepsThePartitionOrder(t *testing.T) {
	queue := &EventQueue{count: 3}
	for i := 0; i < 3; i++ {
		queue.partitions = append(queue.partitions, newPartition(i, 100, nil))
		queue.partitions[i].open(1)
	}
	batcher := newEventBatcher(queue, func(data interface{}) int { return data.(int) % 3 }, 4)
	for i := 0; i < 20; i++ {
		batcher.add(i)
	}
	batcher.flush()
	for p, partition := range queue.partitions {
		var got []int
		for len(partition.channel) > 0 {
			batch := *(<-partition.channel).(*eventBatch)
			if len(batch) == 0 || len(batch) > 4 {
				t.Fatalf("partition %d: a batch of %d events", p, len(batch))
			}
			for _, d := range batch {
				got = append(got, d.(int))
			}
		}
		next := p
		for _, v := range got {
			if v != next {
				t.Fatalf("partition %d: events %v out of order", p, got)
			}
			next += 3
		}
		if next < 20 {
			t.Fatalf("partition %d: events %v missing", p, got)
		}
	}
}

type testSample struct {
	Value uint64
}

// perfOutputProgram writes its 8 byte stack value into the perf event array on every run
func perfOutputProgram(t *testing.T, events *ebpf.Map) *ebpf.Program {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.StoreImm(asm.RFP, -8, 42, asm.DWord),
			asm.LoadMapPtr(asm.R2, events.FD()),
			asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
			asm.Mov.Reg(asm.R4, asm.RFP),
			asm.Add.Imm(asm.R4, -8),
			asm.Mov.Imm(asm.R5, 8),
			asm.FnPerfEventOutput.Call(),
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		},
	})
	if err != nil {
		t.Skipf("cannot load the test program: %v", err)
	}
	return prog
}

// newTestPerfRing is a perf event array and a program that writes the value 42 into it on every run. It
// needs root.
func newTestPerfRing(t *testing.T) (ring *ebpf.Map, closeRing func()) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skip(err)
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerfEventArray})
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { events.Close() })
	prog := perfOutputProgram(t, events)
	t.Cleanup(func() { prog.Close() })
	return events, func() {
		if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
			t.Fatalf("run: %v", err)
		}
	}
}

// testRingReader reads a ring with the reader options of the event queues and counts what it gets
type testRingReader struct {
	received atomic.Int64
	drained  atomic.Int64
}

func readTestRing(t *testing.T, events *ebpf.Map, wakeupEvents int, flushPeriod time.Duration) *testRingReader {
	t.Helper()
	linker := NewLinker()
	t.Cleanup(func() { _ = linker.Close() })
	r := &testRingReader{}
	linker.readEventAsync(events, func(data interface{}) {
		if v := data.(*testSample).Value; v != 42 {
			t.Errorf("event value %d", v)
		}
		r.received.Add(1)
	}, os.Getpagesize(), 1, func() interface{} { return &testSample{} },
		readerOptions{wakeupEvents: wakeupEvents, flushPeriod: flushPeriod, drained: func() { r.drained.Add(1) }})
	require.NoError(t, linker.HasError())
	return r
}

// TestReaderWakeupAndBatching: with a wakeup count far above the traffic, a lone event still arrives
// within the flush period, and the drained callback runs after every run of events
func TestReaderWakeupAndBatching(t *testing.T) {
	events, run := newTestPerfRing(t)
	r := readTestRing(t, events, 1000, 50*time.Millisecond)
	start := time.Now()
	run()
	require.Eventually(t, func() bool { return r.received.Load() == 1 }, 5*time.Second, time.Millisecond)
	require.Less(t, time.Since(start), time.Second, "a lone event with a flush period of 50ms")
	drainedAfterOne := r.drained.Load()
	require.NotZero(t, drainedAfterOne, "the drained callback did not run")
	for i := 0; i < 100; i++ {
		run()
	}
	require.Eventually(t, func() bool { return r.received.Load() == 101 && r.drained.Load() > drainedAfterOne },
		5*time.Second, time.Millisecond)
}

// TestReaderBatchingWithoutWakeup: with batching and no wakeup count, a lone event is handed over (drained)
// as soon as the ring is empty, well within the flush period
func TestReaderBatchingWithoutWakeup(t *testing.T) {
	events, run := newTestPerfRing(t)
	r := readTestRing(t, events, 0, time.Second)
	start := time.Now()
	run()
	require.Eventually(t, func() bool { return r.received.Load() == 1 && r.drained.Load() >= 1 }, 5*time.Second, time.Millisecond)
	require.Less(t, time.Since(start), 500*time.Millisecond, "a partial batch must not wait for the flush period")
}

// TestDrainClock: the clock is asked every drainClockCheckEvery events, and expires a period after the last
// hand over
func TestDrainClock(t *testing.T) {
	start := time.Unix(100, 0)
	clock := &drainClock{period: 100 * time.Millisecond, last: start}
	handOvers := 0
	for i := 1; i <= drainClockCheckEvery*10; i++ {
		now := start.Add(time.Duration(i) * time.Millisecond)
		if !clock.tick() {
			continue
		}
		require.Zero(t, i%drainClockCheckEvery, "asked after %d events", i)
		if clock.expired(now) {
			require.GreaterOrEqual(t, now.Sub(clock.last), clock.period)
			clock.reset(now)
			handOvers++
		}
	}
	require.NotZero(t, handOvers, "never expired")
}

type nopPartition struct{}

func (nopPartition) Start(context.Context) {}
func (nopPartition) Consume(interface{})   {}

// TestBatchedQueueKeepsItsEventBound: with batches, a partition channel holds queue_size events, not
// queue_size batches
func TestBatchedQueueKeepsItsEventBound(t *testing.T) {
	queue := NewEventQueue("test", 2, 1000, func(int) PartitionContext { return nopPartition{} })
	linker := NewLinker()
	linker.SetEventQueueReaderOptions(EventQueueReaderOptions{BatchSize: 64})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx, linker)
	for _, p := range queue.partitions {
		if cap(p.channel) != 16 {
			t.Fatalf("a partition channel holds %d batches of 64 for a queue size of 1000", cap(p.channel))
		}
	}
}
