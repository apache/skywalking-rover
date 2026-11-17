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
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRecycledBatchIsCleared: a recycled batch comes back empty and keeps none of the events it carried
func TestRecycledBatchIsCleared(t *testing.T) {
	queue := &EventQueue{count: 1}
	batch := queue.takeBatch(8)
	if len(*batch) != 0 || cap(*batch) != 8 {
		t.Fatalf("a new batch of len %d cap %d", len(*batch), cap(*batch))
	}
	for i := 0; i < 8; i++ {
		v := i
		*batch = append(*batch, &v)
	}
	slots := (*batch)[:cap(*batch)]
	queue.recycleBatch(batch)
	if len(*batch) != 0 {
		t.Fatalf("a recycled batch of len %d", len(*batch))
	}
	for i, slot := range slots {
		if slot != nil {
			t.Fatalf("slot %d of a recycled batch still holds its event", i)
		}
	}
}

// TestBatchesAreReused: the batcher takes the batches the consumer recycled instead of allocating new ones
func TestBatchesAreReused(t *testing.T) {
	queue := &EventQueue{count: 1}
	queue.partitions = append(queue.partitions, newPartition(0, 100, nil))
	queue.partitions[0].open(1)
	batcher := newEventBatcher(queue, func(interface{}) int { return 0 }, 4)
	seen := map[*eventBatch]bool{}
	reused := 0
	for i := 0; i < 400; i++ {
		batcher.add(i)
		if len(queue.partitions[0].channel) > 0 {
			batch := (<-queue.partitions[0].channel).(*eventBatch)
			if seen[batch] {
				reused++
			}
			seen[batch] = true
			queue.recycleBatch(batch)
		}
	}
	// the pool may drop items (always some under the race detector), but never all of them
	if reused == 0 {
		t.Fatal("no batch was reused")
	}
}

type orderCheckingPartition struct {
	t        *testing.T
	mu       sync.Mutex
	next     map[int]int
	consumed *atomic.Int64
}

func (*orderCheckingPartition) Start(context.Context) {}

func (o *orderCheckingPartition) Consume(data interface{}) {
	ev := data.(*taggedEvent)
	o.mu.Lock()
	// the events of a reader reach a partition in the order the reader read them: a batch reused while
	// still being consumed would show up as a skipped, repeated or foreign event
	if want, ok := o.next[ev.reader]; ok && ev.seq <= want {
		o.t.Errorf("reader %d: event %d after %d", ev.reader, ev.seq, want)
	}
	o.next[ev.reader] = ev.seq
	o.mu.Unlock()
	if ev.seq%7 == 0 {
		runtime.Gosched()
	}
	o.consumed.Add(1)
}

type taggedEvent struct {
	reader, seq, key int
}

// TestBatchRecyclingDoesNotAlias runs several readers into a batched queue: every event is consumed exactly
// once and in order, so no batch is handed out again while its consumer still reads it. Run it with -race.
func TestBatchRecyclingDoesNotAlias(t *testing.T) {
	const readers, partitions, perReader = 3, 4, 20000
	consumed := &atomic.Int64{}
	contexts := make([]*orderCheckingPartition, partitions)
	queue := NewEventQueue("test", partitions, 256, func(i int) PartitionContext {
		contexts[i] = &orderCheckingPartition{t: t, next: map[int]int{}, consumed: consumed}
		return contexts[i]
	})
	linker := NewLinker()
	linker.SetEventQueueReaderOptions(EventQueueReaderOptions{BatchSize: 16})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx, linker)

	var wg sync.WaitGroup
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(reader int) {
			defer wg.Done()
			batcher := newEventBatcher(queue, func(data interface{}) int { return data.(*taggedEvent).key }, 16)
			for i := 0; i < perReader; i++ {
				batcher.add(&taggedEvent{reader: reader, seq: i, key: (i * 31) % 97})
				if i%101 == 0 {
					batcher.flush()
				}
			}
			batcher.flush()
		}(r)
	}
	wg.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for consumed.Load() != readers*perReader {
		if time.Now().After(deadline) {
			t.Fatalf("consumed %d of %d events", consumed.Load(), readers*perReader)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	if c := consumed.Load(); c != readers*perReader {
		t.Fatalf("consumed %d events, sent %d", c, readers*perReader)
	}
}

type countingPartition struct {
	consumed *atomic.Int64
}

func (countingPartition) Start(context.Context) {}
func (c countingPartition) Consume(interface{}) { c.consumed.Add(1) }
