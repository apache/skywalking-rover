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
	"testing"
	"time"
)

// slack is how much later than the read time an event of a test may have been tracked (the goroutine of the test
// may be preempted in between)
const slack = 20 * time.Millisecond

// TestDeliveredThroughHoldsWhileQueued: an event the reader has read stays on its way, for DeliveredThrough, while
// it waits in the batch of the reader or in the channel of its partition, and the time a reader is blocked on a
// full partition does not run on the delivery clock
func TestDeliveredThroughHoldsWhileQueued(t *testing.T) { //nolint:funlen // one scenario checked step by step
	queue := NewEventQueue("delivery test", 1, 2, func(int) PartitionContext { return nil })
	queue.TrackDelivery()
	defer queue.untrackDeliveryForTest()
	p := queue.partitions[0]
	p.open(1) // one slot per event: Push

	settle := func() int64 {
		time.Sleep(time.Millisecond)
		return DeliveredThrough()
	}
	if now, through := DeliveryNow(), settle(); through < now {
		t.Fatalf("nothing queued: through %d behind %d", through, now)
	}

	readAt := DeliveryNow()
	queue.push(0, 1, true)
	time.Sleep(50 * time.Millisecond)
	if through := settle(); through > readAt+int64(slack) {
		t.Fatalf("a queued event is not on its way: through %s after its read", time.Duration(through-readAt))
	}

	// the channel holds 2: the third push blocks until the consumer takes one
	queue.push(0, 2, true)
	secondAt := DeliveryNow()
	done := make(chan struct{})
	go func() {
		queue.push(0, 3, true)
		close(done)
	}()
	// measured from when the push is blocked, however late the goroutine runs
	for deadline := time.Now().Add(10 * time.Second); deliveryBlockedSince.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the third push does not block")
		}
	}
	blockedAt := DeliveryNow()
	time.Sleep(100 * time.Millisecond)
	if ran := time.Duration(DeliveryNow() - blockedAt); ran > 50*time.Millisecond {
		t.Fatalf("the delivery clock ran %s while the reader was blocked", ran)
	}
	<-p.channel
	p.delivery.consumedSingle()
	<-done
	// the second event (read before the block) is still queued
	if through := settle(); through > secondAt+int64(slack) {
		t.Fatalf("through passed an event still queued by %s", time.Duration(through-blockedAt))
	}
	for i := 0; i < 2; i++ {
		<-p.channel
		p.delivery.consumedSingle()
	}
	if now, through := DeliveryNow(), settle(); through < now {
		t.Fatalf("everything consumed: through %s behind", time.Duration(now-through))
	}

	// a batch is on its way from its first event until the partition consumed it
	b := newEventBatcher(queue, func(interface{}) int { return 0 }, 4)
	batchRead := DeliveryNow()
	b.add(1)
	time.Sleep(20 * time.Millisecond)
	if through := settle(); through > batchRead+int64(slack) {
		t.Fatal("an open batch of the reader is not on its way")
	}
	b.flush()
	batch := (<-p.channel).(*eventBatch)
	if through := settle(); through > batchRead+int64(slack) {
		t.Fatal("a batch in the channel is not on its way")
	}
	p.delivery.consumedBatch(batch)
	if now, through := DeliveryNow(), settle(); through < now {
		t.Fatal("the consumed batch is still on its way")
	}
}

// TestPushOfAnotherSender: a push of a goroutine that is not a reader leaves the delivery clock running while it
// blocks, a push before the start is dropped, and a blocked push ends when the queue stops
func TestPushOfAnotherSender(t *testing.T) {
	queue := NewEventQueue("push test", 1, 1, func(int) PartitionContext { return nil })
	queue.TrackDelivery()
	defer queue.untrackDeliveryForTest()
	if queue.Push(0, 1) {
		t.Fatal("a push before the start is taken")
	}
	p := queue.partitions[0]
	done := make(chan struct{})
	p.done = done
	p.open(1)
	if !queue.Push(0, 1) {
		t.Fatal("a push is dropped")
	}
	result := make(chan bool)
	go func() { result <- queue.Push(0, 2) }()
	time.Sleep(50 * time.Millisecond)
	if deliveryBlockedSince.Load() != 0 {
		t.Fatal("the delivery clock stopped for a sender that is not a reader")
	}
	close(done)
	select {
	case taken := <-result:
		if taken {
			t.Fatal("a push into a stopped queue is taken")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a push blocks after the queue stopped")
	}
}
