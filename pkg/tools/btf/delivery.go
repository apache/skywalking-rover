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
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// The delivery clock tells a consumer that waits for an event of the rings how much of the waiting the pipeline
// between the reader and the consumers can account for: an event the reader has read but a partition has not
// consumed yet (it waits in a batch of the reader, or in the channel of a partition that runs behind) is on its
// way, not missing. A consumer that gives a missing event up after a time (the HTTP/2 parser's arrival wait)
// measures that time on this clock, up to DeliveredThrough, so a backlog between the reader and the partitions
// never counts as waiting.
//
// The clock (DeliveryNow) is the monotonic time of the process less the time the readers of the tracked queues
// were blocked on a full partition channel: while a reader is blocked the rings fill and nothing of them is read,
// so that time does not count either.
var (
	deliveryBase = time.Now()

	deliveryBlockMu      sync.Mutex
	deliveryBlocked      atomic.Int64 // nanoseconds some reader of a tracked queue was blocked, ended blocks
	deliveryBlockedSince atomic.Int64 // DeliveryNow-independent start (since deliveryBase) of the ongoing block, 0 none
	deliveryBlockers     int

	deliveryTrackedMu sync.RWMutex
	deliveryTracked   []*EventQueue

	// deliveryVersion changes whenever an event is handed over or consumed. The oldest read time on its way is
	// cached with the version it was computed at (deliveryOldestCache, math.MaxInt64 for none), and when
	// (deliveryOldestCacheAt, on the clock of deliveryBase), see DeliveredThrough
	deliveryVersion       atomic.Int64
	deliveryCacheMu       sync.Mutex
	deliveryOldestCache   int64
	deliveryOldestVersion int64 = -1
	deliveryOldestCacheAt int64
)

// deliveredThroughCacheFor is how long an oldest read time on its way is reused after events were handed over or
// consumed: the new ones were read later, and a consumed one only makes the true value later, so it stays true,
// only more cautious. "Nothing on its way" is never reused once something was handed over.
const deliveredThroughCacheFor = 200 * time.Microsecond

func sinceDeliveryBase() int64 {
	return int64(time.Since(deliveryBase))
}

// DeliveryNow is the current time of the delivery clock (nanoseconds): it never goes backwards
func DeliveryNow() int64 {
	now := sinceDeliveryBase()
	blocked := deliveryBlocked.Load()
	if since := deliveryBlockedSince.Load(); since > 0 && now > since {
		blocked += now - since
	}
	return now - blocked
}

// DeliveredThrough is the time of the delivery clock up to which every event the readers of the tracked queues
// have read has been consumed by its partition: the read time of the oldest event still in a batch of a reader or
// in the channel of a partition, or DeliveryNow when there is none
func DeliveredThrough() int64 {
	now := DeliveryNow()
	return min(now, deliveryOldest())
}

// deliveryOldest is the read time of the oldest event on its way, math.MaxInt64 when there is none
func deliveryOldest() int64 {
	deliveryCacheMu.Lock()
	defer deliveryCacheMu.Unlock()
	version := deliveryVersion.Load()
	at := sinceDeliveryBase()
	if version == deliveryOldestVersion || (deliveryOldestCache != math.MaxInt64 && deliveryOldestVersion >= 0 &&
		at-deliveryOldestCacheAt < int64(deliveredThroughCacheFor)) {
		return deliveryOldestCache
	}
	oldest := int64(math.MaxInt64)
	deliveryTrackedMu.RLock()
	for _, q := range deliveryTracked {
		for _, p := range q.partitions {
			if o, ok := p.delivery.oldest(); ok && o < oldest {
				oldest = o
			}
		}
	}
	deliveryTrackedMu.RUnlock()
	deliveryOldestCache, deliveryOldestVersion, deliveryOldestCacheAt = oldest, version, at
	return oldest
}

// TrackDelivery makes the queue part of the delivery clock: the events its readers read count as on their way
// until their partition consumed them. Call it before Start.
func (e *EventQueue) TrackDelivery() {
	deliveryTrackedMu.Lock()
	defer deliveryTrackedMu.Unlock()
	if e.trackDelivery {
		return
	}
	e.trackDelivery = true
	for _, p := range e.partitions {
		p.delivery.enabled = true
	}
	deliveryTracked = append(deliveryTracked, e)
}

// untrackDeliveryForTest removes the queue from the delivery clock
func (e *EventQueue) untrackDeliveryForTest() {
	deliveryTrackedMu.Lock()
	defer deliveryTrackedMu.Unlock()
	for i, q := range deliveryTracked {
		if q == e {
			deliveryTracked = append(deliveryTracked[:i], deliveryTracked[i+1:]...)
			break
		}
	}
	deliveryVersion.Add(1)
}

func deliveryBlockStart() {
	deliveryBlockMu.Lock()
	defer deliveryBlockMu.Unlock()
	deliveryBlockers++
	if deliveryBlockers == 1 {
		deliveryBlockedSince.Store(max(sinceDeliveryBase(), 1))
	}
}

func deliveryBlockEnd() {
	deliveryBlockMu.Lock()
	defer deliveryBlockMu.Unlock()
	deliveryBlockers--
	if deliveryBlockers == 0 {
		if since := deliveryBlockedSince.Load(); since > 0 {
			// added before the ongoing block is cleared: DeliveryNow never sees the block twice or not at all
			// for long (it may see it twice for an instant, which only makes it smaller)
			deliveryBlocked.Add(max(sinceDeliveryBase()-since, 0))
		}
		deliveryBlockedSince.Store(0)
	}
}

// partitionDelivery is what a partition has been handed over and not consumed yet: the batches by their read
// time, and the single events (a queue without batches) in the order they were pushed
type partitionDelivery struct {
	enabled bool
	mu      sync.Mutex
	batches map[*eventBatch]int64
	singles []int64
}

func (d *partitionDelivery) trackBatch(batch *eventBatch, readAt int64) {
	if !d.enabled {
		return
	}
	d.mu.Lock()
	if d.batches == nil {
		d.batches = make(map[*eventBatch]int64)
	}
	d.batches[batch] = readAt
	d.mu.Unlock()
	deliveryVersion.Add(1)
}

func (d *partitionDelivery) consumedBatch(batch *eventBatch) {
	if !d.enabled {
		return
	}
	d.mu.Lock()
	delete(d.batches, batch)
	d.mu.Unlock()
	deliveryVersion.Add(1)
}

func (d *partitionDelivery) trackSingle(readAt int64) {
	if !d.enabled {
		return
	}
	d.mu.Lock()
	d.singles = append(d.singles, readAt)
	d.mu.Unlock()
	deliveryVersion.Add(1)
}

func (d *partitionDelivery) consumedSingle() {
	if !d.enabled {
		return
	}
	d.mu.Lock()
	if len(d.singles) > 0 {
		d.singles = d.singles[1:]
		if len(d.singles) == 0 {
			d.singles = d.singles[:0:0]
		}
	}
	d.mu.Unlock()
	deliveryVersion.Add(1)
}

// oldest is the read time of the oldest event handed over and not consumed
func (d *partitionDelivery) oldest() (int64, bool) {
	if !d.enabled {
		return 0, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var oldest int64
	found := false
	for _, at := range d.batches {
		if !found || at < oldest {
			oldest, found = at, true
		}
	}
	// pushed in about the order they were read: the first one is the oldest
	if len(d.singles) > 0 && (!found || d.singles[0] < oldest) {
		oldest, found = d.singles[0], true
	}
	return oldest, found
}

// sendTracked sends to the channel of a partition, and false when the queue stopped first (p.done). For a reader
// of the queue, the time the send blocks (the channel is full) counts as time the reader did not read; another
// sender (not a reader) leaves the delivery clock as it is.
func sendTracked(p *partition, data interface{}, reader bool) bool {
	select {
	case p.channel <- data:
		return true
	default:
	}
	if reader && p.delivery.enabled {
		deliveryBlockStart()
		defer deliveryBlockEnd()
	}
	select {
	case p.channel <- data:
		return true
	case <-p.done:
		return false
	}
}
