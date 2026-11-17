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

package buffer

import (
	"sync"
	"testing"
)

// withFreeLists runs f with empty free lists and the counters cleared
func withFreeLists(_ testing.TB, budget int64, f func()) {
	saved := freeLists
	events, bytes, free, overhead := eventsInUse.Load(), bytesInUse.Load(), freeBytes.Load(), eventOverhead.Load()
	defer func() {
		freeLists = saved
		eventsInUse.Store(events)
		bytesInUse.Store(bytes)
		freeBytes.Store(free)
		eventOverhead.Store(overhead)
		memoryBudget.Store(0)
	}()
	freeLists = buildFreeLists()
	eventsInUse.Store(0)
	bytesInUse.Store(0)
	freeBytes.Store(0)
	eventOverhead.Store(0)
	memoryBudget.Store(budget)
	f()
}

// TestFreeListReuse: a released buffer is handed out again, of its own class
func TestFreeListReuse(t *testing.T) {
	withFreeLists(t, 1<<30, func() {
		b := TakeBuffer(3000)
		if cap(b) != 4096 || len(b) != 3000 {
			t.Fatalf("len %d cap %d", len(b), cap(b))
		}
		first := &b[:1][0]
		ReleaseBufferOnly(b)
		if freeBytes.Load() != 4096 {
			t.Fatalf("free %d", freeBytes.Load())
		}
		again := TakeBuffer(4000)
		if &again[:1][0] != first || freeBytes.Load() != 0 || bytesInUse.Load() != 4096 {
			t.Fatal("the free buffer must be reused")
		}
		if other := TakeBuffer(100); cap(other) != 2048 {
			t.Fatalf("class %d", cap(other))
		}
	})
}

// TestFreeListCap: the free lists keep no more than the share of the budget, nor what the events in use
// leave of it
func TestFreeListCap(t *testing.T) {
	const budget = 16 * 16 * MaxEventBufferSize // the share is 16 full buffers
	withFreeLists(t, budget, func() {
		bufs := make([][]byte, 0, 64)
		for i := 0; i < 64; i++ {
			bufs = append(bufs, TakeBuffer(MaxEventBufferSize))
		}
		for _, b := range bufs {
			ReleaseBufferOnly(b)
		}
		if freeBytes.Load() != 16*MaxEventBufferSize || len(freeLists[3].bufs) != 16 {
			t.Fatalf("free %d in %d buffers, want the share of 16", freeBytes.Load(), len(freeLists[3].bufs))
		}
		// the events in use hold all but 3 buffers of the budget: the lists keep 3
		freeLists = buildFreeLists()
		freeBytes.Store(0)
		bytesInUse.Store(budget - 3*MaxEventBufferSize)
		for i := 0; i < 8; i++ {
			freeLists[3].put(make([]byte, MaxEventBufferSize))
		}
		if len(freeLists[3].bufs) != 3 {
			t.Fatalf("kept %d, want 3", len(freeLists[3].bufs))
		}
	})
	withFreeLists(t, 0, func() {
		for i := int64(0); i < freeListNoBudget/MaxEventBufferSize+10; i++ {
			freeLists[3].put(make([]byte, MaxEventBufferSize))
		}
		if freeBytes.Load() > freeListNoBudget {
			t.Fatalf("without a budget the lists keep %d, over %d", freeBytes.Load(), freeListNoBudget)
		}
	})
}

// TestFreeListConcurrent: buffers taken and released on many goroutines are never handed out twice and
// the accounting returns to zero
func TestFreeListConcurrent(t *testing.T) {
	withFreeLists(t, 1<<30, func() {
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				held := make([][]byte, 0, 16)
				for i := 0; i < 5000; i++ {
					b := TakeBuffer((g*977 + i*131) % MaxEventBufferSize)
					b = b[:cap(b)]
					b[0], b[len(b)-1] = byte(g), byte(g)
					held = append(held, b)
					if len(held) == cap(held) {
						for _, h := range held {
							if h[0] != byte(g) || h[len(h)-1] != byte(g) {
								t.Error("a buffer was handed to two holders")
								return
							}
							ReleaseBufferOnly(h)
						}
						held = held[:0]
					}
				}
				for _, h := range held {
					ReleaseBufferOnly(h)
				}
			}(g)
		}
		wg.Wait()
		if bytesInUse.Load() != 0 {
			t.Fatalf("bytes in use %d", bytesInUse.Load())
		}
		var listed int64
		for _, l := range freeLists {
			listed += int64(len(l.bufs) * l.size)
		}
		if listed != freeBytes.Load() {
			t.Fatalf("the lists hold %d, the counter says %d", listed, freeBytes.Load())
		}
	})
}
