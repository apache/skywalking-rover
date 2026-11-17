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
	"sync/atomic"
)

// The data buffers of the socket data events are recycled through a free list per size class. A
// sync.Pool is emptied by every GC (its victim cache survives one cycle): near the Go soft memory limit
// the GC runs often, the pools are empty every time, and the buffers are allocated again, which drives
// the next GC. The free lists survive the GC. What they keep is bounded: together with the events in use
// they stay within the memory budget, and never above a share of it, so a burst does not pin its peak
// as free buffers for good.
type freeList struct {
	mu   sync.Mutex
	bufs [][]byte
	size int
}

var (
	freeLists = buildFreeLists()
	// freeBytes is what the free lists hold
	freeBytes atomic.Int64
	// freeListBudgetShare: the free lists keep at most 1/freeListBudgetShare of the memory budget
	freeListBudgetShare int64 = 16
	// freeListNoBudget is what the free lists keep at most when the memory protection is off
	freeListNoBudget int64 = 32 << 20
)

func buildFreeLists() []*freeList {
	lists := make([]*freeList, len(bufferClasses))
	for i, size := range bufferClasses {
		lists[i] = &freeList{size: size}
	}
	return lists
}

// get returns a buffer of the class size: a free one, or a new one when the list is empty
func (f *freeList) get() []byte {
	f.mu.Lock()
	if n := len(f.bufs); n > 0 {
		b := f.bufs[n-1]
		f.bufs[n-1] = nil
		f.bufs = f.bufs[:n-1]
		f.mu.Unlock()
		freeBytes.Add(-int64(f.size))
		return b
	}
	f.mu.Unlock()
	b := make([]byte, f.size)
	return b
}

// put keeps a released buffer of the class size, unless the free lists are full: it is then left to
// the garbage collector
func (f *freeList) put(b []byte) {
	if freeBytes.Load()+int64(f.size) > freeListLimit() {
		return
	}
	f.mu.Lock()
	f.bufs = append(f.bufs, b)
	f.mu.Unlock()
	freeBytes.Add(int64(f.size))
}

// freeListLimit is what the free lists may hold: what the events in use leave of the memory budget, at
// most a share of it
func freeListLimit() int64 {
	budget := memoryBudget.Load()
	if budget <= 0 {
		return freeListNoBudget
	}
	limit := budget - InflightBytes()
	if share := budget / freeListBudgetShare; limit > share {
		limit = share
	}
	return limit
}
