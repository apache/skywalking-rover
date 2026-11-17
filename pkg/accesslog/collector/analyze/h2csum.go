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
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
)

// H2CSummaries is the user space of the h2c payload summaries (summarize_h2c_payload,
// skywalking-rover/bpf/accesslog/common/h2c_sum.h): it keeps h2c_sum_map from holding entries.
//
// Every period it flips the epoch the new entries are made in, waits for the BPF programs that may still
// update entries of the old epoch, and drains (looks up and deletes) every entry of the old epoch, and every
// entry of a connection that is not active anymore, of either epoch; the parser drains the entries of a stream
// it saw end or reset (DrainStream). A drained entry is handed on only when its delete succeeded: BPF may send
// and delete the same entry at once, and the side whose delete fails drops its copy. The summaries go to the
// partition of their connection (deliver), like the summaries BPF sends in its batches.
type H2CSummaries struct {
	sums, epochs, active *ebpf.Map
	deliver              func(s *events.H2CSummary)
	period, grace        time.Duration

	// ops is how the entries of h2c_sum_map are taken (sums, a fake in the tests)
	ops h2cSumOps

	// epoch is the epoch new entries are made in; flipLock keeps one flip (Flush) at a time
	flipLock sync.Mutex
	epoch    atomic.Uint32
	// drainLock keeps one drain of the parser (DrainStream) at a time, over drainScratch. Two takes of the same
	// entry need no lock (the side whose delete removes the entry has it): it only guards the scratch, and the
	// epoch flush, which walks the whole map, takes with a scratch of its own, so the drains of the partitions do
	// not wait for that walk
	drainLock    sync.Mutex
	drainScratch h2cTakeScratch

	closedLock sync.Mutex
	closed     map[[2]uint64]struct{}
}

// h2cTakeScratch is the key and the value of a take: the map calls get pointers to them, which would make
// variables of the take escape to the heap on every call
type h2cTakeScratch struct {
	key   [events.SummaryKeySize]byte
	value [events.SummaryValueSize]byte
}

// h2cSumOps takes the entries of h2c_sum_map. The key and the value are a [SummaryKeySize]byte and a
// [SummaryValueSize]byte, handed over as pointers so the map calls do not allocate.
type h2cSumOps interface {
	// lookupAndDelete fills value with the entry of the key and deletes it: nil when this call removed it,
	// ebpf.ErrKeyNotExist when there is none (or BPF removed it first)
	lookupAndDelete(key, value unsafe.Pointer) error
}

// ebpfSumOps takes the entries with one BPF_MAP_LOOKUP_AND_DELETE_ELEM where the kernel has it for a hash map
// (Linux 5.14), otherwise with a lookup and a delete, which is what both did before: the side (BPF or the user
// space) whose delete succeeds has the entry. Which one is used is probed on the first take.
type ebpfSumOps struct {
	m sumMapCalls
	// 0: not probed yet, 1: lookup-and-delete, 2: lookup then delete
	mode atomic.Int32
}

// sumMapCalls are the calls of h2c_sum_map ebpfSumOps makes (a *ebpf.Map, a fake in the tests)
type sumMapCalls interface {
	LookupAndDelete(key, valueOut interface{}) error
	Lookup(key, valueOut interface{}) error
	Delete(key interface{}) error
}

const (
	sumOpsUnprobed = iota
	sumOpsLookupAndDelete
	sumOpsLookupDelete
)

func (o *ebpfSumOps) probe() int32 {
	// a key BPF never makes: its padding (key bytes 22-23, h2c_sum_key_t.pad) is not zero, so a kernel that has
	// the operation says there is no such entry, and nothing is deleted
	var key [events.SummaryKeySize]byte
	var value [events.SummaryValueSize]byte
	key[22], key[23] = 0xff, 0xff
	err := o.m.LookupAndDelete(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return sumOpsLookupAndDelete
	}
	partitionLog.Infof("the kernel has no lookup-and-delete for the h2c payload summary map (%v): a lookup and a delete take an entry", err)
	return sumOpsLookupDelete
}

func (o *ebpfSumOps) lookupAndDelete(key, value unsafe.Pointer) error {
	mode := o.mode.Load()
	if mode == sumOpsUnprobed {
		mode = o.probe()
		o.mode.Store(mode)
	}
	if mode == sumOpsLookupAndDelete {
		err := o.m.LookupAndDelete(key, value)
		if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return err
		}
		// not there after all: from now on the two calls
		o.mode.Store(sumOpsLookupDelete)
	}
	if err := o.m.Lookup(key, value); err != nil {
		return err
	}
	if err := o.m.Delete(key); err != nil {
		// BPF sent and deleted it in between: it has it
		return ebpf.ErrKeyNotExist
	}
	return nil
}

// the summaries of this agent, nil while they are off
var h2cSummaries atomic.Pointer[H2CSummaries]

// NewH2CSummaries makes the user space of the summaries over the maps; deliver hands a drained summary to the
// partition of its connection
func NewH2CSummaries(sums, epochs, active *ebpf.Map, deliver func(s *events.H2CSummary)) *H2CSummaries {
	s := &H2CSummaries{sums: sums, epochs: epochs, active: active, deliver: deliver,
		period: time.Second, grace: 10 * time.Millisecond, closed: make(map[[2]uint64]struct{})}
	s.ops = &ebpfSumOps{m: sums}
	return s
}

// SetH2CSummaries makes s the summaries of the agent (nil: off)
func SetH2CSummaries(s *H2CSummaries) {
	h2cSummaries.Store(s)
}

// NoteH2CConnectionClosed tells the summaries a connection closed: its entries are drained by the next flush
// (counted as a close, not as stale)
func NoteH2CConnectionClosed(connectionID, randomID uint64) {
	if s := h2cSummaries.Load(); s != nil {
		s.closedLock.Lock()
		s.closed[[2]uint64{connectionID, randomID}] = struct{}{}
		s.closedLock.Unlock()
	}
}

// Start flushes the summaries every period until the context ends
func (s *H2CSummaries) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.period)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Flush()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// takeClosed is the connections noted closed since the last time, which are forgotten
func (s *H2CSummaries) takeClosed() map[[2]uint64]struct{} {
	s.closedLock.Lock()
	defer s.closedLock.Unlock()
	closed := s.closed
	s.closed = make(map[[2]uint64]struct{})
	return closed
}

// Flush flips the epoch and drains the entries of the old one and of the connections that are gone
func (s *H2CSummaries) Flush() {
	s.flipLock.Lock()
	defer s.flipLock.Unlock()
	old := s.epoch.Load() & 1
	if err := s.epochs.Update(uint32(0), old^1, ebpf.UpdateAny); err != nil {
		// the closed connections are forgotten all the same: their entries are drained as stale by a later flush,
		// and the set does not grow while the flips fail
		s.takeClosed()
		partitionLog.Warnf("cannot flip the epoch of the h2c payload summaries: %v", err)
		return
	}
	s.epoch.Store(old ^ 1)
	// a program that read the old epoch may still be adding to an entry of it
	time.Sleep(s.grace)

	var drained []*events.H2CSummary
	var keys [][events.SummaryKeySize]byte
	scratch := &h2cTakeScratch{}
	iter := s.sums.Iterate()
	for iter.Next(&scratch.key, &scratch.value) {
		keys = append(keys, scratch.key)
	}
	if err := iter.Err(); err != nil {
		// what the walk found is drained, the rest the next time
		partitionLog.Warnf("cannot walk the h2c payload summaries: %v", err)
	}
	closed := s.takeClosed()
	active := make(map[[2]uint64]bool)
	for i := range keys {
		var summary events.H2CSummary
		events.DecodeSummaryKey(&summary, keys[i][:])
		reason := uint8(events.SummaryReasonFlush)
		if _, ok := closed[[2]uint64{summary.ConnectionID, summary.RandomID}]; ok {
			reason = events.SummaryReasonCloseDrain
		} else if !s.isActive(active, summary.ConnectionID, summary.RandomID) {
			reason = events.SummaryReasonStale
		} else if uint32(summary.Epoch) != old {
			// an entry of an active connection in the new epoch: it is still being made
			continue
		}
		if taken := s.take(scratch, &keys[i], reason); taken != nil {
			drained = append(drained, taken)
		}
	}
	// handed on after the walk: the queue of a partition may be full for a while
	for _, summary := range drained {
		s.deliver(summary)
	}
}

// isActive tells whether the connection is still in the active connections of BPF, once per flush
func (s *H2CSummaries) isActive(cache map[[2]uint64]bool, connectionID, randomID uint64) bool {
	if s.active == nil {
		return true
	}
	cacheKey := [2]uint64{connectionID, randomID}
	if active, ok := cache[cacheKey]; ok {
		return active
	}
	var conn common.ActiveConnection
	err := s.active.Lookup(connectionID, &conn)
	active := err == nil && (conn.RandomID == 0 || conn.RandomID == randomID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		active = true
	}
	cache[cacheKey] = active
	return active
}

// take looks the entry of the key up and deletes it: the summary when this delete removed it, nil otherwise.
// The scratch is the caller's own.
func (s *H2CSummaries) take(scratch *h2cTakeScratch, key *[events.SummaryKeySize]byte, reason uint8) *events.H2CSummary {
	scratch.key = *key
	if err := s.ops.lookupAndDelete(unsafe.Pointer(&scratch.key), unsafe.Pointer(&scratch.value)); err != nil {
		return nil
	}
	summary := &events.H2CSummary{}
	events.DecodeSummaryKey(summary, scratch.key[:])
	events.DecodeSummaryValue(summary, scratch.value[:])
	summary.Reason = reason
	return summary
}

// DrainStream takes the entries of the stream of the connection in the directions of the requests. The entry of
// the epoch new entries are made in comes first (a stream mostly lives within one epoch); the entry of the other
// epoch is looked up too unless the first one brought exactly the bytes the request misses, which are then every
// summary of the direction
func (s *H2CSummaries) DrainStream(connectionID, randomID uint64, streamID uint32,
	requests []protocols.HTTP2DrainRequest) []protocols.HTTP2Summary {
	s.drainLock.Lock()
	defer s.drainLock.Unlock()
	var result []protocols.HTTP2Summary
	var key [events.SummaryKeySize]byte
	current := uint8(s.epoch.Load() & 1)
	for _, req := range requests {
		var taken uint64
		for i, epoch := range [2]uint8{current, current ^ 1} {
			if i == 1 && req.Missing != 0 && taken == req.Missing {
				break
			}
			events.EncodeSummaryKey(key[:], connectionID, randomID, streamID, req.Direction, epoch)
			summary := s.take(&s.drainScratch, &key, events.SummaryReasonStreamDrain)
			if summary == nil {
				continue
			}
			taken += summary.Bytes
			result = append(result, summary)
		}
	}
	return result
}
