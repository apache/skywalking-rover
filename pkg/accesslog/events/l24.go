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

package events

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The L2 to L4 details of the socket calls (access_log.kernel_metrics.l2_l3): BPF sends them at the exit of a call in
// an event of their own (struct socket_l24_event, bpf/accesslog/l24/l24.h), the L2L3 collector keeps them in an
// L24Store, and the kernel transfer log of the call (pkg/accesslog/forwarder/transfer.go) takes them from there by the
// connection, the random id and the data id of the call. The socket data event itself is not changed.

// L24Metrics are the L2 to L4 details of one socket call (or the sum of those of several calls, LookupRange)
type L24Metrics struct {
	L4Duration                    uint64
	L3Duration                    uint64
	L3RcvDuration                 uint64
	L3LocalDuration               uint64
	L3OutputDuration              uint64
	L3ResolveMacDuration          uint64
	L3NetFilterDuration           uint64
	L2Duration                    uint64
	L2ReadySendDuration           uint64
	L2SendDuration                uint64
	L2PackageToQueueDuration      uint64
	L2RcvPackageFromQueueDuration uint64
	IfIndex                       uint32
	// the sk_buffs __tcp_transmit_skb sent during a write and their bytes: the L4 package count and size of the
	// write when not 0 (the socket data event carries 1 and the bytes of the call otherwise)
	L4TransmitPackageCount   uint32
	L4TransmitPackageSize    uint64
	L3ResolveMacCount        uint32
	L3NetFilterCount         uint32
	L2EnterQueueCount        uint32
	L4RetransmitPackageCount uint32
	Direction                enums.SocketDataDirection
}

// Add sums the counters and durations of other into the metrics; the interface index stays the first one known
func (m *L24Metrics) Add(other *L24Metrics) {
	m.L4Duration += other.L4Duration
	m.L3Duration += other.L3Duration
	m.L3RcvDuration += other.L3RcvDuration
	m.L3LocalDuration += other.L3LocalDuration
	m.L3OutputDuration += other.L3OutputDuration
	m.L3ResolveMacDuration += other.L3ResolveMacDuration
	m.L3NetFilterDuration += other.L3NetFilterDuration
	m.L2Duration += other.L2Duration
	m.L2ReadySendDuration += other.L2ReadySendDuration
	m.L2SendDuration += other.L2SendDuration
	m.L2PackageToQueueDuration += other.L2PackageToQueueDuration
	m.L2RcvPackageFromQueueDuration += other.L2RcvPackageFromQueueDuration
	if m.IfIndex == 0 {
		m.IfIndex = other.IfIndex
	}
	m.L4TransmitPackageCount += other.L4TransmitPackageCount
	m.L4TransmitPackageSize += other.L4TransmitPackageSize
	m.L3ResolveMacCount += other.L3ResolveMacCount
	m.L3NetFilterCount += other.L3NetFilterCount
	m.L2EnterQueueCount += other.L2EnterQueueCount
	m.L4RetransmitPackageCount += other.L4RetransmitPackageCount
}

// SocketL24Event is struct socket_l24_event of bpf/accesslog/l24/l24.h (152 bytes)
type SocketL24Event struct {
	ConnectionID uint64
	RandomID     uint64
	DataID       uint64
	FunctionName uint8
	Metrics      L24Metrics
}

// ReadFrom reads the event in the order of its fields in BPF
func (e *SocketL24Event) ReadFrom(r btf.Reader) {
	e.ConnectionID = r.ReadUint64()
	e.RandomID = r.ReadUint64()
	e.DataID = r.ReadUint64()
	m := &e.Metrics
	m.L4Duration = r.ReadUint64()
	m.L3Duration = r.ReadUint64()
	m.L3RcvDuration = r.ReadUint64()
	m.L3LocalDuration = r.ReadUint64()
	m.L3OutputDuration = r.ReadUint64()
	m.L3ResolveMacDuration = r.ReadUint64()
	m.L3NetFilterDuration = r.ReadUint64()
	m.L2Duration = r.ReadUint64()
	m.L2ReadySendDuration = r.ReadUint64()
	m.L2SendDuration = r.ReadUint64()
	m.L2PackageToQueueDuration = r.ReadUint64()
	m.L2RcvPackageFromQueueDuration = r.ReadUint64()
	m.IfIndex = r.ReadUint32()
	m.L4TransmitPackageCount = r.ReadUint32()
	m.L4TransmitPackageSize = uint64(r.ReadUint32())
	m.L3ResolveMacCount = r.ReadUint32()
	m.L3NetFilterCount = r.ReadUint32()
	m.L2EnterQueueCount = r.ReadUint32()
	m.L4RetransmitPackageCount = uint32(r.ReadUint8())
	m.Direction = enums.SocketDataDirection(r.ReadUint8())
	e.FunctionName = r.ReadUint8()
	// (5 bytes of padding)
}

// L24Key is the socket call the details are of
type L24Key struct {
	ConnectionID uint64
	RandomID     uint64
	DataID       uint64
}

const l24StoreShards = 64

// L24Store keeps the L2 to L4 details of the socket calls until the kernel logs of the calls take them, bounded and
// expiring: an entry lives ttl after it came, and only grace after a kernel log took it (a socket call may be in the
// kernel logs of two protocol logs, the end of one message and the start of the next, or the frames of several
// HTTP/2 streams: the logs of a call are built within a flush or two of each other). A store at its capacity drops
// the details of a new call (counted): that call's kernel log is then built without them.
type L24Store struct {
	shards      [l24StoreShards]l24Shard
	ttl, grace  int64
	shardLimit  int
	now         func() int64
	dropped     atomic.Uint64
	expired     atomic.Uint64
	stopSweeper chan struct{}
	stopOnce    sync.Once
}

type l24Shard struct {
	mu      sync.Mutex
	entries map[L24Key]l24Entry
	// (a cache line per shard: the lock and the map of one shard are not on the line of another)
	_ [48]byte
}

type l24Entry struct {
	metrics L24Metrics
	// expire is the time (L24Store.now) the entry goes
	expire int64
}

// NewL24Store makes a store of at most capacity entries (at least one per shard), whose entries live ttl, and grace
// once a kernel log took them
func NewL24Store(capacity int, ttl, grace time.Duration) *L24Store {
	s := &L24Store{
		ttl:        int64(ttl),
		grace:      int64(grace),
		shardLimit: max(capacity/l24StoreShards, 1),
		now:        func() int64 { return time.Now().UnixNano() },
	}
	for i := range s.shards {
		s.shards[i].entries = make(map[L24Key]l24Entry)
	}
	return s
}

func (s *L24Store) shard(key L24Key) *l24Shard {
	h := key.ConnectionID*0x9e3779b97f4a7c15 ^ key.DataID*0xc2b2ae3d27d4eb4f ^ key.RandomID
	return &s.shards[(h>>32)%l24StoreShards]
}

// Put keeps the details of a call; false when the store is full and they were dropped
func (s *L24Store) Put(key L24Key, metrics *L24Metrics) bool {
	sh := s.shard(key)
	expire := s.now() + s.ttl
	sh.mu.Lock()
	if _, exists := sh.entries[key]; !exists && len(sh.entries) >= s.shardLimit {
		sh.mu.Unlock()
		s.dropped.Add(1)
		return false
	}
	sh.entries[key] = l24Entry{metrics: *metrics, expire: expire}
	sh.mu.Unlock()
	return true
}

// Lookup gives the details of the call, false when there are none; the entry then goes after the grace period
func (s *L24Store) Lookup(key L24Key) (L24Metrics, bool) {
	sh := s.shard(key)
	sh.mu.Lock()
	e, ok := sh.entries[key]
	if ok {
		if limit := s.now() + s.grace; e.expire > limit {
			e.expire = limit
			sh.entries[key] = e
		}
	}
	sh.mu.Unlock()
	return e.metrics, ok
}

// LookupRange sums the details of the calls of the connection of the direction with the data ids first to last (the
// calls of one event, see SocketDataUploadEvent.DataIDSpan), false when none has details
func (s *L24Store) LookupRange(connectionID, randomID, first, last uint64,
	direction enums.SocketDataDirection) (L24Metrics, bool) {
	var sum L24Metrics
	found := false
	for id := first; id <= last && id >= first; id++ {
		m, ok := s.Lookup(L24Key{ConnectionID: connectionID, RandomID: randomID, DataID: id})
		if !ok || m.Direction != direction {
			continue
		}
		if !found {
			sum, found = m, true
			continue
		}
		sum.Add(&m)
	}
	return sum, found
}

// Sweep removes the entries whose time has passed and returns how many
func (s *L24Store) Sweep() int {
	now := s.now()
	removed := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		//nolint:gocritic // ranging over the map values, the copy is cheaper than a second lookup of each key
		for key, e := range sh.entries {
			if e.expire <= now {
				delete(sh.entries, key)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	s.expired.Add(uint64(removed))
	return removed
}

// Len is the count of entries
func (s *L24Store) Len() int {
	n := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		n += len(sh.entries)
		sh.mu.Unlock()
	}
	return n
}

// Dropped is the count of details the full store dropped
func (s *L24Store) Dropped() uint64 { return s.dropped.Load() }

// Expired is the count of entries the sweeps removed
func (s *L24Store) Expired() uint64 { return s.expired.Load() }

// StartSweeper sweeps the store every period until Stop
func (s *L24Store) StartSweeper(period time.Duration) {
	s.stopSweeper = make(chan struct{})
	go func() {
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Sweep()
			case <-s.stopSweeper:
				return
			}
		}
	}()
}

// Stop stops the sweeper
func (s *L24Store) Stop() {
	s.stopOnce.Do(func() {
		if s.stopSweeper != nil {
			close(s.stopSweeper)
		}
	})
}

// l24Store is the store the kernel logs take the details from, nil while access_log.kernel_metrics.l2_l3 is off
var l24Store atomic.Pointer[L24Store]

// SetL24Store makes the kernel logs take the details of their calls from the store, nil turns that off
func SetL24Store(s *L24Store) {
	l24Store.Store(s)
}

// L24Enabled tells whether a store is set (SetL24Store)
func L24Enabled() bool {
	return l24Store.Load() != nil
}

// LookupL24 gives the L2 to L4 details of the socket call (or of the calls) the kernel log detail stands for: a socket
// data event (of coalesced calls: their sum) or a batch record; false without a store or without details
func LookupL24(detail SocketDetail) (L24Metrics, bool) {
	s := l24Store.Load()
	if s == nil {
		return L24Metrics{}, false
	}
	switch e := detail.(type) {
	case *SocketDataUploadEvent:
		if e.DataIDSpan == 0 {
			return s.Lookup(L24Key{ConnectionID: e.ConnectionID, RandomID: e.RandomID, DataID: e.DataID0})
		}
		return s.LookupRange(e.ConnectionID, e.RandomID, e.FirstDataID(), e.DataID0, e.Direction0)
	case *H2CRecord:
		return s.Lookup(L24Key{ConnectionID: e.ConnectionID, RandomID: e.RandomID, DataID: e.DataID0})
	}
	return L24Metrics{}, false
}
