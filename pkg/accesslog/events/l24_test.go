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
	"encoding/binary"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// testL24Store is a store with a clock the test moves
func testL24Store(capacity int, ttl, grace time.Duration) (store *L24Store, now *int64) {
	s := NewL24Store(capacity, ttl, grace)
	clock := int64(1_000_000_000)
	s.now = func() int64 { return clock }
	return s, &clock
}

// TestL24StoreExpiry: an entry lives ttl, and grace once a kernel log took it; the sweep removes what expired
func TestL24StoreExpiry(t *testing.T) {
	s, clock := testL24Store(1000, 10*time.Second, 2*time.Second)
	taken, waiting := L24Key{1, 2, 3}, L24Key{1, 2, 4}
	s.Put(taken, &L24Metrics{IfIndex: 7, L3Duration: 100})
	s.Put(waiting, &L24Metrics{IfIndex: 8})
	m, ok := s.Lookup(taken)
	if !ok || m.IfIndex != 7 || m.L3Duration != 100 {
		t.Fatalf("lookup: %+v %v", m, ok)
	}
	// a second log of the call (the end of one message and the start of the next) still finds it
	if _, ok := s.Lookup(taken); !ok {
		t.Fatal("the second lookup within the grace period found nothing")
	}
	*clock += int64(3 * time.Second)
	if n := s.Sweep(); n != 1 || s.Len() != 1 {
		t.Fatalf("swept %d, %d left", n, s.Len())
	}
	if _, ok := s.Lookup(taken); ok {
		t.Fatal("the taken entry outlived its grace period")
	}
	*clock += int64(8 * time.Second)
	if n := s.Sweep(); n != 1 || s.Len() != 0 || s.Expired() != 2 {
		t.Fatalf("swept %d, %d left, %d expired", n, s.Len(), s.Expired())
	}
	if _, ok := s.Lookup(L24Key{9, 9, 9}); ok {
		t.Fatal("found a call that sent nothing")
	}
}

// TestL24StoreCapacity: a full store drops the details of a new call (counted) and still replaces those of a known one
func TestL24StoreCapacity(t *testing.T) {
	s, _ := testL24Store(l24StoreShards, time.Minute, time.Second) // one entry per shard
	first := L24Key{1, 1, 1}
	if !s.Put(first, &L24Metrics{IfIndex: 1}) {
		t.Fatal("the first entry was dropped")
	}
	// a key of the same shard
	var other L24Key
	for id := uint64(2); ; id++ {
		other = L24Key{1, 1, id}
		if s.shard(other) == s.shard(first) {
			break
		}
	}
	if s.Put(other, &L24Metrics{IfIndex: 2}) || s.Dropped() != 1 {
		t.Fatalf("a full shard took a new entry, %d dropped", s.Dropped())
	}
	if !s.Put(first, &L24Metrics{IfIndex: 3}) {
		t.Fatal("a full shard refused to replace an entry")
	}
	if m, _ := s.Lookup(first); m.IfIndex != 3 {
		t.Fatalf("the entry is %+v", m)
	}
}

// TestL24StoreLookupRange: the calls of a coalesced event, of its direction only, summed with the first interface
func TestL24StoreLookupRange(t *testing.T) {
	s, _ := testL24Store(1000, time.Minute, time.Second)
	egress, ingress := enums.SocketDataDirectionEgress, enums.SocketDataDirectionIngress
	s.Put(L24Key{5, 1, 10}, &L24Metrics{Direction: egress, IfIndex: 0, L3Duration: 1, L4TransmitPackageCount: 1, L4TransmitPackageSize: 100})
	s.Put(L24Key{5, 1, 11}, &L24Metrics{Direction: egress, IfIndex: 4, L3Duration: 2, L4TransmitPackageCount: 2, L4TransmitPackageSize: 200})
	s.Put(L24Key{5, 1, 12}, &L24Metrics{Direction: ingress, IfIndex: 9, L3Duration: 50})
	s.Put(L24Key{5, 1, 13}, &L24Metrics{Direction: egress, IfIndex: 6, L3Duration: 4, L2EnterQueueCount: 1})
	s.Put(L24Key{5, 2, 13}, &L24Metrics{Direction: egress, L3Duration: 1000}) // another connection on the fd
	m, ok := s.LookupRange(5, 1, 10, 13, egress)
	if !ok || m.L3Duration != 7 || m.IfIndex != 4 || m.L4TransmitPackageCount != 3 || m.L4TransmitPackageSize != 300 ||
		m.L2EnterQueueCount != 1 {
		t.Fatalf("range: %+v %v", m, ok)
	}
	if _, ok := s.LookupRange(5, 1, 20, 30, egress); ok {
		t.Fatal("a range without details found some")
	}
}

// TestSocketL24EventReadFrom: the event is read in the layout of struct socket_l24_event (bpf/accesslog/l24/l24.h)
func TestSocketL24EventReadFrom(t *testing.T) {
	sample := make([]byte, 152)
	for i := 0; i < 15; i++ {
		binary.LittleEndian.PutUint64(sample[i*8:], uint64(100+i))
	}
	for i := 0; i < 6; i++ {
		binary.LittleEndian.PutUint32(sample[120+i*4:], uint32(200+i))
	}
	sample[144], sample[145], sample[146] = 3, 1, 9
	var e SocketL24Event
	r := btf.NewReader(sample)
	e.ReadFrom(r)
	if r.HasError() != nil {
		t.Fatal(r.HasError())
	}
	m := e.Metrics
	want := L24Metrics{
		L4Duration: 103, L3Duration: 104, L3RcvDuration: 105, L3LocalDuration: 106, L3OutputDuration: 107,
		L3ResolveMacDuration: 108, L3NetFilterDuration: 109, L2Duration: 110, L2ReadySendDuration: 111,
		L2SendDuration: 112, L2PackageToQueueDuration: 113, L2RcvPackageFromQueueDuration: 114,
		IfIndex: 200, L4TransmitPackageCount: 201, L4TransmitPackageSize: 202, L3ResolveMacCount: 203,
		L3NetFilterCount: 204, L2EnterQueueCount: 205, L4RetransmitPackageCount: 3, Direction: 1,
	}
	if e.ConnectionID != 100 || e.RandomID != 101 || e.DataID != 102 || e.FunctionName != 9 || m != want {
		t.Fatalf("read %+v", e)
	}
}

// TestLookupL24OfDetails: the details of the call of an event, of the calls of a coalesced one, of a batch record; none
// without a store
func TestLookupL24OfDetails(t *testing.T) {
	s, _ := testL24Store(1000, time.Minute, time.Second)
	egress := enums.SocketDataDirectionEgress
	for id := uint64(1); id <= 4; id++ {
		s.Put(L24Key{7, 3, id}, &L24Metrics{Direction: egress, IfIndex: 2, L3Duration: id})
	}
	one := &SocketDataUploadEvent{ConnectionID: 7, RandomID: 3, DataID0: 2, Direction0: egress}
	coalesced := &SocketDataUploadEvent{ConnectionID: 7, RandomID: 3, DataID0: 4, DataIDSpan: 2, Direction0: egress}
	record := &H2CRecord{ConnectionID: 7, RandomID: 3, DataID0: 1}
	if _, ok := LookupL24(one); ok {
		t.Fatal("details without a store")
	}
	SetL24Store(s)
	defer SetL24Store(nil)
	if m, ok := LookupL24(one); !ok || m.L3Duration != 2 {
		t.Fatalf("one call: %+v %v", m, ok)
	}
	if m, ok := LookupL24(coalesced); !ok || m.L3Duration != 2+3+4 {
		t.Fatalf("coalesced calls: %+v %v", m, ok)
	}
	if m, ok := LookupL24(record); !ok || m.L3Duration != 1 {
		t.Fatalf("record: %+v %v", m, ok)
	}
}
