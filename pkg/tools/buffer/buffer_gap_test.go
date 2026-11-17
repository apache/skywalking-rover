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
	"testing"
)

func gapTestBuffer(ids ...uint64) *Buffer {
	b := NewBuffer()
	for _, id := range ids {
		eventsInUse.Add(1) // as if admitted, the release takes it back
		b.AppendDataEvent(&testEvent{dataID: id, data: []byte("x")})
		b.AppendDetailEvent(&testDetail{dataID: id})
	}
	return b
}

type testDetail struct{ dataID uint64 }

func (d *testDetail) DataID() uint64 { return d.dataID }
func (d *testDetail) Time() uint64   { return 0 }

func dataIDs(b *Buffer) []uint64 {
	var ids []uint64
	for _, e := range b.TotalBuffer() {
		ids = append(ids, e.DataID())
	}
	return ids
}

func TestReleaseEventsBeforeAndFrom(t *testing.T) {
	before := eventsInUse.Load()
	b := gapTestBuffer(1, 2, 3, 5, 8, 9)
	if !b.PrepareForReading() {
		t.Fatal("expected data")
	}
	if n := b.ReleaseEventsBefore(4); n != 3 || b.head != nil {
		t.Fatalf("released %d, head %v", n, b.head)
	}
	if n := b.ReleaseEventsFrom(8); n != 2 {
		t.Fatalf("released %d", n)
	}
	if ids := dataIDs(b); len(ids) != 1 || ids[0] != 5 || b.detailEvents.Len() != 1 {
		t.Fatalf("left %v, details %d", ids, b.detailEvents.Len())
	}
	if n := b.ReleaseEventsBefore(5) + b.ReleaseEventsFrom(6); n != 0 {
		t.Fatalf("nothing outside the bounds must be released, released %d", n)
	}
	b.ReleaseAll()
	if eventsInUse.Load() != before {
		t.Fatalf("events in use %d, %d before", eventsInUse.Load(), before)
	}
}

func TestLastDataEventBefore(t *testing.T) {
	b := gapTestBuffer(1, 2, 3, 4)
	defer b.ReleaseAll()
	even := func(e SocketDataBuffer) bool { return e.DataID()%2 == 0 }
	if e := b.LastDataEventBefore(4, even); e == nil || e.DataID() != 2 {
		t.Fatalf("found %v", e)
	}
	if e := b.LastDataEventBefore(2, even); e != nil {
		t.Fatalf("found %v", e)
	}
}
