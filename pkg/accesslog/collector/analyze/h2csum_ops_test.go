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
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
)

// fakeSumMapCalls is h2c_sum_map as ebpfSumOps calls it: one entry, and whether the kernel has lookup-and-delete
type fakeSumMapCalls struct {
	value                  [events.SummaryValueSize]byte
	present                bool
	noLAD                  bool // the kernel has no lookup-and-delete for a hash map
	ladAfter               int  // lookup-and-delete calls that work before the kernel says it has none (0: always works)
	deleteRace             bool // BPF deletes the entry between the lookup and the delete
	lads, lookups, deletes int
}

func (f *fakeSumMapCalls) LookupAndDelete(key, value interface{}) error {
	f.lads++
	if f.noLAD || (f.ladAfter > 0 && f.lads > f.ladAfter) {
		return ebpf.ErrNotSupported
	}
	if k := (*[events.SummaryKeySize]byte)(key.(unsafe.Pointer)); k[22] != 0 || k[23] != 0 {
		return ebpf.ErrKeyNotExist // the probe: a key BPF never makes
	}
	if !f.present {
		return ebpf.ErrKeyNotExist
	}
	*(*[events.SummaryValueSize]byte)(value.(unsafe.Pointer)) = f.value
	f.present = false
	return nil
}

func (f *fakeSumMapCalls) Lookup(_, value interface{}) error {
	f.lookups++
	if !f.present {
		return ebpf.ErrKeyNotExist
	}
	*(*[events.SummaryValueSize]byte)(value.(unsafe.Pointer)) = f.value
	return nil
}

func (f *fakeSumMapCalls) Delete(interface{}) error {
	f.deletes++
	if f.deleteRace || !f.present {
		f.present = false
		return ebpf.ErrKeyNotExist
	}
	f.present = false
	return nil
}

func takeWith(o *ebpfSumOps) ([events.SummaryValueSize]byte, error) {
	var key [events.SummaryKeySize]byte
	var value [events.SummaryValueSize]byte
	err := o.lookupAndDelete(unsafe.Pointer(&key), unsafe.Pointer(&value))
	return value, err
}

// TestSumOpsFallback: a kernel without lookup-and-delete for a hash map (probed on the first take, or found on a
// later one) takes an entry with a lookup and a delete, and an entry BPF deletes in between is not taken
func TestSumOpsFallback(t *testing.T) {
	want := [events.SummaryValueSize]byte{1, 2, 3}

	f := &fakeSumMapCalls{value: want, present: true, noLAD: true}
	o := &ebpfSumOps{m: f}
	if v, err := takeWith(o); err != nil || v != want || o.mode.Load() != sumOpsLookupDelete || f.lookups != 1 || f.deletes != 1 {
		t.Fatalf("probed without lookup-and-delete: %v %v, mode %d, %d lookups, %d deletes", v, err, o.mode.Load(), f.lookups, f.deletes)
	}

	// the probe works, a later take finds the kernel has none after all: that take falls back at once
	f = &fakeSumMapCalls{value: want, present: true, ladAfter: 1}
	o = &ebpfSumOps{m: f}
	if v, err := takeWith(o); err != nil || v != want || o.mode.Load() != sumOpsLookupDelete || f.lookups != 1 {
		t.Fatalf("found without lookup-and-delete: %v %v, mode %d, %d lookups", v, err, o.mode.Load(), f.lookups)
	}
	if _, err := takeWith(o); !errors.Is(err, ebpf.ErrKeyNotExist) || f.lads != 2 {
		t.Fatalf("a taken entry is taken again: %v, %d lookup-and-deletes", err, f.lads)
	}

	// BPF sends and deletes the entry between the lookup and the delete: it has it
	f = &fakeSumMapCalls{value: want, present: true, noLAD: true, deleteRace: true}
	o = &ebpfSumOps{m: f}
	if _, err := takeWith(o); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("an entry BPF deleted is taken: %v", err)
	}

	// with lookup-and-delete: one call, and nothing when there is no entry
	f = &fakeSumMapCalls{value: want, present: true}
	o = &ebpfSumOps{m: f}
	if v, err := takeWith(o); err != nil || v != want || o.mode.Load() != sumOpsLookupAndDelete || f.lookups != 0 {
		t.Fatalf("with lookup-and-delete: %v %v, mode %d, %d lookups", v, err, o.mode.Load(), f.lookups)
	}
	if _, err := takeWith(o); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("no entry: %v", err)
	}
}
