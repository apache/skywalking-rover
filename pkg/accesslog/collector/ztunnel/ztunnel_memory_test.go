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

package ztunnel

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"testing"
)

// fakeMemory is an in-memory stand-in for a monitored process' address space, so the ArcStr
// decoding can be tested without a live ztunnel.
type fakeMemory struct {
	regions map[uint64][]byte
	reads   atomic.Int64
}

func newFakeMemory() *fakeMemory {
	return &fakeMemory{regions: make(map[uint64][]byte)}
}

// writeArcStr lays out an arcstr ThinInner at addr:
// len_flag(len<<1) | count_flag | data.
func (f *fakeMemory) writeArcStr(addr uint64, value string) {
	buf := make([]byte, arcStrDataOffset+len(value))
	binary.LittleEndian.PutUint64(buf[0:8], uint64(len(value))<<1)
	binary.LittleEndian.PutUint64(buf[8:16], 1)
	copy(buf[arcStrDataOffset:], value)
	f.regions[addr] = buf
}

func (f *fakeMemory) ReadAt(p []byte, addr uint64) error {
	f.reads.Add(1)
	for base, data := range f.regions {
		if addr < base || addr >= base+uint64(len(data)) {
			continue
		}
		off := addr - base
		if off+uint64(len(p)) > uint64(len(data)) {
			return fmt.Errorf("short region at 0x%x", addr)
		}
		copy(p, data[off:])
		return nil
	}
	return fmt.Errorf("unmapped address 0x%x", addr)
}

func TestDecodeArcStr(t *testing.T) {
	mem := newFakeMemory()
	mem.writeArcStr(0x1000, "default")
	mem.writeArcStr(0x2000, "bookinfo-productpage")

	c := newArcStrCache(16)

	if got, ok := c.decodeArcStr(mem, 0x1000); !ok || got != "default" {
		t.Fatalf("decode 0x1000 = %q,%v; want \"default\",true", got, ok)
	}
	if got, ok := c.decodeArcStr(mem, 0x2000); !ok || got != "bookinfo-productpage" {
		t.Fatalf("decode 0x2000 = %q,%v; want \"bookinfo-productpage\",true", got, ok)
	}
}

// a null pointer is the None of Option<Strng>(niche encoded), a normal "field absent"
// outcome rather than a decode failure
func TestDecodeArcStrNullIsAbsentNotFailure(t *testing.T) {
	c := newArcStrCache(16)
	got, ok := c.decodeArcStr(newFakeMemory(), 0)
	if !ok || got != "" {
		t.Fatalf("decode null = %q,%v; want \"\",true", got, ok)
	}
}

// the pointer cache is what makes reading identities from userspace cheap: the same workload's
// ArcStr recurs for every connection, so a repeat decode must not touch process memory again
func TestDecodeArcStrCachesByPointer(t *testing.T) {
	mem := newFakeMemory()
	mem.writeArcStr(0x1000, "default")
	c := newArcStrCache(16)

	if _, ok := c.decodeArcStr(mem, 0x1000); !ok {
		t.Fatal("first decode failed")
	}
	readsAfterFirst := mem.reads.Load()
	if _, ok := c.decodeArcStr(mem, 0x1000); !ok {
		t.Fatal("second decode failed")
	}
	if mem.reads.Load() != readsAfterFirst {
		t.Fatalf("second decode did %d extra memory reads; want 0", mem.reads.Load()-readsAfterFirst)
	}
}

// A wrong offset hands the decoder a value that is not an ArcStr pointer. Every such case must
// be REJECTED rather than turned into a garbage identity, because a garbage identity would be
// reported to the backend as if it were real. These are the cases the plausibility guards cover.
func TestDecodeArcStrRejectsImplausible(t *testing.T) {
	mem := newFakeMemory()
	// unreasonable length: len_flag decodes to way past arcStrMaxLen
	mem.regions[0x3000] = func() []byte {
		buf := make([]byte, arcStrDataOffset+8)
		binary.LittleEndian.PutUint64(buf[0:8], uint64(1<<20)<<1)
		return buf
	}()
	// plausible length but the bytes are not printable ASCII
	mem.regions[0x4000] = func() []byte {
		buf := make([]byte, arcStrDataOffset+4)
		binary.LittleEndian.PutUint64(buf[0:8], uint64(4)<<1)
		copy(buf[arcStrDataOffset:], []byte{0x00, 0xff, 0x01, 0x7f})
		return buf
	}()
	// zero length is not a useful identity either
	mem.regions[0x5000] = make([]byte, arcStrDataOffset)

	c := newArcStrCache(16)
	for _, tc := range []struct {
		name string
		ptr  uint64
	}{
		{"length out of range", 0x3000},
		{"non printable bytes", 0x4000},
		{"zero length", 0x5000},
		{"misaligned pointer", 0x1004},
		{"unmapped pointer", 0x9000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := c.decodeArcStr(mem, tc.ptr); ok {
				t.Fatalf("decode 0x%x unexpectedly succeeded with %q", tc.ptr, got)
			}
		})
	}
}
