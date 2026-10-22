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

import "testing"

func TestEventAdmission(t *testing.T) {
	defer memoryProtectionActive.Store(false)
	memoryProtectionActive.Store(false)
	base, dropped0, _, _ := MemoryStats()
	a := AcquireEventBuffer(MaxEventBufferSize)
	if a == nil {
		t.Fatal("below the threshold the buffer must be granted")
	}
	memoryProtectionActive.Store(true)
	if AcquireEventBuffer(MaxEventBufferSize) != nil || AcquireEvent() {
		t.Fatal("while the protection is active events must be refused")
	}
	inUse, dropped, _, _ := MemoryStats()
	if inUse-base != 1 || dropped-dropped0 != 2 {
		t.Fatalf("accounting: inUse=%d base=%d dropped=%d base=%d", inUse, base, dropped, dropped0)
	}
	memoryProtectionActive.Store(false)
	b := AcquireEventBuffer(MaxEventBufferSize)
	if b == nil {
		t.Fatal("after the protection is released events must be accepted again")
	}
	ReleaseEvent(a)
	ReleaseEvent(b)
	ReleaseEvent(nil) // an event that embeds its array still releases its slot
	eventsInUse.Add(1)
	if inUse, _, _, _ := MemoryStats(); inUse != base {
		t.Fatalf("slots not released: inUse=%d base=%d", inUse, base)
	}
}

func TestMemoryProtectionThresholdFromLimit(t *testing.T) {
	defer func() { memoryThreshold.Store(0); memoryProtectionActive.Store(false) }()
	desc, err := EnableMemoryProtection(90, 0)
	if err != nil {
		t.Skipf("no memory limit in this environment: %v", err)
	}
	if _, _, _, threshold := MemoryStats(); threshold <= 0 {
		t.Fatalf("threshold not set: %s", desc)
	}
	if _, err := EnableMemoryProtection(90, 123456); err != nil {
		t.Fatal(err)
	}
	if _, _, _, threshold := MemoryStats(); threshold != 123456 {
		t.Fatalf("absolute threshold must win: %d", threshold)
	}
}

// TestMemorySampleSwitchesTheProtection: the sampler decision itself (the only trigger of the
// protection) must switch the dropping of socket data events on and off
func TestMemorySampleSwitchesTheProtection(t *testing.T) {
	defer func() {
		memoryThreshold.Store(0)
		memoryProtectionActive.Store(false)
		applyMemorySample(0)
	}()
	memoryThreshold.Store(1000)

	if activated := applyMemorySample(999); activated || memoryProtectionActive.Load() {
		t.Fatal("below the threshold the protection must stay off")
	}
	if !AcquireEvent() {
		t.Fatal("below the threshold events must be accepted")
	}
	eventsInUse.Add(-1)

	if activated := applyMemorySample(1000); !activated || !memoryProtectionActive.Load() {
		t.Fatal("reaching the threshold must activate the protection")
	}
	_, dropped0, _, _ := MemoryStats()
	if AcquireEvent() {
		t.Fatal("while the protection is active events must be refused")
	}
	if _, dropped, _, _ := MemoryStats(); dropped-dropped0 != 1 {
		t.Fatalf("the refused event must be counted: %d", dropped-dropped0)
	}

	if activated := applyMemorySample(500); activated || memoryProtectionActive.Load() {
		t.Fatal("falling below the threshold must release the protection")
	}
	if !AcquireEvent() {
		t.Fatal("after the release events must be accepted again")
	}
	eventsInUse.Add(-1)
	if _, _, usage, threshold := MemoryStats(); usage != 500 || threshold != 1000 {
		t.Fatalf("the sample must be reported: usage=%d threshold=%d", usage, threshold)
	}
}
