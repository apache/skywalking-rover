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
	"errors"
	"fmt"
	"testing"
)

// withPressureListener records the states the listener is told, starting from no pressure
func withPressureListener(t *testing.T, fail *bool) *[]bool {
	t.Helper()
	pressureOn.Store(false)
	var told []bool
	SetPressureListener(func(on bool) error {
		if fail != nil && *fail {
			return errors.New("map update failed")
		}
		told = append(told, on)
		return nil
	})
	told = told[:0]
	t.Cleanup(func() {
		SetPressureListener(nil)
		pressureOn.Store(false)
	})
	return &told
}

// TestPressureHysteresis: the pressure goes on when an event is refused at the budget, stays on while the
// events in use hold 90% of the budget or more, and goes off once they fall below it; the listener is told
// each change once
func TestPressureHysteresis(t *testing.T) {
	withInflight(t, 100_000, 100, func() {
		told := withPressureListener(t, nil)
		_, dropped0, _, _ := MemoryStats()
		bytesInUse.Store(99_800)
		if !AcquireEvent() || UnderPressure() {
			t.Fatal("below the budget the event is admitted without pressure")
		}
		bytesInUse.Store(99_900) // + the event of 100 = the budget
		if AcquireEvent() || !UnderPressure() {
			t.Fatal("at the budget the event is refused and the pressure goes on")
		}
		if AcquireEvent() || fmt.Sprint(*told) != "[true]" {
			t.Fatalf("the listener is told once: %v", *told)
		}
		// released down to 95% of the budget: the user space admits events again, the pressure stays
		eventsInUse.Store(1)
		bytesInUse.Store(95_000)
		ReleaseEvent(nil)
		if !UnderPressure() || !AcquireEvent() || !UnderPressure() {
			t.Fatal("at 95% of the budget the pressure stays on while events are admitted")
		}
		// 90% exactly still holds it
		eventsInUse.Store(1)
		bytesInUse.Store(90_000)
		ReleaseEvent(nil)
		if !UnderPressure() {
			t.Fatalf("at 90%% of the budget (in use %d) the pressure stays on", InflightBytes())
		}
		eventsInUse.Store(1)
		bytesInUse.Store(89_999)
		ReleaseEvent(nil)
		if UnderPressure() || fmt.Sprint(*told) != "[true false]" {
			t.Fatalf("below 90%% the pressure goes off: %t, told %v", UnderPressure(), *told)
		}
		// the shed events count as dropped
		CountShedEvent()
		if _, dropped, _, _ := MemoryStats(); dropped-dropped0 != 3 {
			t.Fatalf("dropped %d, expected the 2 refused events and the shed one", dropped-dropped0)
		}
		// on again at the budget
		bytesInUse.Store(100_000)
		if AcquireEvent() || !UnderPressure() || fmt.Sprint(*told) != "[true false true]" {
			t.Fatalf("on again: %t, told %v", UnderPressure(), *told)
		}
		// the protection turned off releases the pressure at the next release
		memoryBudget.Store(0)
		eventsInUse.Store(1)
		ReleaseEvent(nil)
		if UnderPressure() || fmt.Sprint(*told) != "[true false true false]" {
			t.Fatalf("without a budget the pressure goes off: %t, told %v", UnderPressure(), *told)
		}
	})
}

// TestPressureListenerRetry: a listener that failed is told the state again at the next change, and a
// listener set while the pressure is on is told at once
func TestPressureListenerRetry(t *testing.T) {
	withInflight(t, 100_000, 100, func() {
		fail := true
		told := withPressureListener(t, &fail)
		bytesInUse.Store(100_000)
		if AcquireEvent() || !UnderPressure() || len(*told) != 0 {
			t.Fatalf("the failed apply is not recorded: %v", *told)
		}
		fail = false
		eventsInUse.Store(1)
		bytesInUse.Store(1_000)
		ReleaseEvent(nil)
		// off now, and the flag was never set: nothing to tell
		if UnderPressure() || len(*told) != 0 {
			t.Fatalf("told %v", *told)
		}
		bytesInUse.Store(100_000)
		if AcquireEvent() || fmt.Sprint(*told) != "[true]" {
			t.Fatalf("told %v", *told)
		}
		var late []bool
		SetPressureListener(func(on bool) error { late = append(late, on); return nil })
		if fmt.Sprint(late) != "[false true]" {
			t.Fatalf("a listener set under pressure is cleared, then told it at once: %v", late)
		}
	})
}

// TestPressurePeriodicRelease: the pressure is released by the periodic evaluation as well, when the
// events in use fell below 90% of the budget without a release this package saw (it never stays set)
func TestPressurePeriodicRelease(t *testing.T) {
	withInflight(t, 100_000, 100, func() {
		told := withPressureListener(t, nil)
		bytesInUse.Store(100_000)
		if AcquireEvent() || !UnderPressure() {
			t.Fatal("at the budget the pressure goes on")
		}
		evaluatePressure()
		if !UnderPressure() {
			t.Fatal("still at the budget the pressure stays on")
		}
		bytesInUse.Store(10_000)
		evaluatePressure()
		if UnderPressure() || fmt.Sprint(*told) != "[true false]" {
			t.Fatalf("the evaluation releases the pressure: %t, told %v", UnderPressure(), *told)
		}
	})
}
