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
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

// The pressure of the memory protection, for the kernel: once AcquireEvent refuses an event because the
// events in use hold the budget, the pressure is on, and it stays on until they fall back below
// pressureReleasePercent of the budget (the hysteresis keeps it from flapping at the budget). A listener
// (SetPressureListener) is told every change: the access log sets a flag in BPF with it, and BPF then sends
// only a small event per socket call instead of its data, which the reader takes for a refused one
// (CountShedEvent), instead of copying the data out of the perf ring only to drop it here.
//
// AcquireEvent itself does not follow the pressure: it still admits an event whenever the events in use
// hold less than the budget, as before.
const pressureReleasePercent = 90

var (
	pressureOn       atomic.Bool
	pressureListener atomic.Pointer[pressureCallback]
	// pressureMu serializes the listener calls: whoever calls it tells the state as it is then, so the
	// last call always tells the last state, whatever order the changes raced in
	pressureMu      sync.Mutex
	pressureApplied bool
	pressureChanges atomic.Int64
	shedEvents      atomic.Int64
	// the calls and the bytes the memory protection dropped, by who dropped them (dropReason*)
	droppedCalls, droppedBytes [2]atomic.Int64
	pressureTicker             sync.Once
)

// pressureCheckInterval is how often the pressure is evaluated besides the releases: the flag never stays
// set because no event happens to be released, and a listener whose apply failed is told again
const pressureCheckInterval = time.Second

// the reasons a socket call, or bytes of it, were dropped by the memory protection
const (
	// DropReasonMemory: the user space refused the event after it was copied out of the perf ring
	DropReasonMemory = 0
	// DropReasonKernelShed: the kernel sent the call without its data because of the pressure
	DropReasonKernelShed = 1
)

var dropReasonLabels = [2]string{"memory", "kernel_shed"}

// dropReasonLabel is the name of the label of the drop reason (dropReasonLabels)
const dropReasonLabel = "reason"

// CountDroppedCall counts a socket call, or a part of one, the memory protection dropped: calls is 1 for
// the first part of a call (0 for the others), bytes are the bytes of the call that were lost with it
func CountDroppedCall(reason int, calls, bytes int64) {
	droppedCalls[reason].Add(calls)
	droppedBytes[reason].Add(bytes)
}

// DroppedCalls returns the calls and the bytes the memory protection dropped for the reason
func DroppedCalls(reason int) (calls, bytes int64) {
	return droppedCalls[reason].Load(), droppedBytes[reason].Load()
}

type pressureCallback struct {
	apply func(on bool) error
}

// SetPressureListener hands every change of the pressure to apply, the current state at once; nil removes
// it. A failed apply is retried at the next change.
func SetPressureListener(apply func(on bool) error) {
	pressureMu.Lock()
	if apply == nil {
		pressureListener.Store(nil)
	} else {
		pressureListener.Store(&pressureCallback{apply: apply})
		// cleared under the lock: a change applied meanwhile (applyPressure takes the lock) comes after it, so
		// the flag and pressureApplied never disagree
		if err := apply(false); err != nil {
			log.Warnf("cannot clear the memory pressure flag: %v", err)
		}
	}
	pressureApplied = false
	pressureMu.Unlock()
	if apply != nil {
		pressureTicker.Do(func() {
			go func() {
				for range time.Tick(pressureCheckInterval) {
					evaluatePressure()
				}
			}()
		})
		applyPressure()
	}
}

// UnderPressure tells whether the pressure is on
func UnderPressure() bool {
	return pressureOn.Load()
}

// CountShedEvent counts an event the kernel sent without its data because of the pressure: it is what a
// refused event would have been, so it counts as dropped by the memory protection
func CountShedEvent() {
	droppedByBudget.Add(1)
	shedEvents.Add(1)
}

// AdmitShedEvent admits the event a call the kernel sent without its data decodes into, whatever the
// budget: it only carries the details of its call, and ReleaseEvent gives it back as any event
func AdmitShedEvent() {
	eventsInUse.Add(1)
}

// notePressure is called when AcquireEvent refuses an event
func notePressure() {
	if pressureOn.CompareAndSwap(false, true) {
		pressureChanges.Add(1)
		applyPressure()
	}
}

// checkPressureRelease turns the pressure off once the events in use hold less than
// pressureReleasePercent of the budget, or the protection is off. It is called whenever events are
// released while the pressure is on.
func checkPressureRelease() {
	budget := memoryBudget.Load()
	if budget > 0 && InflightBytes() >= budget/100*pressureReleasePercent {
		return
	}
	if pressureOn.CompareAndSwap(true, false) {
		pressureChanges.Add(1)
		applyPressure()
	}
}

// evaluatePressure releases the pressure when it is due and tells the listener the state it was not told
func evaluatePressure() {
	if pressureOn.Load() {
		checkPressureRelease()
	}
	applyPressure()
}

func applyPressure() {
	listener := pressureListener.Load()
	if listener == nil {
		return
	}
	pressureMu.Lock()
	defer pressureMu.Unlock()
	on := pressureOn.Load()
	if on == pressureApplied {
		return
	}
	if err := listener.apply(on); err != nil {
		log.Warnf("cannot set the memory pressure flag to %t: %v", on, err)
		return
	}
	pressureApplied = on
}

func init() {
	telemetry.Register("rover_socket_data_pressure",
		"1 while the memory protection has the kernel send the socket calls without their data (the events "+
			"in use reached the budget and have not fallen below 90% of it since), 0 otherwise",
		telemetry.Gauge, func() float64 {
			if pressureOn.Load() {
				return 1
			}
			return 0
		})
	telemetry.Register("rover_socket_data_pressure_changes_total",
		"Times the memory pressure was turned on or off",
		telemetry.Counter, func() float64 { return float64(pressureChanges.Load()) })
	for _, kind := range []struct {
		name, help string
		counters   *[2]atomic.Int64
	}{
		{"rover_socket_data_dropped_calls_total", "Socket calls whose data the memory protection dropped, by reason: " +
			"memory (the user space refused the first event of the call), kernel_shed (the kernel sent the call " +
			"without its data under pressure)", &droppedCalls},
		{"rover_socket_data_dropped_bytes_total", "Bytes of socket calls the memory protection dropped, by reason: " +
			"memory (the data of the refused events), kernel_shed (the size of the calls sent without their data)",
			&droppedBytes},
	} {
		counters := kind.counters
		telemetry.RegisterSeries(kind.name, kind.help, telemetry.Counter, func() []telemetry.Sample {
			samples := make([]telemetry.Sample, len(dropReasonLabels))
			for i, label := range dropReasonLabels {
				samples[i] = telemetry.Sample{Labels: map[string]string{dropReasonLabel: label}, Value: float64(counters[i].Load())}
			}
			return samples
		})
	}
	telemetry.Register("rover_socket_data_events_shed_total",
		"Socket data events the kernel sent without their data because of the memory pressure, also counted "+
			"as dropped by the memory protection",
		telemetry.Counter, func() float64 { return float64(shedEvents.Load()) })
}
