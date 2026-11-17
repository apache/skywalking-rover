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
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"sync/atomic"

	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

// The memory protection keeps the socket data events held in memory within max_memory_percent of the
// memory the agent can be allocated (memory_limit.go): the bytes the events in use hold (their pooled
// buffers plus a per event overhead) are known exactly and for free, so AcquireEvent refuses a new event
// as long as they are at the budget. That is all: what the events cost is what the analysis cannot keep
// up with, the rest of the process is small and steady.
var (
	memoryLimitBytes atomic.Int64 // the memory the agent can be allocated, 0: unknown
	memoryBudget     atomic.Int64 // bytes the events in use may hold, 0: protection off
	// eventOverhead is what one event in use costs besides its pooled buffer: the event itself and the
	// list element that holds it. The default is the rover's own event, which embeds the 20KB array.
	eventOverhead   atomic.Int64
	droppedByBudget atomic.Int64
)

const (
	// eventBookkeepingBytes: the list element and the interface that keep an event in a connection buffer
	eventBookkeepingBytes = 64
	// embeddedEventSize is the Go size class of an event that embeds the 20KB upload array
	embeddedEventSize = 21760

	defaultMaxMemoryPercent = 80
	// goSoftLimitPercent is the Go soft memory limit the agent sets, percent of its memory limit: the
	// events may hold max_memory_percent of it, and without the soft limit the GC lets the heap grow to
	// twice what is live (GOGC=100), past the limit
	goSoftLimitPercent = 90
)

// setMemoryLimit and lookupEnv are the runtime and the environment, replaced by the tests
var (
	setMemoryLimit = debug.SetMemoryLimit
	lookupEnv      = os.LookupEnv
)

// applyGoSoftLimit sets the Go soft memory limit to goSoftLimitPercent of the memory limit, once at
// startup, unless GOMEMLIMIT is set: that is the user's choice
func applyGoSoftLimit(limit int64) string {
	if v, set := lookupEnv("GOMEMLIMIT"); set && v != "" {
		return fmt.Sprintf("Go memory limit kept at GOMEMLIMIT=%s", v)
	}
	soft := limit * goSoftLimitPercent / 100
	setMemoryLimit(soft)
	return fmt.Sprintf("Go memory limit set to %d MB (%d%%)", soft>>20, goSoftLimitPercent)
}

func init() {
	eventOverhead.Store(embeddedEventSize + eventBookkeepingBytes)
}

// MemoryConfig is the configuration of the memory protection
type MemoryConfig struct {
	// MaxPercent: the events in use may hold this percent of the memory limit (0 disables the protection)
	MaxPercent int
	// EventSize: the size of one socket data event struct, 0 for an event that embeds the 20KB array
	EventSize int
}

// EnableMemoryProtection discovers the memory limit and sets the budget. It returns a description of
// what was configured, or an error when no limit could be determined (the protection then stays off).
func EnableMemoryProtection(cfg MemoryConfig) (string, error) {
	return enableMemoryProtection(cfg, defaultLimitDiscovery().discover())
}

func enableMemoryProtection(cfg MemoryConfig, found memoryLimit) (string, error) {
	if cfg.EventSize > 0 {
		eventOverhead.Store(int64(cfg.EventSize) + eventBookkeepingBytes)
	}
	memoryLimitBytes.Store(found.limit)
	if found.limit <= 0 {
		memoryBudget.Store(0)
		return "", fmt.Errorf("no memory limit found (no cgroup limit, no /proc/meminfo): memory protection disabled")
	}
	percent := cfg.MaxPercent
	if percent > 100 {
		percent = defaultMaxMemoryPercent
	}
	budget := found.limit * int64(percent) / 100
	memoryBudget.Store(budget)
	return fmt.Sprintf("limit %d MB from %s, the socket data events may hold %d MB (%d%%), %s",
		found.limit>>20, found.source, budget>>20, percent, applyGoSoftLimit(found.limit)), nil
}

// EnableMemoryProtectionFromConfig applies the configuration and logs the outcome
func EnableMemoryProtectionFromConfig(cfg MemoryConfig) {
	if cfg.MaxPercent <= 0 {
		log.Infof("memory protection disabled (max_memory_percent %d)", cfg.MaxPercent)
		return
	}
	desc, err := EnableMemoryProtection(cfg)
	if err != nil {
		log.Warnf("%v", err)
		return
	}
	log.Infof("memory protection enabled: %s", desc)
}

// InflightBytes is the memory held by the socket data events in use: their pooled buffers plus the
// overhead of each event. A compact record (ChargeRecord) has its own size in bytesInUse and only the
// bookkeeping of an event besides. Derived from the counters, so it costs nothing on the event path.
func InflightBytes() int64 {
	v := inflightBytes()
	if v < 0 {
		return 0
	}
	return v
}

// SetEventSize sets the size of the socket data event struct the memory protection charges an event in use
// besides its buffer (MemoryConfig.EventSize) and returns the size it had, for the tests that compare runs
// with compact records (charged CompactRecordSize) and with the events they stand for
func SetEventSize(size int) int {
	old := eventOverhead.Swap(int64(size) + eventBookkeepingBytes)
	return int(old - eventBookkeepingBytes)
}

// ChargeEmbeddedEvent charges an admitted event (AcquireEvent) whose struct embeds its data, of structSize bytes (the
// network profiling's event, which embeds the 20KB upload array), what its struct holds beyond the event overhead every
// event in use is charged: the overhead is the size of the access log's event when the access log set it
// (MemoryConfig.EventSize), far below such a struct. It returns the bytes charged (0 when the overhead covers the
// struct, as by default), which the event gives back with RefundEmbeddedEvent when it is released: the overhead may
// change in between (SetEventSize).
func ChargeEmbeddedEvent(structSize int) int {
	extra := int64(structSize) + eventBookkeepingBytes - eventOverhead.Load()
	if extra <= 0 {
		return 0
	}
	bytesInUse.Add(extra)
	return int(extra)
}

// RefundEmbeddedEvent gives back what ChargeEmbeddedEvent charged an event, before its release (ReleaseEvent)
func RefundEmbeddedEvent(charged int) {
	if charged > 0 {
		bytesInUse.Add(-int64(charged))
	}
}

// inflightBytes is InflightBytes before it is clamped at 0
func inflightBytes() int64 {
	records := recordsInUse.Load()
	return bytesInUse.Load() + (eventsInUse.Load()-records)*eventOverhead.Load() + records*eventBookkeepingBytes
}

// MemoryBudget is the bytes the socket data events in use may hold, 0 when the protection is off
func MemoryBudget() int64 {
	return memoryBudget.Load()
}

// SetMemoryBudget sets the budget in bytes (0 turns the protection off), for the tests of the packages
// that drive the protection; the agent sizes the budget in EnableMemoryProtection
func SetMemoryBudget(budget int64) {
	memoryBudget.Store(budget)
}

// the agent cannot be operated on a heap profile: these are the numbers that say whether the
// analysis is keeping up with the kernel, and they are the first thing to look at when it is not
func init() {
	telemetry.Register("rover_socket_data_events_in_use",
		"Socket data events held by the analysis, each holding a buffer of the upload chunk size",
		telemetry.Gauge, func() float64 { return float64(eventsInUse.Load()) })
	telemetry.Register("rover_socket_data_bytes_in_use",
		"Bytes the socket data events held by the analysis occupy, which the variable length upload "+
			"makes different from the event count times the chunk size; a compact HTTP/2 record counts its own size",
		telemetry.Gauge, func() float64 { return float64(bytesInUse.Load()) })
	telemetry.Register("rover_socket_data_events_accepted_total",
		"Socket data events taken from the kernel: the analysis cost follows this, not the bytes",
		telemetry.Counter, func() float64 { return float64(acceptedEvents.Load()) })
	telemetry.Register("rover_socket_data_bytes_total",
		"Bytes of socket data appended to a connection buffer, which against the event count is the average event",
		telemetry.Counter, func() float64 { return float64(acceptedBytes.Load()) })
	telemetry.RegisterSeries("rover_socket_data_buffers_taken_total",
		"Pooled socket data buffers taken, by size class: against rover_socket_data_bytes_total this "+
			"says how much of a class the payloads of that class actually use",
		telemetry.Counter, func() []telemetry.Sample {
			samples := make([]telemetry.Sample, len(bufferClasses))
			for i, class := range bufferClasses {
				samples[i] = telemetry.Sample{
					Labels: map[string]string{"class": strconv.Itoa(class)},
					Value:  float64(buffersTakenByClass[i].Load()),
				}
			}
			return samples
		})
	telemetry.Register("rover_socket_data_events_expired_total",
		"Socket data events released by the expiry rather than by an analyzer, so their message never completed",
		telemetry.Counter, func() float64 { return float64(expiredEvents.Load()) })
	telemetry.RegisterSeries("rover_socket_data_events_dropped_total",
		"Socket data events refused by the memory protection: the events in use held the memory budget",
		telemetry.Counter, func() []telemetry.Sample {
			return []telemetry.Sample{
				{Labels: map[string]string{dropReasonLabel: dropReasonLabels[DropReasonMemory]}, Value: float64(droppedByBudget.Load())},
			}
		})
	telemetry.Register("rover_socket_data_records_in_use",
		"Compact HTTP/2 call records held by the analysis (part of rover_socket_data_events_in_use), each "+
			"charged its own size instead of the event overhead",
		telemetry.Gauge, func() float64 { return float64(recordsInUse.Load()) })
	telemetry.Register("rover_socket_data_inflight_bytes",
		"Memory held by the socket data events in use (pooled buffers plus the per event overhead)",
		telemetry.Gauge, func() float64 { return float64(InflightBytes()) })
	telemetry.Register("rover_socket_data_inflight_budget_bytes",
		"Memory the socket data events in use may hold (max_memory_percent of the memory limit), 0 when "+
			"the protection is off",
		telemetry.Gauge, func() float64 { return float64(memoryBudget.Load()) })
	telemetry.Register("rover_memory_limit_bytes",
		"Memory the agent can be allocated (its cgroup limit, else the memory of the host), 0 when unknown",
		telemetry.Gauge, func() float64 { return float64(memoryLimitBytes.Load()) })
}
