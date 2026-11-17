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

package http1skip

import (
	"sync/atomic"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

type giveUpReason int

// why a followed message was given up
const (
	reasonLoss      giveUpReason = iota // the reader lost events
	reasonOrder                         // a call is missing or out of order
	reasonDirection                     // a call of the other direction came first
	reasonOverrun                       // the message ends inside a call (pipelining) or lost bytes of its framing
	reasonProtocol                      // TLS or another protocol on the connection
	reasonUnframed                      // a call the tracker does not frame
	reasonAge                           // the message runs too long
	reasonCount
)

var reasonNames = [reasonCount]string{"loss", "order", "direction", "overrun", "protocol", "unframed", "age"}

var (
	skippedEvents, skippedBytes atomic.Int64
	// skipWaits counts the body calls copied because the analyzer is not known to frame the calls as
	// the tracker does yet
	skipWaits atomic.Int64
	// unsyncedCalls counts the calls the tracker could not frame: the connection is copied until the
	// analyzer reported clean behind them
	unsyncedCalls atomic.Int64
	// overlaps counts the calls decoded after a skipped call with a larger data id
	overlaps atomic.Int64
	// holeWaits counts the body calls copied because a smaller data id of the connection was not decoded
	// yet: the call that took it may still upload and sort in front of the body calls
	holeWaits atomic.Int64
	// gapClears counts the calls that proved missing data ids of their connection to be calls that uploaded
	// nothing (they overlapped no other call)
	gapClears          atomic.Int64
	giveUps            [reasonCount]atomic.Int64
	trackedConnections atomic.Int64
)

func init() {
	telemetry.Register("rover_http1_body_skip_events_total",
		"HTTP/1 body socket calls decoded without their bytes (skip_http1_body_payload)", telemetry.Counter,
		func() float64 { return float64(skippedEvents.Load()) })
	telemetry.Register("rover_http1_body_skip_bytes_total",
		"Bytes of the HTTP/1 body socket calls decoded without their bytes", telemetry.Counter,
		func() float64 { return float64(skippedBytes.Load()) })
	telemetry.Register("rover_http1_body_skip_waits_total",
		"HTTP/1 body socket calls copied because the analyzer is not known to frame the calls alike yet",
		telemetry.Counter, func() float64 { return float64(skipWaits.Load()) })
	telemetry.Register("rover_http1_body_skip_unsynced_total",
		"HTTP/1 socket calls the body skipping could not frame: the connection is copied until the analyzer reported clean behind them",
		telemetry.Counter, func() float64 { return float64(unsyncedCalls.Load()) })
	telemetry.Register("rover_http1_body_skip_conflicts_total",
		"Reads that wanted the bytes of an HTTP/1 body call decoded without them, expected to stay 0",
		telemetry.Counter, func() float64 { return float64(buffer.BodySkipConflicts()) })
	telemetry.Register("rover_http1_body_skip_overlaps_total",
		"HTTP/1 socket calls decoded after a skipped call of the connection that was made later (overlapping calls)",
		telemetry.Counter, func() float64 { return float64(overlaps.Load()) })
	telemetry.Register("rover_http1_body_skip_hole_waits_total",
		"HTTP/1 body socket calls copied because a socket call of the connection with a smaller data id was not decoded (still to come, or uploaded nothing)",
		telemetry.Counter, func() float64 { return float64(holeWaits.Load()) })
	telemetry.Register("rover_http1_body_skip_gap_clears_total",
		"HTTP/1 socket calls that proved the missing data ids below them to be calls that uploaded nothing (no other call of the fd was in flight)",
		telemetry.Counter, func() float64 { return float64(gapClears.Load()) })
	telemetry.Register("rover_http1_body_skip_connections",
		"HTTP/1 connections the body skipping follows", telemetry.Gauge,
		func() float64 { return float64(trackedConnections.Load()) })
	telemetry.RegisterSeries("rover_http1_body_skip_give_ups_total",
		"Followed HTTP/1 messages given up, by reason", telemetry.Counter,
		func() []telemetry.Sample {
			samples := make([]telemetry.Sample, 0, reasonCount)
			for i := range giveUps {
				samples = append(samples, telemetry.Sample{Labels: map[string]string{"reason": reasonNames[i]},
					Value: float64(giveUps[i].Load())})
			}
			return samples
		})
}
