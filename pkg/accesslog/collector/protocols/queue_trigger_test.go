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

package protocols

import (
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	cmap "github.com/orcaman/concurrent-map"
)

// TestNoteDataEventTrigger: the partition asks for an immediate analysis once triggerEvents data
// events are waiting, and never when the trigger is disabled. The pending counter is reset by the
// analysis itself, so a trigger that could not run keeps asking for one.
func TestNoteDataEventTrigger(t *testing.T) {
	p := &PartitionContext{triggerEvents: 3, connections: cmap.New()}
	triggers := 0
	for i := 0; i < 10; i++ {
		if p.NoteDataEvent() {
			triggers++
			p.ProcessEvents() // the analysis resets the pending counter
		}
	}
	if triggers != 3 {
		t.Fatalf("expected 3 triggers for 10 events with a trigger count of 3, got %d", triggers)
	}
	disabled := &PartitionContext{}
	for i := 0; i < 10; i++ {
		if disabled.NoteDataEvent() {
			t.Fatal("a disabled trigger must never fire")
		}
	}
}

// countingProtocol counts the analyze calls and runs a callback on every one of them
type countingProtocol struct {
	calls  int
	onCall func()
}

func (c *countingProtocol) ForProtocol() enums.ConnectionProtocol {
	return enums.ConnectionProtocolHTTP
}

func (c *countingProtocol) GenerateConnection(_, _ uint64) ProtocolMetrics { return nil }

func (c *countingProtocol) Analyze(*PartitionConnection, *AnalyzeHelper) error {
	c.calls++
	if c.onCall != nil {
		c.onCall()
	}
	return nil
}

// TestProcessEventsRerunsAfterRefusedTrigger: a trigger that cannot run because another ProcessEvents
// holds the lock must not be lost; the running one repeats the pass
func TestProcessEventsRerunsAfterRefusedTrigger(t *testing.T) {
	p := &PartitionContext{triggerEvents: 1, connections: cmap.New()}
	analyzer := &countingProtocol{}
	p.connections.Set("1_1", &PartitionConnection{
		connectionID:       1,
		randomID:           1,
		dataBuffers:        map[enums.ConnectionProtocol]*buffer.Buffer{enums.ConnectionProtocolHTTP: buffer.NewBuffer()},
		protocol:           map[enums.ConnectionProtocol]uint64{enums.ConnectionProtocolHTTP: 0},
		protocolAnalyzer:   map[enums.ConnectionProtocol]Protocol{enums.ConnectionProtocolHTTP: analyzer},
		protocolMetrics:    map[enums.ConnectionProtocol]ProtocolMetrics{enums.ConnectionProtocolHTTP: nil},
		lastCheckCloseTime: time.Now(),
	})
	analyzer.onCall = func() {
		if analyzer.calls == 1 {
			// a trigger arrives while the analysis is running: ProcessEvents refuses it and asks for a rerun
			p.ProcessEvents()
		}
	}
	p.ProcessEvents()
	if analyzer.calls != 2 {
		t.Fatalf("the refused trigger must be repeated after the running analysis, analyze calls: %d", analyzer.calls)
	}
}
