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

package common

import (
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
)

// fakeResolutionFlusher is a FlusherListener that also implements ResolutionAwareFlusher
// so the ShouldDeferForResolution listener dispatch can be exercised without a real ztunnel
type fakeResolutionFlusher struct {
	pending bool
}

func (f *fakeResolutionFlusher) ReadyToFlushConnection(*ConnectionInfo, events.Event) {}
func (f *fakeResolutionFlusher) IsResolutionPending(*ConnectionInfo) bool             { return f.pending }
func (f *fakeResolutionFlusher) UnresolvedReason(*ConnectionInfo) string              { return "test-unresolved" }
func (f *fakeResolutionFlusher) FinalizeConnection(*ConnectionInfo)                   {}

// plainFlusher only implements FlusherListener(not ResolutionAwareFlusher), it must never
// cause a defer
type plainFlusher struct{}

func (p *plainFlusher) ReadyToFlushConnection(*ConnectionInfo, events.Event) {}

func newTestManager(grace time.Duration, listeners ...FlusherListener) *ConnectionManager {
	return &ConnectionManager{
		flushListeners:        listeners,
		resolutionGracePeriod: grace,
	}
}

func TestShouldDeferForResolution(t *testing.T) {
	t.Run("nil connection is never deferred", func(t *testing.T) {
		mgr := newTestManager(time.Second*7, &fakeResolutionFlusher{pending: true})
		if mgr.ShouldDeferForResolution(nil) {
			t.Fatal("nil connection should not be deferred")
		}
	})

	t.Run("no resolution-aware listener is never deferred", func(t *testing.T) {
		mgr := newTestManager(time.Second*7, &plainFlusher{})
		conn := &ConnectionInfo{}
		if mgr.ShouldDeferForResolution(conn) {
			t.Fatal("a plain flusher must not trigger a defer")
		}
	})

	t.Run("not pending is not deferred", func(t *testing.T) {
		mgr := newTestManager(time.Second*7, &fakeResolutionFlusher{pending: false})
		conn := &ConnectionInfo{}
		if mgr.ShouldDeferForResolution(conn) {
			t.Fatal("a not-pending connection must not be deferred")
		}
		if conn.ResolutionDeadline != nil {
			t.Fatal("no deadline should be recorded when not pending")
		}
	})

	t.Run("pending sets a deadline and defers on the first call", func(t *testing.T) {
		mgr := newTestManager(time.Second*7, &fakeResolutionFlusher{pending: true})
		conn := &ConnectionInfo{}
		if !mgr.ShouldDeferForResolution(conn) {
			t.Fatal("a pending connection should be deferred on the first flush")
		}
		if conn.ResolutionDeadline == nil {
			t.Fatal("a deadline should be recorded on the first defer")
		}
	})

	t.Run("pending within the grace deadline keeps deferring", func(t *testing.T) {
		mgr := newTestManager(time.Second*7, &fakeResolutionFlusher{pending: true})
		future := time.Now().Add(time.Second * 3)
		conn := &ConnectionInfo{ResolutionDeadline: &future}
		if !mgr.ShouldDeferForResolution(conn) {
			t.Fatal("a pending connection within its deadline should keep deferring")
		}
	})

	t.Run("pending past the grace deadline stops deferring", func(t *testing.T) {
		mgr := newTestManager(time.Second*7, &fakeResolutionFlusher{pending: true})
		past := time.Now().Add(-time.Second)
		conn := &ConnectionInfo{ResolutionDeadline: &past}
		if mgr.ShouldDeferForResolution(conn) {
			t.Fatal("a connection past its deadline must be flushed even if still pending")
		}
	})
}

func TestResolutionGraceForIs20s(t *testing.T) {
	// defaultFlushPeriod(5s) + resolutionDeferMargin(15s) = 20s, and the cap
	// connectionDeleteDelayTime(25s) - flushPeriod(5s) = 20s does not clip it
	if got := resolutionGraceFor(defaultFlushPeriod); got != 20*time.Second {
		t.Fatalf("resolutionGraceFor(defaultFlushPeriod) = %v, want 20s", got)
	}
	// grace must always stay strictly under the connection delete delay so a deferred
	// connection survives its whole grace window
	if got := resolutionGraceFor(defaultFlushPeriod); got >= connectionDeleteDelayTime {
		t.Fatalf("grace %v must stay under connectionDeleteDelayTime %v", got, connectionDeleteDelayTime)
	}
}
