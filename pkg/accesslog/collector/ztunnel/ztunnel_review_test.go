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
	"context"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	ztunneltool "github.com/apache/skywalking-rover/pkg/tools/ztunnel"
)

// newTestCollector builds a Collector usable in unit tests: NewCollector does not set the context
// (that happens in Start), but downgrade -> startAccessLogTailer spawns a goroutine that selects on
// z.ctx.Done(), so the tests must provide one.
func newTestCollector(t *testing.T) *Collector {
	t.Helper()
	z := NewCollector(time.Minute)
	z.ctx, z.cancel = context.WithCancel(context.Background())
	t.Cleanup(z.cancel)
	return z
}

// identityUprobeEnabled is the switch the e2e uprobe/file matrix flips. Its shell twin in
// identity-source.sh must agree with it, so the accepted falsey values are pinned here.
func TestIdentityUprobeEnabled(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"", true}, // unset / empty -> enabled(the built-in default)
		{"true", true},
		{"TRUE", true},
		{"nope", true}, // any unrecognized value -> enabled
		{"1", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"no", false},
		{"off", false},
		{"OFF", false},
		{" false ", false}, // trimmed
	} {
		t.Setenv("ROVER_ZTUNNEL_IDENTITY_UPROBE_ENABLED", tc.val)
		if got := identityUprobeEnabled(); got != tc.want {
			t.Errorf("identityUprobeEnabled() with %q = %v; want %v", tc.val, got, tc.want)
		}
	}
}

// After ZTunnelIdentityDecodeFailureLimit consecutive full-window decode failures the path must
// downgrade to the access-log tailer. A zero window never decodes to an identity, so every event
// is a failure; the counter reaching the limit must flip `downgraded` and start the tailer.
func TestFullWindowDecodeFailuresDowngrade(t *testing.T) {
	z := newTestCollector(t)
	s := z.identitySource
	s.decoder.Store(newZTunnelIdentityDecoder(validOffsets(), newArcStrCache(16)))

	ev := &events.ZTunnelConnectionResultEvent{PID: 4242} // all-zero Data -> Decode always errors
	for i := 0; i < ZTunnelIdentityDecodeFailureLimit; i++ {
		s.HandleEvent(ev)
	}
	if !s.downgraded.Load() {
		t.Fatalf("expected downgrade after %d consecutive full-window decode failures", ZTunnelIdentityDecodeFailureLimit)
	}
	if !z.accessLogTailerStarted {
		t.Error("a downgrade must start the access-log tailer")
	}
}

// The compact path's downgrade net: a compact event that SHIPPED non-null identity pointers but
// decoded to no identity is counted as a failure; ZTunnelIdentityDecodeFailureLimit of them in a row
// must downgrade. Misaligned pointers are rejected by decodeArcStr WITHOUT a memory read, keeping the
// test deterministic.
func TestCompactDecodeFailuresDowngrade(t *testing.T) {
	z := newTestCollector(t)
	s := z.identitySource

	ev := &events.ZTunnelConnectionResultCompactEvent{
		PID: 4242, SrcIP: 0x0a000001, SrcPort: 1234, SrcPrincipalNsPtr: 0x1001, // misaligned, non-null
	}
	for i := 0; i < ZTunnelIdentityDecodeFailureLimit; i++ {
		s.HandleCompactEvent(ev)
	}
	if !s.downgraded.Load() {
		t.Fatalf("expected downgrade after %d consecutive compact decode failures", ZTunnelIdentityDecodeFailureLimit)
	}
	if !z.accessLogTailerStarted {
		t.Error("a downgrade must start the access-log tailer")
	}
}

// A compact event that shipped ALL-NULL identity pointers is a normal non-mTLS miss, NOT an offset
// mismatch, so no number of them may ever trip the downgrade - otherwise ordinary non-mTLS traffic
// would push a correctly-resolved probe onto the access-log fallback.
func TestCompactAllNullPointersDoNotDowngrade(t *testing.T) {
	z := newTestCollector(t)
	s := z.identitySource

	ev := &events.ZTunnelConnectionResultCompactEvent{PID: 4242, SrcIP: 0x0a000001, SrcPort: 1234}
	for i := 0; i < ZTunnelIdentityDecodeFailureLimit*2; i++ {
		s.HandleCompactEvent(ev)
	}
	if s.downgraded.Load() {
		t.Fatal("all-null-pointer(non-mTLS) events must never trip the downgrade")
	}
}

// accessLogEnabled gates the DST-identity flush deferral. It must be true when the identity uprobe is
// the SOLE source(an active decoder, no tailer) - otherwise a uprobe-only node would flush connections
// before their DST identity arrives.
func TestAccessLogEnabledWithActiveUprobe(t *testing.T) {
	z := NewCollector(time.Minute)
	if z.accessLogEnabled() {
		t.Fatal("no tailer and no decoder: the access-log deferral must be off")
	}
	z.identitySource.decoder.Store(newZTunnelIdentityDecoder(validOffsets(), newArcStrCache(16)))
	if !z.accessLogEnabled() {
		t.Error("an active identity uprobe(decoder set, not downgraded) must enable the access-log deferral")
	}
}

// decodeCompact must read the mutual-TLS byte ONLY when the offsets located the security_policy field.
// A calibrated set leaves it absent, so the shipped byte must be ignored and MutualTLS default to true;
// a set that DID locate it must honor the byte.
func TestDecodeCompactSecurityPolicyGating(t *testing.T) {
	mem := newFakeMemory()
	mem.writeArcStr(0x1000, "bookinfo")
	mem.writeArcStr(0x2000, "reviews")
	// event carries a non-mTLS security-policy byte(0); a valid source identity so decodeCompact succeeds
	ev := &events.ZTunnelConnectionResultCompactEvent{
		SrcIP: 0x0a2c0016, SrcPort: 41244,
		SrcPrincipalNsPtr: 0x1000, SrcPrincipalSaPtr: 0x2000,
		SecurityPolicy: 0,
	}

	absent := newZTunnelIdentitySource(nil)
	absent.decoder.Store(newZTunnelIdentityDecoder(&ztunneltool.Offsets{SecurityPolicy: ztunneltool.OffsetAbsent}, newArcStrCache(16)))
	if sm := absent.decodeCompact(ev, mem); sm == nil || !sm.MutualTLS {
		t.Errorf("security_policy absent: MutualTLS must default true, got %+v", sm)
	}

	present := newZTunnelIdentitySource(nil)
	present.decoder.Store(newZTunnelIdentityDecoder(&ztunneltool.Offsets{SecurityPolicy: 226}, newArcStrCache(16)))
	if sm := present.decodeCompact(ev, mem); sm == nil || sm.MutualTLS {
		t.Errorf("security_policy present + non-mTLS byte: MutualTLS must be false, got %+v", sm)
	}
}
