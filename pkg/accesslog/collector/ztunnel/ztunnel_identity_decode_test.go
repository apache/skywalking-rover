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
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	ztunneltool "github.com/apache/skywalking-rover/pkg/tools/ztunnel"
)

// garbage lays out an ArcStr whose bytes are NOT printable ASCII at addr, the way a wrong offset
// hands the decoder a pointer into memory that is not really a Strng. decodeArcStr must reject it.
func (f *fakeMemory) garbage(addr uint64) {
	buf := make([]byte, arcStrDataOffset+4)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(4)<<1)
	copy(buf[arcStrDataOffset:], []byte{0x00, 0xff, 0x01, 0x7f})
	f.regions[addr] = buf
}

// compactShippedIdentityPointer is the gate that decides whether a compact event that decoded to
// NO identity should count towards the access-log downgrade. It must be true only when the probe
// actually shipped a non-null pointer(ztunnel held an identity there, so a failure to decode it is
// evidence the offsets are wrong) and false when every pointer is null(a non-mTLS leg that simply
// carried no identity - ordinary traffic that must never trip the fallback).
func TestCompactShippedIdentityPointer(t *testing.T) {
	if compactShippedIdentityPointer(&events.ZTunnelConnectionResultCompactEvent{}) {
		t.Fatal("an event with all-null identity pointers must NOT count towards the downgrade")
	}
	for _, tc := range []struct {
		name  string
		mutar func(e *events.ZTunnelConnectionResultCompactEvent)
	}{
		{"src principal ns", func(e *events.ZTunnelConnectionResultCompactEvent) { e.SrcPrincipalNsPtr = 0x10 }},
		{"src principal sa", func(e *events.ZTunnelConnectionResultCompactEvent) { e.SrcPrincipalSaPtr = 0x10 }},
		{"dst principal ns", func(e *events.ZTunnelConnectionResultCompactEvent) { e.DstPrincipalNsPtr = 0x10 }},
		{"dst principal sa", func(e *events.ZTunnelConnectionResultCompactEvent) { e.DstPrincipalSaPtr = 0x10 }},
		{"src namespace", func(e *events.ZTunnelConnectionResultCompactEvent) { e.SrcNamespacePtr = 0x10 }},
		{"dst namespace", func(e *events.ZTunnelConnectionResultCompactEvent) { e.DstNamespacePtr = 0x10 }},
		{"src cluster", func(e *events.ZTunnelConnectionResultCompactEvent) { e.SrcClusterPtr = 0x10 }},
		{"dst cluster", func(e *events.ZTunnelConnectionResultCompactEvent) { e.DstClusterPtr = 0x10 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &events.ZTunnelConnectionResultCompactEvent{}
			tc.mutar(e)
			if !compactShippedIdentityPointer(e) {
				t.Fatalf("a non-null %s pointer must count towards the downgrade", tc.name)
			}
		})
	}
}

// An absent principal offset means its inline Identity fields were not resolved. The fallback
// namespace and cluster remain usable, but bytes immediately before ConnectionResult start must
// never be interpreted as principal pointers by adding the relative member offsets to -1.
func TestDecodeAbsentPrincipalDoesNotReadRelativeIdentityOffsets(t *testing.T) {
	offsets := validOffsets()
	offsets.SourcePrincipal = ztunneltool.OffsetAbsent
	window := make([]byte, offsets.Window)
	mem := newFakeMemory()
	mem.writeArcStr(0x1000, "misplaced-namespace")
	mem.writeArcStr(0x2000, "misplaced-account")
	mem.writeArcStr(0x3000, "source-ns")
	mem.writeArcStr(0x4000, "source-cluster")
	mem.writeArcStr(0x5000, "destination-ns")
	mem.writeArcStr(0x6000, "destination-account")
	mem.writeArcStr(0x7000, "destination-cluster")

	putPointer := func(offset int, value uint64) {
		binary.LittleEndian.PutUint64(window[offset:offset+8], value)
	}
	// SourcePrincipal is absent. These deliberately plausible pointer values are outside the
	// ConnectionResult's principal fields and must not be followed as if they were one.
	putPointer(7, 0x1000)  // OffsetAbsent + IdentityNamespace
	putPointer(15, 0x2000) // OffsetAbsent + IdentityServiceAccount
	putPointer(offsets.SourceNamespace, 0x3000)
	putPointer(offsets.SourceCluster, 0x4000)
	putPointer(offsets.DestinationPrincipal+offsets.IdentityNamespace, 0x5000)
	putPointer(offsets.DestinationPrincipal+offsets.IdentityServiceAccount, 0x6000)
	putPointer(offsets.DestinationCluster, 0x7000)
	window[offsets.Src+sockAddrV4IPOffset] = 10
	window[offsets.Src+sockAddrV4IPOffset+1] = 20
	window[offsets.Src+sockAddrV4IPOffset+2] = 0
	window[offsets.Src+sockAddrV4IPOffset+3] = 1
	binary.LittleEndian.PutUint16(window[offsets.Src+sockAddrV4PortOffset:], 41244)
	window[offsets.SecurityPolicy] = ztunnelSecurityPolicyMutualTLS

	sample, err := newZTunnelIdentityDecoder(offsets, newArcStrCache(16)).Decode(window, mem)
	if err != nil {
		t.Fatalf("decode with absent source principal: %v", err)
	}
	if sample.Source == nil || sample.Source.Namespace != "source-ns" || sample.Source.Cluster != "source-cluster" {
		t.Fatalf("source fallback identity = %+v; want namespace/cluster from resolved labels", sample.Source)
	}
	if sample.Source.ServiceAccount != "" {
		t.Fatalf("absent source principal produced service account %q", sample.Source.ServiceAccount)
	}
	if sample.Destination == nil || sample.Destination.Namespace != "destination-ns" ||
		sample.Destination.ServiceAccount != "destination-account" || sample.Destination.Cluster != "destination-cluster" {
		t.Fatalf("destination identity = %+v; want the resolved destination labels", sample.Destination)
	}
}

// A compact event whose identity pointers resolve to real ArcStrs decodes to the identity ztunnel
// attributed to each side - the happy path the probe ships once offsets are resolved.
func TestDecodeCompactValidIdentity(t *testing.T) {
	mem := newFakeMemory()
	mem.writeArcStr(0x1000, "bookinfo") // src namespace
	mem.writeArcStr(0x2000, "reviews")  // src service account
	mem.writeArcStr(0x3000, "ratings")  // dst service account
	mem.writeArcStr(0x4000, "bookinfo") // dst namespace

	s := newZTunnelIdentitySource(nil)
	event := &events.ZTunnelConnectionResultCompactEvent{
		SrcIP: 0x0a2c0016, SrcPort: 41244,
		SrcPrincipalNsPtr: 0x1000, SrcPrincipalSaPtr: 0x2000,
		DstPrincipalNsPtr: 0x4000, DstPrincipalSaPtr: 0x3000,
	}
	sample := s.decodeCompact(event, mem)
	if sample == nil {
		t.Fatal("a compact event with valid identity pointers must decode")
	}
	if sample.Source == nil || sample.Source.Namespace != "bookinfo" || sample.Source.ServiceAccount != "reviews" {
		t.Fatalf("source identity = %+v; want bookinfo/reviews", sample.Source)
	}
	if sample.Destination == nil || sample.Destination.ServiceAccount != "ratings" {
		t.Fatalf("destination identity = %+v; want sa ratings", sample.Destination)
	}
}

// The case this whole change exists for: the offsets are slightly wrong, so the probe ships NON-NULL
// pointers that do not point at ArcStrs. Every field is rejected by the plausibility guards, so the
// event decodes to no identity(returns nil) AND is flagged as having shipped pointers - which is what
// makes the caller count it towards the downgrade instead of silently dropping it forever.
func TestDecodeCompactGarbagePointersRejected(t *testing.T) {
	mem := newFakeMemory()
	mem.garbage(0x6000)

	s := newZTunnelIdentitySource(nil)
	event := &events.ZTunnelConnectionResultCompactEvent{
		SrcIP: 0x0a2c0016, SrcPort: 41244,
		SrcPrincipalNsPtr: 0x6000, SrcPrincipalSaPtr: 0x6000,
		DstPrincipalNsPtr: 0x6000, DstPrincipalSaPtr: 0x6000,
	}
	if sample := s.decodeCompact(event, mem); sample != nil {
		t.Fatalf("garbage identity pointers must not decode to an identity, got %+v", sample.Source)
	}
	if !compactShippedIdentityPointer(event) {
		t.Fatal("the event shipped non-null pointers, so it must count towards the downgrade")
	}
}

// A legitimate non-mTLS leg carries no identity at all: the probe ships all-null pointers, the event
// decodes to nil, and the gate reports it must NOT count towards the downgrade - so a stream of such
// connections can never push a correctly-resolved probe onto the access-log fallback.
func TestDecodeCompactAllNullIsNotAFailure(t *testing.T) {
	s := newZTunnelIdentitySource(nil)
	event := &events.ZTunnelConnectionResultCompactEvent{SrcIP: 0x0a2c0016, SrcPort: 41244}
	if sample := s.decodeCompact(event, newFakeMemory()); sample != nil {
		t.Fatalf("an all-null-pointer event carries no identity and must decode to nil, got %+v", sample)
	}
	if compactShippedIdentityPointer(event) {
		t.Fatal("an all-null-pointer event must NOT count towards the downgrade")
	}
}
