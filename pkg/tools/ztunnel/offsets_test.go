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
	"os"
	"testing"
)

// validOffsets is the resolved form of the layout measured from a real ztunnel release-1.28 debug
// build. It is derived from validLayouts rather than restated, so the two fixtures cannot drift.
func validOffsets() *Offsets {
	offsets, err := validLayouts().Resolve()
	if err != nil {
		panic(err)
	}
	return offsets
}

func TestOffsetsValidateAcceptsMeasuredLayout(t *testing.T) {
	if err := validOffsets().Validate(); err != nil {
		t.Fatalf("the layout measured from ztunnel 1.28 was rejected: %v", err)
	}
}

// Validation is the guard that stops a wrong offset set - from a hand-edited table, a bad
// generator run, or a mis-converged calibration - from being used to read ztunnel's memory.
// Each case here is a way a set can be wrong that MUST be caught before any read happens.
func TestOffsetsValidateRejectsBadSets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Offsets)
	}{
		{"zero window", func(o *Offsets) { o.Window = 0 }},
		{"absurd window", func(o *Offsets) { o.Window = maxWindow + 8 }},
		{"field past the window", func(o *Offsets) { o.DestinationCluster = o.Window }},
		{"principal straddling the window end", func(o *Offsets) {
			o.DestinationPrincipal = o.Window - 8
		}},
		{"misaligned pointer field", func(o *Offsets) { o.SourceCluster = 113 }},
		{"negative offset", func(o *Offsets) { o.Src = -8 }},
		{"reporter outside the window", func(o *Offsets) { o.Reporter = o.Window }},
		{"identity member outside a Spiffe", func(o *Offsets) { o.IdentityNamespace = IdentitySpiffeSize }},
		{"duplicated identity members", func(o *Offsets) { o.IdentityNamespace = o.IdentityTrustDomain }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := validOffsets()
			tc.mutate(o)
			if err := o.Validate(); err == nil {
				t.Fatalf("Validate accepted a bad offset set (%s)", tc.name)
			}
		})
	}
}

// TestExtractOffsetsFromRealZTunnelDWARF runs the extractor against an actual ztunnel binary
// built with debug info. It is the only test that proves the DWARF type/member names the
// extractor looks for are the ones rustc really emits, so it is also the check the offset-table
// generator relies on. Point ZTUNNEL_DWARF_BINARY at a debug build to enable it.
func TestExtractOffsetsFromRealZTunnelDWARF(t *testing.T) {
	path := os.Getenv("ZTUNNEL_DWARF_BINARY")
	if path == "" {
		t.Skip("set ZTUNNEL_DWARF_BINARY to a ztunnel build with debug info to run this test")
	}
	got, err := ExtractOffsetsFromDWARF(path)
	if err != nil {
		t.Fatalf("extract offsets from %s: %v", path, err)
	}
	if got.Source != OffsetSourceDWARF {
		t.Fatalf("source = %q; want %q", got.Source, OffsetSourceDWARF)
	}
	// The concrete numbers move with the ztunnel version, so assert the invariants that must
	// hold for ANY version instead of pinning values that would make this test version locked.
	if err := got.Validate(); err != nil {
		t.Fatalf("extracted offsets failed validation: %v", err)
	}
	if got.DestinationPrincipal == got.SourcePrincipal {
		t.Fatal("source and destination principals resolved to the same offset")
	}
	if got.DestinationCluster == got.SourceCluster {
		t.Fatal("source and destination clusters resolved to the same offset")
	}
	t.Logf("extracted from %s: %+v", path, *got)
}
