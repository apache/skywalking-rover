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

import "testing"

// validLayouts is the layout measured from a real ztunnel release-1.28 debug build, transcribed
// in full - every field of every type, not just the ones the probe reads today. Testing against
// the complete type is what makes the "a later agent can use a field nobody asked for yet" claim
// meaningful rather than aspirational.
func validLayouts() Layouts {
	return Layouts{
		TypeConnectionResult: {
			Size: 408,
			Fields: map[string]int{
				"tl": 0, "start": 232, "src": 248, "dst": 288, "hbone_target": 328,
				"metrics": 360, "sent_metric": 368, "recv_metric": 376,
				"sent": 384, "recv": 392, "recorded": 400,
			},
		},
		TypeCommonTrafficLabels: {
			Size: 232,
			Fields: map[string]int{
				"locality":        0,
				"source_workload": 40, "source_canonical_service": 48, "source_canonical_revision": 56,
				"source_workload_namespace": 64, "source_principal": 72,
				"source_app": 96, "source_version": 104, "source_cluster": 112,
				"destination_service": 120, "destination_service_namespace": 128,
				"destination_service_name": 136, "destination_workload": 144,
				"destination_canonical_service": 152, "destination_canonical_revision": 160,
				"destination_workload_namespace": 168, "destination_principal": 176,
				"destination_app": 200, "destination_version": 208, "destination_cluster": 216,
				"reporter": 224, "request_protocol": 225,
				"connection_security_policy": 226, "response_flags": 227,
			},
		},
		TypeIdentitySpiffe: {
			Size:   24,
			Fields: map[string]int{"trust_domain": 0, "namespace": 8, "service_account": 16},
		},
	}
}

// Resolving must fold ConnectionResult.tl into the label offsets, so the decoder gets positions
// relative to the pointer the probe actually copies.
func TestLayoutsResolveComposesTrafficLabels(t *testing.T) {
	offsets, err := validLayouts().Resolve()
	if err != nil {
		t.Fatalf("the layout measured from ztunnel 1.28 did not resolve: %v", err)
	}
	for _, check := range []struct {
		field string
		got   int
		want  int
	}{
		{"window", offsets.Window, 408},
		{"src", offsets.Src, 248},
		{"destinationPrincipal", offsets.DestinationPrincipal, 176},
		{"destinationCluster", offsets.DestinationCluster, 216},
		{"reporter", offsets.Reporter, 224},
		{"identityServiceAccount", offsets.IdentityServiceAccount, 16},
	} {
		if check.got != check.want {
			t.Errorf("%s = %d; want %d", check.field, check.got, check.want)
		}
	}
	if !offsets.HasDirection {
		t.Error("layouts carrying reporter and connection_security_policy must resolve with a known direction")
	}
}

// `tl` is not always at zero in principle, so resolution must ADD it rather than assume the
// labels start where ConnectionResult does.
func TestLayoutsResolveAddsTrafficLabelBase(t *testing.T) {
	layouts := validLayouts()
	layouts[TypeConnectionResult].Fields["tl"] = 8

	offsets, err := layouts.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if offsets.DestinationPrincipal != 176+8 {
		t.Fatalf("destinationPrincipal = %d; want %d, the tl base must be folded in",
			offsets.DestinationPrincipal, 176+8)
	}
	// fields of ConnectionResult itself are already absolute and must NOT be shifted
	if offsets.Src != 248 {
		t.Fatalf("src = %d; want 248, ConnectionResult's own fields must not be shifted", offsets.Src)
	}
}

// A layout set that cannot describe the types the probe reads must be refused before anything
// uses it - a missing field would otherwise resolve to offset zero and read the wrong bytes.
func TestLayoutsValidateRejectsUnusable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(Layouts)
	}{
		{"missing type", func(l Layouts) { delete(l, TypeIdentitySpiffe) }},
		{"missing field", func(l Layouts) { delete(l[TypeCommonTrafficLabels].Fields, "destination_principal") }},
		{"zero size", func(l Layouts) { l[TypeConnectionResult].Size = 0 }},
		{"absurd size", func(l Layouts) { l[TypeConnectionResult].Size = maxWindow + 8 }},
		{"field past the type", func(l Layouts) {
			l[TypeCommonTrafficLabels].Fields["destination_cluster"] = 10_000
		}},
		{"negative offset", func(l Layouts) { l[TypeIdentitySpiffe].Fields["namespace"] = -8 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layouts := validLayouts()
			tc.mutate(layouts)
			if err := layouts.Validate(); err == nil {
				t.Fatalf("Validate accepted unusable layouts (%s)", tc.name)
			}
			if _, err := layouts.Resolve(); err == nil {
				t.Fatalf("Resolve accepted unusable layouts (%s)", tc.name)
			}
		})
	}
}

// The fingerprint decides whether two binaries share an entry, so it must not depend on Go's
// randomized map iteration order.
func TestLayoutsFingerprintIsStable(t *testing.T) {
	first, second := validLayouts().Fingerprint(), validLayouts().Fingerprint()
	if first != second {
		t.Fatalf("fingerprint is unstable:\n%s\n%s", first, second)
	}
	changed := validLayouts()
	changed[TypeCommonTrafficLabels].Fields["destination_cluster"] = 208
	if changed.Fingerprint() == first {
		t.Fatal("layouts differing in a field offset produced the same fingerprint")
	}
}
