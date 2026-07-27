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
	"fmt"
	"sync"
	"testing"

	ztunneltool "github.com/apache/skywalking-rover/pkg/tools/ztunnel"
)

// The fixture below reproduces the CommonTrafficLabels layout measured from a real ztunnel
// release-1.28 debug build, field for field, so calibration is exercised against the arrangement
// it will actually meet - including the traps that make naive rules fail:
//
//   - source_workload_namespace(+64) holds the SAME string as destination_workload_namespace
//     (+168) whenever both ends share a namespace, which is the common case;
//   - source_cluster(+112) holds the same string as destination_cluster(+216) in a single
//     cluster mesh;
//   - destination_app(+200) and destination_version(+208) sit BETWEEN the destination identity
//     and destination_cluster, so "the first string after the identity" is the wrong field;
//   - source_principal(+72) is null, because ztunnel does not fill it on an outbound connection.
type calibrationFixture struct {
	window []byte
	mem    *fakeMemory
	truth  *calibrationTruth
}

const (
	fixtureSrcIP    = "10.0.1.5"
	fixtureSrcPort  = 34567
	fixtureRealDest = "10.0.2.7"
)

func newCalibrationFixture(namespace, serviceAccount, cluster string) *calibrationFixture {
	mem := newFakeMemory()
	window := make([]byte, 408)

	addr := uint64(0x100000)
	put := func(offset int, value string) {
		mem.writeArcStr(addr, value)
		binary.LittleEndian.PutUint64(window[offset:], addr)
		addr += 0x1000
	}

	// source side: same namespace and cluster as the destination, and no principal
	put(40, "productpage-v1")
	put(48, "productpage")
	put(56, "v1")
	put(64, namespace)
	put(96, "productpage")
	put(104, "v1")
	put(112, cluster)

	// destination side
	put(120, "reviews."+namespace+".svc.cluster.local")
	put(128, namespace)
	put(136, "reviews")
	put(144, "reviews-v2")
	put(152, "reviews")
	put(160, "v2")
	put(168, namespace)
	// destination_principal: Identity::Spiffe{trust_domain, namespace, service_account}
	put(176, "cluster.local")
	put(184, namespace)
	put(192, serviceAccount)
	put(200, "reviews")
	put(208, "v2")
	put(216, cluster)

	// src / dst SocketAddr: 2 byte discriminant, then the octets and a little-endian port
	writeSockAddr(window, 248, fixtureSrcIP, fixtureSrcPort)
	writeSockAddr(window, 288, fixtureRealDest, 9080)

	return &calibrationFixture{
		window: window,
		mem:    mem,
		truth: &calibrationTruth{byIP: map[string]*WorkloadIdentity{
			fixtureRealDest: {Namespace: namespace, ServiceAccount: serviceAccount, Cluster: cluster},
		}},
	}
}

func writeSockAddr(window []byte, offset int, ip string, port uint16) {
	var a, b, c, d int
	if _, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d); err != nil {
		panic(err)
	}
	copy(window[offset+sockAddrV4IPOffset:], []byte{byte(a), byte(b), byte(c), byte(d)})
	binary.LittleEndian.PutUint16(window[offset+sockAddrV4PortOffset:], port)
}

func fixtureRealDestLookup(ip string, port uint16) string {
	if ip == fixtureSrcIP && port == fixtureSrcPort {
		return fixtureRealDest
	}
	return ""
}

// feedUntilConverged drives the calibrator with one sample until it adopts an offset set, or nil if
// it never does within limit samples. The single-phase calibrator adopts once ztunnelCalibrationAgreements
// independent samples derive the same offset set; the extra samples in limit are harmless headroom.
func feedUntilConverged(c *ztunnelOffsetCalibrator, window []byte, mem memoryReader,
	truth *calibrationTruth, lookup realDestinationLookup, limit int) *ztunneltool.Offsets {
	for i := 0; i < limit; i++ {
		if got := c.Observe(window, mem, truth, lookup); got != nil {
			return got
		}
	}
	return nil
}

func TestCalibrationRecoversMeasuredLayout(t *testing.T) {
	fixture := newCalibrationFixture("bookinfo", "bookinfo-reviews", "demo")
	c := newZTunnelOffsetCalibrator(newArcStrCache(256), len(fixture.window))

	// an outbound stream: once ztunnelCalibrationAgreements samples agree, the destination-only
	// calibrated set is adopted (direction and source identity stay absent, as ztunnel does not fill
	// source_principal on an outbound leg)
	got := feedUntilConverged(c, fixture.window, fixture.mem, fixture.truth, fixtureRealDestLookup,
		ztunnelCalibrationAgreements+5)
	if got == nil {
		t.Fatalf("calibration did not converge on an outbound stream")
	}

	want := validOffsets()
	for _, check := range []struct {
		field string
		got   int
		want  int
	}{
		{"src", got.Src, want.Src},
		{"destinationPrincipal", got.DestinationPrincipal, want.DestinationPrincipal},
		{"identityNamespace", got.IdentityNamespace, want.IdentityNamespace},
		{"identityServiceAccount", got.IdentityServiceAccount, want.IdentityServiceAccount},
		{"identityTrustDomain", got.IdentityTrustDomain, want.IdentityTrustDomain},
		// the traps: the source side holds the same strings at lower offsets
		{"destinationNamespace", got.DestinationNamespace, want.DestinationNamespace},
		{"destinationCluster", got.DestinationCluster, want.DestinationCluster},
	} {
		if check.got != check.want {
			t.Errorf("%s = %d; want %d (the layout measured from ztunnel 1.28)",
				check.field, check.got, check.want)
		}
	}
	// calibration cannot recover the single byte enums, and must say so rather than guess
	if got.HasDirection {
		t.Error("a calibrated offset set claimed to know the direction bytes")
	}
	if got.SourcePrincipal != ztunneltool.OffsetAbsent {
		t.Errorf("sourcePrincipal = %d; want absent, ztunnel leaves it unset on an outbound connection",
			got.SourcePrincipal)
	}
	if got.Source != ztunneltool.OffsetSourceCalibrated {
		t.Errorf("source = %q; want %q", got.Source, ztunneltool.OffsetSourceCalibrated)
	}
}

// Calibration must not converge on a sample it cannot anchor: with no known real destination
// there is no truth to recognize an offset by, and any "match" would be a coincidence.
func TestCalibrationNeedsAnAnchor(t *testing.T) {
	fixture := newCalibrationFixture("bookinfo", "bookinfo-reviews", "demo")
	c := newZTunnelOffsetCalibrator(newArcStrCache(256), len(fixture.window))
	noAnchor := func(string, uint16) string { return "" }

	if got := feedUntilConverged(c, fixture.window, fixture.mem, fixture.truth, noAnchor,
		ztunnelCalibrationAgreements+5); got != nil {
		t.Fatalf("calibration converged without an anchor: %+v", *got)
	}
}

// A workload whose config_dump entry lacks a service account gives calibration only ONE string
// to match, which is far too weak to identify an offset - it must refuse rather than guess.
func TestCalibrationRefusesWeakTruth(t *testing.T) {
	fixture := newCalibrationFixture("bookinfo", "bookinfo-reviews", "demo")
	fixture.truth.byIP[fixtureRealDest] = &WorkloadIdentity{Namespace: "bookinfo"}
	c := newZTunnelOffsetCalibrator(newArcStrCache(256), len(fixture.window))

	if got := feedUntilConverged(c, fixture.window, fixture.mem, fixture.truth, fixtureRealDestLookup,
		ztunnelCalibrationAgreements+5); got != nil {
		t.Fatalf("calibration converged on a single-value truth: %+v", *got)
	}
}

// When the config_dump reports a cluster that is not what ztunnel actually holds - the case the
// config_dump is explicitly not trusted for - the cluster must come back ABSENT rather than
// binding whichever neighboring field happened to be nearby.
func TestCalibrationLeavesClusterAbsentWhenTruthDisagrees(t *testing.T) {
	fixture := newCalibrationFixture("bookinfo", "bookinfo-reviews", "demo")
	fixture.truth.byIP[fixtureRealDest].Cluster = "Kubernetes"
	c := newZTunnelOffsetCalibrator(newArcStrCache(256), len(fixture.window))

	got := feedUntilConverged(c, fixture.window, fixture.mem, fixture.truth, fixtureRealDestLookup,
		ztunnelCalibrationAgreements+5)
	if got == nil {
		t.Fatal("calibration should still converge on the identity when only the cluster disagrees")
	}
	if got.DestinationCluster != ztunneltool.OffsetAbsent {
		t.Fatalf("destinationCluster = %d; want absent when the config_dump cluster is not in the struct",
			got.DestinationCluster)
	}
}

// The whole point of a calibrated set is that it decodes correctly. Round-tripping it through
// the decoder proves the offsets are not merely self-consistent but actually yield the identity.
func TestCalibratedOffsetsDecodeTheIdentity(t *testing.T) {
	fixture := newCalibrationFixture("bookinfo", "bookinfo-reviews", "demo")
	strings := newArcStrCache(256)
	c := newZTunnelOffsetCalibrator(strings, len(fixture.window))

	offsets := feedUntilConverged(c, fixture.window, fixture.mem, fixture.truth, fixtureRealDestLookup,
		ztunnelCalibrationAgreements+5)
	if offsets == nil {
		t.Fatal("calibration did not converge")
	}

	sample, err := newZTunnelIdentityDecoder(offsets, strings).Decode(fixture.window, fixture.mem)
	if err != nil {
		t.Fatalf("decoding with the calibrated offsets failed: %v", err)
	}
	if sample.SrcIP != fixtureSrcIP || sample.SrcPort != fixtureSrcPort {
		t.Errorf("src = %s:%d; want %s:%d", sample.SrcIP, sample.SrcPort, fixtureSrcIP, fixtureSrcPort)
	}
	if sample.Destination == nil {
		t.Fatal("no destination identity decoded")
	}
	if sample.Destination.Namespace != "bookinfo" {
		t.Errorf("destination namespace = %q; want %q", sample.Destination.Namespace, "bookinfo")
	}
	if sample.Destination.ServiceAccount != "bookinfo-reviews" {
		t.Errorf("destination service account = %q; want %q", sample.Destination.ServiceAccount, "bookinfo-reviews")
	}
	if sample.Destination.Cluster != "demo" {
		t.Errorf("destination cluster = %q; want %q", sample.Destination.Cluster, "demo")
	}
	if sample.DirectionKnown {
		t.Error("a calibrated sample must report the direction as unknown")
	}
	// a calibrated set leaves SecurityPolicy absent, so MutualTLS must DEFAULT to true - this is what
	// lets apply() cache the identity(it gates on sample.MutualTLS); if this regressed, every calibrated
	// sample would be treated as non-mTLS and its identity dropped
	if !sample.MutualTLS {
		t.Error("a calibrated sample must default MutualTLS to true when the security policy is absent")
	}
}

// validOffsets is the layout measured from a real ztunnel release-1.28 debug build. Calibration
// is asserted against these numbers, so a regression shows up as "you recovered the wrong field"
// rather than merely "the offsets are self-consistent".
func validOffsets() *ztunneltool.Offsets {
	return &ztunneltool.Offsets{
		Window:                 408,
		HasDirection:           true,
		Src:                    248,
		Dst:                    288,
		HboneTarget:            328,
		Reporter:               224,
		SecurityPolicy:         226,
		SourcePrincipal:        72,
		DestinationPrincipal:   176,
		SourceNamespace:        64,
		DestinationNamespace:   168,
		SourceCluster:          112,
		DestinationCluster:     216,
		IdentityTrustDomain:    0,
		IdentityNamespace:      8,
		IdentityServiceAccount: 16,
	}
}

// The collector calls Observe from several BPF-event goroutines at once, and the vote map is mutated
// there. Observe must be safe under that concurrency: before it took a lock this raced and the
// runtime could abort the agent with "fatal error: concurrent map writes". Reaching the end without
// the runtime aborting is the assertion(run with -race to also flag the write-write race).
func TestCalibrationObserveIsConcurrencySafe(_ *testing.T) {
	fixture := newCalibrationFixture("bookinfo", "bookinfo-reviews", "demo")
	c := newZTunnelOffsetCalibrator(newArcStrCache(256), len(fixture.window))

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				c.Observe(fixture.window, fixture.mem, fixture.truth, fixtureRealDestLookup)
			}
		}()
	}
	wg.Wait()
}
