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
	"fmt"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"
	ztunneltool "github.com/apache/skywalking-rover/pkg/tools/ztunnel"
)

// resolvedZTunnelOffsets is the outcome of walking the offset fallback ladder for one ztunnel
// binary: the offsets(nil when no static rung produced any) plus how the binary identified
// itself, which is worth logging either way - it is what an operator needs in order to add a
// table entry for a binary the table does not cover.
type resolvedZTunnelOffsets struct {
	Offsets   *ztunneltool.Offsets
	BuildID   string
	BuildInfo *ztunneltool.BuildInfo
}

// resolveStaticZTunnelOffsets tries the rungs that can produce offsets BEFORE any traffic flows:
// the binary's own debug info, then the pre-generated table - by build ID, and failing that by
// the revision the binary reports.
//
// In practice the table is the rung that fires. Every official istio ztunnel image measured - and
// the vendor rebuild running in production - is compiled with `cargo build --release`, whose
// profile leaves `debug` off, so it ships a symbol table but no .debug_* sections. The DWARF rung
// exists for self-built and debug ztunnels, where it is authoritative and free.
//
// A nil result is not a failure: it means the caller should try runtime calibration, and if that
// does not converge either, downgrade to reading the ztunnel access log.
func resolveStaticZTunnelOffsets(exePath string, pid int32) *resolvedZTunnelOffsets {
	result := &resolvedZTunnelOffsets{}

	offsets, err := ztunneltool.ExtractOffsetsFromDWARF(exePath)
	if err == nil {
		ztunnelLog.Infof("resolved the ztunnel identity offsets from the binary's own debug info: %+v", *offsets)
		result.Offsets = offsets
		return result
	}
	// Debug info is absent on every release build, so this is the NORMAL path and must not be
	// logged as a warning; it is only interesting when chasing why a node is calibrating.
	ztunnelLog.Debugf("no usable debug info in the ztunnel binary %s, "+
		"falling back to the pre-generated offset table: %v", exePath, err)

	table, err := ztunneltool.LoadTable()
	if err != nil {
		ztunnelLog.Warnf("cannot load the ztunnel offset table, the identity uprobe will have to "+
			"calibrate at runtime: %v", err)
		return result
	}

	buildID, buildIDErr := ztunneltool.ReadELFBuildID(exePath)
	result.BuildID = buildID
	if buildIDErr == nil {
		if matched := table.Lookup(buildID); matched != nil {
			ztunnelLog.Infof("resolved the ztunnel identity offsets from the pre-generated table, "+
				"build id: %s, offsets: %+v", buildID, *matched)
			result.Offsets = matched
			return result
		}
	} else {
		// Only when the build ID cannot be READ does the weaker revision key come into play. A
		// build ID that WAS read and simply missed means "this exact binary was never measured",
		// and answering that from another binary which merely shares a revision is the mistake
		// keying on the build ID exists to prevent.
		ztunnelLog.Infof("cannot read the ztunnel build id from %s(%v), falling back to "+
			"identifying it by the revision it reports", exePath, buildIDErr)
		if info, infoErr := readZTunnelBuildInfo(pid); infoErr != nil {
			ztunnelLog.Infof("the ztunnel build info is unavailable too: %v", infoErr)
		} else {
			result.BuildInfo = info
			if matched := table.LookupByRevision(info); matched != nil {
				ztunnelLog.Infof("resolved the ztunnel identity offsets from the pre-generated "+
					"table by revision(%s), offsets: %+v", info, *matched)
				result.Offsets = matched
				return result
			}
		}
	}

	// Nothing matched. Report what the binary says about itself alongside the build ID: a bare
	// hash tells an operator nothing about what they are actually running, and the pair is what
	// they need to add a table entry. Best effort - a ztunnel that will not report its version
	// still gets its build ID logged.
	if result.BuildInfo == nil {
		if info, infoErr := readZTunnelBuildInfo(pid); infoErr == nil {
			result.BuildInfo = info
		}
	}
	ztunnelLog.Infof("the ztunnel offset table has no entry for build id %q (ztunnel reports: %s), "+
		"the identity uprobe will calibrate the offsets at runtime(and downgrade to the access log "+
		"if it cannot)", result.BuildID, result.BuildInfo)
	return result
}

const (
	// ztunnelCalibrationAgreements is how many independent samples must derive the SAME offsets
	// before they are used. One sample can be a coincidence - a string that happens to equal the
	// expected namespace at an unrelated offset - but three connections, generally to different
	// workloads, agreeing on the same layout is not.
	ztunnelCalibrationAgreements = 3
	// ztunnelCalibrationMaxSamples bounds how long calibration is attempted. Past this the
	// binary is declared un-calibratable and the collector downgrades to the access log, rather
	// than scanning every connection forever on a ztunnel whose layout defeats the heuristics.
	ztunnelCalibrationMaxSamples = 500
)

// calibrationTruth is the known-good data calibration recognizes offsets by: the ztunnel admin
// /config_dump workload index, which maps a workload IP to the namespace, service account and
// cluster ztunnel itself believes it has.
type calibrationTruth struct {
	byIP map[string]*WorkloadIdentity
}

// realDestinationLookup answers "which real backend pod did this source address end up talking
// to". It is satisfied by the mapping the track_outbound uprobe and the admin dump already
// maintain, and is what ANCHORS calibration: knowing the real destination of a sample turns the
// config_dump into a statement about what THIS ConnectionResult must contain.
type realDestinationLookup func(srcIP string, srcPort uint16) string

// ztunnelOffsetCalibrator recovers the field offsets of a ztunnel binary that has neither debug
// info nor a table entry - a vendor or locally patched build - by scanning a raw ConnectionResult
// for values it can already prove.
//
// What it can and cannot recover:
//   - It CAN pin the source address and the destination identity, because the anchor gives it a
//     known (namespace, service account) pair to search the window for.
//   - It CANNOT recover the reporter and connection_security_policy bytes: both hold 0 or 1 and
//     carry no signature to match against. The resulting set reports HasDirection false and the
//     caller uses the monitored socket's own role instead.
//   - It CANNOT anchor the SOURCE identity: ztunnel leaves source_principal unset on an outbound
//     connection(it is only filled from a derived mTLS peer), so an outbound sample carries no
//     source identity to find. Those offsets stay absent and the inbound PEER_* addition keeps
//     using the access-log source.
//
// The cluster offset is located by matching the config_dump clusterId. That value is not fully
// trusted, but using it to LOCATE rather than to verify is safe either way: a wrong clusterId is
// simply not present in the window, so the cluster is reported absent instead of binding some
// neighboring field's offset.
type ztunnelOffsetCalibrator struct {
	// mu serializes Observe: the collector calls it from several BPF-event goroutines at once and the
	// vote map is mutated there. Calibration is a transient, low-frequency startup phase, so a single
	// lock costs nothing and removes the concurrent-map-write data race that would otherwise abort the
	// agent with "fatal error: concurrent map writes".
	mu       sync.Mutex
	strings  *arcStrCache
	window   int
	votes    map[string]*calibrationCandidate
	observed int
}

type calibrationCandidate struct {
	offsets ztunneltool.Offsets
	votes   int
}

func newZTunnelOffsetCalibrator(strings *arcStrCache, window int) *ztunnelOffsetCalibrator {
	return &ztunnelOffsetCalibrator{
		strings: strings,
		window:  window,
		votes:   make(map[string]*calibrationCandidate),
	}
}

// Exhausted reports that calibration has seen enough samples without converging, so the caller
// should stop trying and downgrade.
func (c *ztunnelOffsetCalibrator) Exhausted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observed >= ztunnelCalibrationMaxSamples
}

// Observe feeds one raw ConnectionResult window to the calibrator and returns a validated offset
// set once enough samples agree, or nil while it is still undecided.
func (c *ztunnelOffsetCalibrator) Observe(window []byte, mem memoryReader, truth *calibrationTruth,
	realDest realDestinationLookup) *ztunneltool.Offsets {
	c.mu.Lock()
	defer c.mu.Unlock()
	// inline exhausted check, not c.Exhausted(): that method takes the same lock and would deadlock
	if truth == nil || len(truth.byIP) == 0 || c.observed >= ztunnelCalibrationMaxSamples {
		return nil
	}
	c.observed++

	candidate := c.deriveFromSample(window, mem, truth, realDest)
	if candidate == nil {
		return nil
	}
	if err := candidate.Validate(); err != nil {
		return nil
	}

	key := fmt.Sprintf("%+v", *candidate)
	entry := c.votes[key]
	if entry == nil {
		entry = &calibrationCandidate{offsets: *candidate}
		c.votes[key] = entry
	}
	entry.votes++
	if entry.votes < ztunnelCalibrationAgreements {
		return nil
	}
	result := entry.offsets
	return &result
}

// deriveFromSample runs the whole derivation for one window, or returns nil if the sample carries
// no usable anchor.
func (c *ztunnelOffsetCalibrator) deriveFromSample(window []byte, mem memoryReader,
	truth *calibrationTruth, realDest realDestinationLookup) *ztunneltool.Offsets {
	srcOffset, destination := c.anchor(window, truth, realDest)
	if srcOffset == ztunneltool.OffsetAbsent {
		return nil
	}

	strings := c.scanStrings(window, mem)
	if len(strings) == 0 {
		return nil
	}

	principal, members := findIdentityTriple(strings, c.window, destination.Namespace, destination.ServiceAccount)
	if principal == ztunneltool.OffsetAbsent {
		return nil
	}

	offsets := &ztunneltool.Offsets{
		Source:       ztunneltool.OffsetSourceCalibrated,
		Window:       c.window,
		HasDirection: false,
		// calibration has no layout to read the Spiffe size from, so it uses the compiled-in size -
		// the same 24 byte window findIdentityTriple scanned to place the members
		IdentitySpiffeSize:     ztunneltool.IdentitySpiffeSize,
		Src:                    srcOffset,
		Dst:                    ztunneltool.OffsetAbsent,
		HboneTarget:            ztunneltool.OffsetAbsent,
		Reporter:               ztunneltool.OffsetAbsent,
		SecurityPolicy:         ztunneltool.OffsetAbsent,
		SourcePrincipal:        ztunneltool.OffsetAbsent,
		SourceNamespace:        ztunneltool.OffsetAbsent,
		SourceCluster:          ztunneltool.OffsetAbsent,
		DestinationPrincipal:   principal,
		IdentityTrustDomain:    members.trustDomain,
		IdentityNamespace:      members.namespace,
		IdentityServiceAccount: members.serviceAccount,
		DestinationNamespace:   findNamespaceLabel(strings, principal, destination.Namespace),
		DestinationCluster:     findClusterLabel(strings, principal, destination.Cluster),
	}
	return offsets
}

// anchor finds the offset holding the connection's source address, by looking for an address the
// collector has ALREADY resolved a real backend for. A sample without such an address tells us
// nothing verifiable, so it is skipped.
func (c *ztunnelOffsetCalibrator) anchor(window []byte, truth *calibrationTruth,
	realDest realDestinationLookup) (srcOffset int, destination *WorkloadIdentity) {
	for off := 0; off+sockAddrMinSize <= c.window; off += 8 {
		ip, port, ok := decodeSockAddrV4(window, off)
		if !ok {
			continue
		}
		destIP := realDest(ip, port)
		if destIP == "" {
			continue
		}
		id := truth.byIP[destIP]
		// both members are required: they are the two independent values the search below has to
		// match, and one alone is far too weak to identify an offset by
		if id == nil || id.Namespace == "" || id.ServiceAccount == "" {
			continue
		}
		return off, id
	}
	return ztunneltool.OffsetAbsent, nil
}

// scanStrings decodes every 8-aligned slot of the window that looks like a live ArcStr. The
// plausibility guards inside decodeArcStr(alignment, length bound, printable bytes) are what keep
// this from producing a haystack of noise: on a real ConnectionResult only a few dozen slots
// survive them.
func (c *ztunnelOffsetCalibrator) scanStrings(window []byte, mem memoryReader) map[int]string {
	found := make(map[int]string)
	for off := 0; off+8 <= c.window; off += 8 {
		ptr := readPointer(window, off)
		if ptr == 0 {
			continue
		}
		if s, ok := c.strings.decodeArcStr(mem, ptr); ok && s != "" {
			found[off] = s
		}
	}
	return found
}

// identityMembers is where the three ArcStr members sit inside an Identity::Spiffe.
type identityMembers struct {
	trustDomain    int
	namespace      int
	serviceAccount int
}

// findIdentityTriple locates an Identity::Spiffe whose namespace and service account are the
// expected pair, and reports where each member sits inside it. Requiring BOTH values to appear
// in the same 24 byte window, at distinct slots, is what makes a hit trustworthy: a single
// matching string is common(the namespace also appears as a standalone label), but the pair
// co-located in one triple is the identity itself.
func findIdentityTriple(strings map[int]string, window int, namespace, serviceAccount string) (int, identityMembers) {
	for _, base := range sortedOffsets(strings) {
		if base+ztunneltool.IdentitySpiffeSize > window {
			continue
		}
		members := identityMembers{trustDomain: ztunneltool.OffsetAbsent, namespace: ztunneltool.OffsetAbsent, serviceAccount: ztunneltool.OffsetAbsent}
		for slot := 0; slot < ztunneltool.IdentitySpiffeSize; slot += 8 {
			switch strings[base+slot] {
			case namespace:
				members.namespace = slot
			case serviceAccount:
				members.serviceAccount = slot
			}
		}
		if members.namespace == ztunneltool.OffsetAbsent || members.serviceAccount == ztunneltool.OffsetAbsent ||
			members.namespace == members.serviceAccount {
			continue
		}
		// the remaining slot is the trust domain; it is not searched for by value because the
		// trust domain is not in the config_dump workload entry
		for slot := 0; slot < ztunneltool.IdentitySpiffeSize; slot += 8 {
			if slot != members.namespace && slot != members.serviceAccount {
				members.trustDomain = slot
			}
		}
		return base, members
	}
	return ztunneltool.OffsetAbsent, identityMembers{}
}

// findNamespaceLabel locates the standalone destination_workload_namespace label: the same
// namespace string at a slot outside the identity triple. It recovers the namespace for
// connections whose principal is absent, so it is worth pinning even though the principal
// already carries one.
//
// The SOURCE namespace label holds the same string whenever both ends live in one namespace -
// very common - so the nearest match to the destination principal is taken rather than the
// first. The two sides' labels sit next to their own principals, so proximity is what separates
// them; picking the first match would silently bind the source's label on same-namespace traffic.
func findNamespaceLabel(strings map[int]string, principal int, namespace string) int {
	return findNearestLabel(strings, principal, namespace)
}

// findClusterLabel locates the destination cluster slot by matching the cluster the config_dump
// attributes to this workload.
//
// It deliberately does NOT take "the first string after the identity" - between the identity and
// the cluster sit destination_app and destination_version, so a positional guess picks the wrong
// field. Matching by value is also safe in BOTH directions given the config_dump's clusterId is
// not fully trusted: if that value is wrong it simply will not be found in the window and the
// cluster is reported absent, rather than binding some other field's offset. A value that does
// match is by construction the real one.
func findClusterLabel(strings map[int]string, principal int, cluster string) int {
	if cluster == "" {
		return ztunneltool.OffsetAbsent
	}
	return findNearestLabel(strings, principal, cluster)
}

// findNearestLabel returns the slot holding value that lies CLOSEST to the destination identity,
// skipping the identity's own slots.
//
// Nearest rather than first is essential: the source side of CommonTrafficLabels holds the very
// same strings whenever both ends share a namespace or a cluster - the common case - and those
// source labels sit at LOWER offsets, so a first-match rule would bind the source's field every
// time. Each side's labels are laid out around their own principal, which makes distance to the
// destination principal the thing that separates them.
func findNearestLabel(strings map[int]string, principal int, value string) int {
	best, bestDistance := ztunneltool.OffsetAbsent, 0
	for _, off := range sortedOffsets(strings) {
		if off >= principal && off < principal+ztunneltool.IdentitySpiffeSize {
			continue
		}
		if strings[off] != value {
			continue
		}
		distance := off - principal
		if distance < 0 {
			distance = -distance
		}
		if best == ztunneltool.OffsetAbsent || distance < bestDistance {
			best, bestDistance = off, distance
		}
	}
	return best
}

func sortedOffsets(strings map[int]string) []int {
	offsets := make([]int, 0, len(strings))
	for off := range strings {
		offsets = append(offsets, off)
	}
	sort.Ints(offsets)
	return offsets
}

var (
	// ZTunnelVersionTimeout bounds the `ztunnel version` call. It only prints a struct and exits,
	// so anything slower means the attempt is stuck and is not worth waiting on.
	ZTunnelVersionTimeout = time.Second * 10
	// ztunnelBinaryInContainer is where the istio images place the binary; the version call runs
	// inside ztunnel's own mount namespace, so this is a path in THAT namespace.
	ztunnelBinaryInContainer = "/usr/local/bin/ztunnel"
)

// readZTunnelBuildInfo asks a running ztunnel what build it is, by executing its `version`
// subcommand.
//
// The binary cannot simply be executed through /proc/<pid>/exe: it is dynamically linked, and its
// interpreter and libraries live in the ztunnel container's filesystem, not the agent's - the
// attempt fails with a bare "not found"(measured). Both ways of entering that filesystem were
// verified to work on a real cluster with the privileges the agent already has(hostPID, root,
// CAP_SYS_ADMIN): nsenter into the mount namespace, and chroot into /proc/<pid>/root. nsenter is
// tried first and chroot is the backup, since an image may ship one and not the other.
//
// This is the FALLBACK identification path. The build ID is read from the ELF with nothing but an
// open+read and identifies a binary exactly, so it is always preferred; this exists for a ztunnel
// whose build ID note is absent.
func readZTunnelBuildInfo(pid int32) (*ztunneltool.BuildInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ZTunnelVersionTimeout)
	defer cancel()

	// the two ways to enter the ztunnel container's mount namespace to run `ztunnel version`.
	const (
		cmdNsenter           = "nsenter"
		cmdChroot            = "chroot"
		ztunnelVersionSubcmd = "version"
	)
	attempts := []struct {
		name string
		args []string
	}{
		{cmdNsenter, []string{
			cmdNsenter, "-t", fmt.Sprintf("%d", pid), "-m", "--", ztunnelBinaryInContainer, ztunnelVersionSubcmd,
		}},
		{cmdChroot, []string{
			cmdChroot, host.GetHostProcInHost(fmt.Sprintf("%d/root", pid)), ztunnelBinaryInContainer, ztunnelVersionSubcmd,
		}},
	}

	var lastErr error
	for _, attempt := range attempts {
		// #nosec G204 -- the argv is fixed here; only the pid, which is an integer, varies
		output, err := exec.CommandContext(ctx, attempt.args[0], attempt.args[1:]...).CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", attempt.name, err)
			continue
		}
		info, err := ztunneltool.ParseBuildInfo(string(output))
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", attempt.name, err)
			continue
		}
		return info, nil
	}
	return nil, fmt.Errorf("cannot read the ztunnel build info: %w", lastErr)
}
