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
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	ztunneltool "github.com/apache/skywalking-rover/pkg/tools/ztunnel"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var (
	// ZTunnelRecordInternalSymbolPrefix is ztunnel::proxy::metrics::ConnectionResult::record_internal,
	// the function that writes the ztunnel access log. Probing it yields everything the log line
	// carries - both peers and the whole CommonTrafficLabels - without the file, the kubelet
	// round trip, or the tailer's poll interval. It is present in every ztunnel measured from
	// 1.24 through master and in the vendor rebuild running in production, and takes &self in
	// PARM1 on both architectures(it returns unit, so no sret shifts the argument registers the
	// way it does for the ConnectionResult constructors).
	ZTunnelRecordInternalSymbolPrefix = "_ZN7ztunnel5proxy7metrics16ConnectionResult15record_internal"

	// ZTunnelIdentityDecodeFailureLimit is how many consecutive undecodable events end the
	// uprobe identity path. A wrong offset set does not fail loudly - it reads plausible-looking
	// bytes - so the plausibility guards are what catch it, and this bounds how long a binary
	// whose layout does not match keeps producing nothing before the collector falls back to
	// reading the access log.
	ZTunnelIdentityDecodeFailureLimit = 50

	// ztunnelArcStrCacheSize bounds the pointer -> string cache. Entries are one short string per
	// distinct workload field value, so a few thousand covers a large mesh many times over.
	ztunnelArcStrCacheSize = 4096
)

// sourceRecordInternal marks a mapping recovered from the identity probe. It is a full
// replacement for the access-log tailer's mapping source: the same (downstream src -> real pod)
// pair, from the same moment in ztunnel's lifecycle, without any file IO.
const sourceRecordInternal ztunnelMappingSource = "record_internal"

// ztunnelIdentitySource owns the uprobe-based identity path: resolving the offsets for the
// ztunnel binary on this node, decoding the raw ConnectionResult snapshots the probe emits, and
// deciding when the path is not working and the access-log reader has to take over.
//
// The fallback ladder it implements, in order:
//  1. the ztunnel binary's own debug info;
//  2. the pre-generated table, matched on the binary's GNU build ID;
//  3. runtime calibration against the admin config_dump;
//  4. give up and let the access-log tailer supply identities, exactly as before.
type ztunnelIdentitySource struct {
	collector *Collector
	strings   *arcStrCache

	decoder atomic.Pointer[ztunnelIdentityDecoder]

	// calibration state, only touched from the event handler under mu
	mu         sync.Mutex
	calibrator *ztunnelOffsetCalibrator
	memReaders map[int32]*procMemReader
	// probeLinks are the record_internal uprobe links this path OWNS(one per monomorphized copy),
	// so downgrade can DETACH the probe entirely instead of leaving it firing into a dropped event.
	// Guarded by mu: set once at attach, closed once at downgrade/stop.
	probeLinks []io.Closer

	// pid of the ztunnel this source is bound to, set in Prepare; used to key the BPF offsets
	// config map(push the resolved offsets, or mark the probe disabled on downgrade)
	pid atomic.Int32

	// downgraded latches once the path has given up, so the decision is made once and the
	// access-log tailer is started once
	downgraded atomic.Bool

	events           atomic.Int64
	decoded          atomic.Int64
	decodeFailures   atomic.Int64
	consecutiveFails atomic.Int64
	calibrationTries atomic.Int64
}

func newZTunnelIdentitySource(collector *Collector) *ztunnelIdentitySource {
	return &ztunnelIdentitySource{
		collector:  collector,
		strings:    newArcStrCache(ztunnelArcStrCacheSize),
		memReaders: make(map[int32]*procMemReader),
	}
}

// Prepare resolves the offsets for a newly discovered ztunnel binary and reports whether the
// uprobe identity path can carry the identities on its own. A false result means the access-log
// tailer must run: either nothing could be resolved yet(calibration will keep trying, and the
// tailer covers the gap meanwhile) or the resolved set cannot describe the inbound side.
func (s *ztunnelIdentitySource) Prepare(exePath string, pid int32) bool {
	s.pid.Store(pid)
	resolved := resolveStaticZTunnelOffsets(exePath, pid)
	if resolved.Offsets == nil {
		s.mu.Lock()
		s.calibrator = newZTunnelOffsetCalibrator(s.strings, events.ZTunnelConnectionResultWindow)
		s.mu.Unlock()
		return false
	}
	return s.adopt(resolved.Offsets)
}

// adopt installs an offset set and reports whether it covers the inbound side too.
func (s *ztunnelIdentitySource) adopt(offsets *ztunneltool.Offsets) bool {
	if offsets.Window > events.ZTunnelConnectionResultWindow {
		// the probe copies a fixed window; a ztunnel whose ConnectionResult outgrew it would be
		// decoded from truncated bytes, so refuse rather than read past the copy
		ztunnelLog.Warnf("the ztunnel ConnectionResult is %d bytes but the probe only copies %d, "+
			"the identity uprobe cannot be used for this build", offsets.Window,
			events.ZTunnelConnectionResultWindow)
		return false
	}
	s.decoder.Store(newZTunnelIdentityDecoder(offsets, s.strings))
	s.consecutiveFails.Store(0)

	// hand the resolved offsets to the probe so it switches from the full window to the compact
	// event. The full-window handler stays wired for any events already in flight and for the
	// calibration path, so a failed push only costs the byte saving, not correctness.
	s.pushOffsetsConfig(s.pid.Load(), offsets)

	// A calibrated set has no source-side offsets: ztunnel leaves source_principal unset on an
	// outbound connection, so calibration has nothing to anchor the inbound identity against.
	// The inbound PEER_* addition therefore keeps its existing access-log source, which is why
	// the tailer still has to run in that case.
	coversInbound := offsets.SourcePrincipal != ztunneltool.OffsetAbsent
	ztunnelLog.Infof("the ztunnel identity uprobe is using %s offsets(inbound peer identity covered: %t)",
		offsets.Source, coversInbound)
	return coversInbound
}

// Active reports whether the uprobe path is currently supplying identities.
func (s *ztunnelIdentitySource) Active() bool {
	return !s.downgraded.Load() && s.decoder.Load() != nil
}

// HandleEvent decodes one raw ConnectionResult snapshot: it feeds the (source -> real pod)
// mapping and both identities into the same caches the access-log tailer fills, so everything
// downstream - the addition builder, the deferral, the finalize accounting - is unchanged and
// only the data source differs.
func (s *ztunnelIdentitySource) HandleEvent(event *events.ZTunnelConnectionResultEvent) {
	s.events.Add(1)
	if s.downgraded.Load() {
		return
	}
	window := event.Data[:]
	mem := s.memReaderFor(int32(event.PID))

	decoder := s.decoder.Load()
	if decoder == nil {
		s.calibrate(window, mem)
		return
	}

	sample, err := decoder.Decode(window, mem)
	if err != nil {
		s.decodeFailures.Add(1)
		// one debug line for every event that could NOT be decoded, so a build whose offsets do not
		// match is diagnosable per event instead of only when the downgrade threshold is finally hit
		ztunnelAccessLog.Debugf("ztunnel access log entry [source=uprobe]: decode error, the offsets "+
			"may not match this ztunnel build: %v", err)
		if s.consecutiveFails.Add(1) >= int64(ZTunnelIdentityDecodeFailureLimit) {
			s.downgrade(fmt.Sprintf("%d consecutive undecodable events, the offsets do not match this "+
				"ztunnel build: %v", ZTunnelIdentityDecodeFailureLimit, err))
		}
		return
	}
	s.consecutiveFails.Store(0)
	s.decoded.Add(1)
	// one debug line for every decoded entry - the uprobe equivalent of an access-log line - naming
	// the source and the fields read, on the same "accesslog.collector.ztunnel.accesslog" module the
	// file tailer logs under, so ONE module shows every identity read regardless of where it came from
	ztunnelAccessLog.Debugf("ztunnel access log entry [source=uprobe]: src=%s:%d dst=%s:%d direction=%s "+
		"mtls=%t src.identity=%s dst.identity=%s",
		sample.SrcIP, sample.SrcPort, sample.DstIP, sample.DstPort, directionLabel(sample),
		sample.MutualTLS, identitySummary(sample.Source), identitySummary(sample.Destination))
	s.apply(sample)
}

// apply routes one decoded sample into the caches. The direction comes from ztunnel's own
// reporter when the offsets carry it; a calibrated set cannot recover that byte, and there the
// keys themselves do the routing - an outbound sample is keyed by the local application socket,
// which is the only key a monitored connection can ever match.
func (s *ztunnelIdentitySource) apply(sample *ztunnelProbeSample) {
	z := s.collector
	outbound := !sample.DirectionKnown || sample.Outbound

	if outbound {
		if sample.MutualTLS || !sample.DirectionKnown {
			z.cacheDstIdentity(sample.SrcIP, int(sample.SrcPort), sample.Destination)
		}
		// mark the source as seen so a connection waiting on its identity stops deferring once
		// its own event has arrived, with or without a usable identity
		key := z.buildSrcOnlyCacheKey(sample.SrcIP, int(sample.SrcPort))
		z.accessLogSeenSrcs.Set(key, struct{}{}, ZTunnelSrcOnlyMappingExpireDuration)

		// the probe also carries the real backend, so it replaces the access-log tailer's
		// mapping duty as well; an existing uprobe mapping is left alone so the resolution
		// source stays attributed to whichever one saw the connection first
		if podIP, podPort := sample.DstIP, sample.DstPort; podIP != "" {
			if _, exist := z.ipMappingCache.Get(key); !exist {
				z.mappingEventCount.Add(1)
				z.ipMappingCache.Set(key, &LoadBalanceAddress{
					IP:     podIP,
					Port:   podPort,
					From:   v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
					Source: sourceRecordInternal,
				}, ZTunnelSrcOnlyMappingExpireDuration)
			}
		}
		z.retroResolve(sample.SrcIP, sample.SrcPort)
		return
	}

	// inbound: the source side carries the ORIGINAL client identity, cached by the peer source
	// IP - the same best-effort by-IP join the access-log path uses
	if sample.MutualTLS {
		z.cachePeerIdentity(sample.SrcIP, sample.Source)
	}
}

// identitySummary renders a decoded identity for the debug log as namespace/serviceAccount@cluster,
// with "-" for a field the read did not recover and "<none>" for a side that carried no identity.
func identitySummary(id *WorkloadIdentity) string {
	if id == nil {
		return "<none>"
	}
	field := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	return fmt.Sprintf("%s/%s@%s", field(id.Namespace), field(id.ServiceAccount), field(id.Cluster))
}

// directionLabel names the leg a decoded sample describes for the debug log. A calibrated offset set
// cannot recover ztunnel's reporter byte, so the direction reads "unknown" there(see HasDirection).
func directionLabel(sample *ztunnelProbeSample) string {
	switch {
	case !sample.DirectionKnown:
		return "unknown"
	case sample.Outbound:
		return directionOutbound
	default:
		return directionInbound
	}
}

// calibrate feeds a sample to the calibrator while no offsets are known, and installs them once
// enough samples agree. A calibrator that runs out of samples without converging ends the path.
func (s *ztunnelIdentitySource) calibrate(window []byte, mem memoryReader) {
	s.mu.Lock()
	calibrator := s.calibrator
	s.mu.Unlock()
	if calibrator == nil {
		return
	}
	s.calibrationTries.Add(1)

	truth := s.collector.calibrationTruth()
	offsets := calibrator.Observe(window, mem, truth, s.collector.realDestinationFor)
	if offsets == nil {
		if calibrator.Exhausted() {
			s.downgrade("runtime calibration did not converge on this ztunnel build")
		}
		return
	}
	ztunnelLog.Infof("runtime calibration recovered the ztunnel identity offsets: %+v", *offsets)
	if !s.adopt(offsets) {
		// calibrated sets never cover the inbound side, so the tailer has to keep running for
		// PEER_*; this is a partial success, NOT a downgrade
		s.collector.startAccessLogTailer()
	}
}

// downgrade ends the uprobe identity path for good and hands identities back to the access-log
// tailer. It is deliberately one-way: a path that has proven it cannot decode this binary will
// not start working later, and flapping between sources would make the data harder to reason
// about than simply staying on the fallback.
func (s *ztunnelIdentitySource) downgrade(reason string) {
	if s.downgraded.Swap(true) {
		return
	}
	// INFO, not WARN: a downgrade is an expected, correct outcome on a ztunnel build whose offsets
	// this agent cannot resolve, and it keeps every identity flowing through the access-log fallback.
	// The line states both the CAUSE(reason) and the WHOLE picture at the moment of the decision(how
	// far the uprobe path got before giving up) so an operator can see at a glance why it fell back.
	ztunnelLog.Infof("detaching the ztunnel identity uprobe and falling back to reading the ztunnel "+
		"access log; reason: %s; identity-uprobe state at downgrade: {events observed: %d, decoded: %d, "+
		"decode failures: %d, calibration samples: %d}",
		reason, s.events.Load(), s.decoded.Load(), s.decodeFailures.Load(), s.calibrationTries.Load())
	// DETACH the record_internal uprobe entirely rather than just silencing its output: the offsets
	// are definitively unavailable, so leaving it attached would keep interrupting ztunnel on its
	// hot path to ship events user space drops. Closing the links removes the interception itself.
	s.detachProbe()
	s.collector.startAccessLogTailer()
}

// setProbeLinks records the record_internal uprobe links this path OWNS(one per monomorphized
// copy), so detachProbe can close them. Called once, right after the probe is attached.
func (s *ztunnelIdentitySource) setProbeLinks(links []io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeLinks = links
}

// detachProbe closes the record_internal uprobe links, removing the uprobe from ztunnel entirely.
// Safe to call with no links(the probe never attached) and idempotent(downgrade latches once).
func (s *ztunnelIdentitySource) detachProbe() {
	s.mu.Lock()
	links := s.probeLinks
	s.probeLinks = nil
	s.mu.Unlock()
	for _, l := range links {
		if err := l.Close(); err != nil {
			ztunnelLog.Warnf("failed to detach a ztunnel identity uprobe link: %v", err)
		}
	}
}

// memReaderFor returns the cached /proc/<pid>/mem reader for a ztunnel process. The identity
// strings live in refcounted buffers the probe cannot copy, so they are read from the process
// afterwards; the pointer cache means this happens once per distinct value, not per connection.
func (s *ztunnelIdentitySource) memReaderFor(pid int32) memoryReader {
	s.mu.Lock()
	defer s.mu.Unlock()
	reader := s.memReaders[pid]
	if reader == nil {
		// a ztunnel restart leaves the old reader behind holding a dead pid; drop them so the map
		// cannot grow without bound across restarts
		for existing, r := range s.memReaders {
			if existing != pid {
				r.Close()
				delete(s.memReaders, existing)
			}
		}
		reader = newProcMemReader(pid)
		s.memReaders[pid] = reader
	}
	return reader
}

// stats renders the identity-probe counters for the periodic stats line.
func (s *ztunnelIdentitySource) stats() string {
	state := "active"
	switch {
	case s.downgraded.Load():
		state = "downgraded to access log"
	case s.decoder.Load() == nil:
		state = "calibrating"
	}
	return fmt.Sprintf("state: %s, events: %d, decoded: %d, decode failures: %d, calibration samples: %d",
		state, s.events.Load(), s.decoded.Load(), s.decodeFailures.Load(), s.calibrationTries.Load())
}

// prepareIdentityProbe resolves the field offsets for a ztunnel binary and reports whether the
// identity uprobe should be attached at all. It also decides, once, whether the access-log
// tailer still has to run alongside it.
func (z *Collector) prepareIdentityProbe(exePath string, pid int32) bool {
	coversEverything := z.identitySource.Prepare(exePath, pid)
	if !coversEverything {
		// Either nothing could be resolved yet(calibration will try, and the tailer covers the
		// gap meanwhile) or the resolved set does not carry the inbound peer identity. Both cases
		// need the access-log tailer, which is exactly the behavior that existed before this
		// probe, so nothing regresses while the uprobe path is incomplete.
		z.startAccessLogTailer()
	}
	// attach in both cases: even an un-resolved binary needs the events, because calibration is
	// driven by them
	return true
}

// calibrationTruth exposes the ztunnel admin config_dump workload index as the known-good data
// runtime calibration recognizes field offsets by.
func (z *Collector) calibrationTruth() *calibrationTruth {
	index := z.workloadIdentities.Load()
	if index == nil {
		return nil
	}
	return &calibrationTruth{byIP: *index}
}

// realDestinationFor reports the real backend pod a downstream source was mapped to, if the
// collector already knows it. This is what ANCHORS calibration: an already-resolved mapping
// turns the config_dump into a statement about what this particular ConnectionResult must hold.
func (z *Collector) realDestinationFor(srcIP string, srcPort uint16) string {
	obj, found := z.ipMappingCache.Get(z.buildSrcOnlyCacheKey(srcIP, int(srcPort)))
	if !found {
		return ""
	}
	address, ok := obj.(*LoadBalanceAddress)
	if !ok || address.Source == sourceRecordInternal {
		// a mapping this probe produced itself is not independent evidence, so it cannot anchor
		// the calibration of this same probe
		return ""
	}
	return address.IP
}
