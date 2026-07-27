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
	"os"
	"sync"

	"github.com/cilium/ebpf"
	lru "github.com/hashicorp/golang-lru"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	ztunneltool "github.com/apache/skywalking-rover/pkg/tools/ztunnel"
)

// ztunnel's SocketAddr is a 32 byte Rust enum over SocketAddrV4/V6. For the V4 variant the
// payload starts after a 2 byte discriminant, giving the octets at +2 and the port as a
// little-endian u16 at +6. This is the same decoding the long-standing track_outbound probe
// uses on ztunnel's SocketAddr arguments, so it is proven against every ztunnel the agent has
// run on rather than inferred from the layout alone.
const (
	sockAddrV4IPOffset   = 2
	sockAddrV4PortOffset = 6
	sockAddrMinSize      = 8
)

// ztunnelReporterSource is the CommonTrafficLabels.reporter value ztunnel uses for the OUTBOUND
// leg(it is reporting as the source of the connection); destination(1) marks the inbound leg.
const ztunnelReporterSource = 0

// ztunnelSecurityPolicyMutualTLS is the connection_security_policy value that makes the
// principals trustworthy. ztunnel applies the same filter before printing src.identity /
// dst.identity to its access log, so honoring it keeps the uprobe from reporting an identity
// the access-log path would have suppressed.
const ztunnelSecurityPolicyMutualTLS = 1

// ztunnelProbeSample is one decoded ConnectionResult snapshot: the connection's peers plus the
// identities ztunnel itself attributed to each side. It is the uprobe equivalent of one parsed
// ztunnel access-log line, minus the file, the kubelet round trip and the tailer's poll delay.
type ztunnelProbeSample struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16

	// Outbound reports the direction as ztunnel labeled it. It is only meaningful when the
	// offsets came from debug info or the table; a calibrated offset set cannot recover the
	// reporter byte(it carries no signature to calibrate against), so callers must consult
	// DirectionKnown before trusting it.
	Outbound       bool
	DirectionKnown bool

	// MutualTLS mirrors ztunnel's own gate on whether the principals mean anything.
	MutualTLS bool

	Source      *WorkloadIdentity
	Destination *WorkloadIdentity
}

// ztunnelIdentityDecoder turns a raw ConnectionResult window into a sample, using one resolved
// offset set. It holds the ArcStr pointer cache, so repeated connections to the same workload
// cost a map lookup instead of a read of the monitored process' memory.
type ztunnelIdentityDecoder struct {
	offsets *ztunneltool.Offsets
	strings *arcStrCache
}

func newZTunnelIdentityDecoder(offsets *ztunneltool.Offsets, strings *arcStrCache) *ztunnelIdentityDecoder {
	return &ztunnelIdentityDecoder{offsets: offsets, strings: strings}
}

// Decode reads one sample out of the window. It returns an error rather than a partial sample
// whenever the bytes do not look like a ConnectionResult, so a mismatched offset set surfaces as
// a decode failure the caller can count towards downgrading, instead of as a plausible-looking
// identity built from garbage.
func (d *ztunnelIdentityDecoder) Decode(window []byte, mem memoryReader) (*ztunnelProbeSample, error) {
	if len(window) < d.offsets.Window {
		return nil, fmt.Errorf("the probe copied %d bytes but the offsets describe a %d byte struct",
			len(window), d.offsets.Window)
	}
	sample := &ztunnelProbeSample{}

	var ok bool
	if sample.SrcIP, sample.SrcPort, ok = decodeSockAddrV4(window, d.offsets.Src); !ok {
		return nil, fmt.Errorf("the source address at offset %d is not a usable IPv4 SocketAddr", d.offsets.Src)
	}
	// the destination is best effort: an IPv6 peer, or an HBONE hop whose L4 destination is the
	// ztunnel itself, still leaves a perfectly usable sample keyed by the source
	sample.DstIP, sample.DstPort, _ = decodeSockAddrV4(window, d.offsets.Dst)

	// The two single-byte enums are gated INDEPENDENTLY by whether their offset was resolved, not
	// by one shared HasDirection flag. A table/DWARF set carries both(direction + security policy).
	// Runtime calibration can recover the reporter(it flips 0<->1 between outbound and inbound, a
	// signature the differential search keys on) but NOT the security policy(it is 1 on every mesh
	// connection, so nothing separates its byte from other constant-1 bytes); such a set therefore
	// reports the direction and defaults to mTLS, which is correct for the ambient traffic whose
	// identity ztunnel populates in the first place. A set that resolved neither(the partial
	// calibrated set) reports the direction as unknown and the caller decides it from the socket.
	sample.DirectionKnown = d.offsets.Reporter != ztunneltool.OffsetAbsent
	sample.MutualTLS = true
	if b, ok := readWindowByte(window, d.offsets.Reporter); ok {
		sample.Outbound = b == ztunnelReporterSource
	}
	if b, ok := readWindowByte(window, d.offsets.SecurityPolicy); ok {
		sample.MutualTLS = b == ztunnelSecurityPolicyMutualTLS
	}

	sample.Source = d.decodeIdentity(window, d.offsets.SourcePrincipal, d.offsets.SourceCluster,
		d.offsets.SourceNamespace, mem)
	sample.Destination = d.decodeIdentity(window, d.offsets.DestinationPrincipal, d.offsets.DestinationCluster,
		d.offsets.DestinationNamespace, mem)
	if sample.Source == nil && sample.Destination == nil {
		return nil, fmt.Errorf("neither side of the connection carried a decodable identity")
	}
	return sample, nil
}

// decodeIdentity resolves one side's identity: namespace and service account out of the
// Identity::Spiffe triple, cluster out of the sibling DefaultedUnknown<RichStrng>. Any field may
// be absent - a non-mTLS connection has no principal, and a workload ztunnel has not learned yet
// has no cluster - so a partial identity is returned rather than discarded, matching the
// skip-missing semantics the addition builder already applies. Nil means nothing was readable.
func (d *ztunnelIdentityDecoder) decodeIdentity(window []byte, principalOffset, clusterOffset,
	namespaceOffset int, mem memoryReader) *WorkloadIdentity {
	// Resolve the four ArcStr pointers out of the copied window, then decode them exactly as the
	// compact path does - where the probe already extracted these same pointers. Sharing
	// decodeIdentityFromPointers keeps the two event paths decoding identically by construction.
	// The Option<Identity> is niche encoded into the pointers themselves: an absent principal
	// leaves them null, which decodeArcStr reports as an empty string rather than a failure.
	return decodeIdentityFromPointers(d.strings, mem,
		readPointer(window, principalOffset+d.offsets.IdentityNamespace),
		readPointer(window, principalOffset+d.offsets.IdentityServiceAccount),
		readPointer(window, namespaceOffset),
		readPointer(window, clusterOffset))
}

// readWindowByte reads the single byte at off, reporting ok=false for an absent offset(OffsetAbsent)
// or one that would run past the window - so a caller can gate a field on whether it was resolved
// without risking an out-of-range index.
func readWindowByte(window []byte, off int) (byte, bool) {
	if off < 0 || off >= len(window) {
		return 0, false
	}
	return window[off], true
}

// readPointer reads a little-endian 64 bit value at off, or 0 when it would run past the window.
// Zero reads back as the None of a niche-encoded Option, which is what an out-of-range offset
// should degrade to anyway.
func readPointer(window []byte, off int) uint64 {
	if off < 0 || off+8 > len(window) {
		return 0
	}
	return binary.LittleEndian.Uint64(window[off:])
}

// decodeSockAddrV4 pulls an IPv4 address and port out of a Rust SocketAddr at off. ok is false
// for anything that is not a usable IPv4 peer(out of range, or the V6 variant, whose octets
// decode to a zero address here).
func decodeSockAddrV4(window []byte, off int) (ip string, port uint16, ok bool) {
	if off < 0 || off+sockAddrMinSize > len(window) {
		return "", 0, false
	}
	b := window[off+sockAddrV4IPOffset : off+sockAddrV4IPOffset+4]
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		return "", 0, false
	}
	port = binary.LittleEndian.Uint16(window[off+sockAddrV4PortOffset:])
	if port == 0 {
		return "", 0, false
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), port, true
}

// ztunnelOffsetsConfig is the user-space mirror of struct ztunnel_offsets_config_t in
// bpf/accesslog/ambient/ztunnel.h: the RESOLVED offsets pushed into the BPF map so the probe can
// extract only the needed fields and ship the compact event. Field order MUST match the C struct.
type ztunnelOffsetsConfig struct {
	Valid                  int32
	Src                    int32
	Dst                    int32
	Reporter               int32
	SecurityPolicy         int32
	HasDirection           int32
	SourcePrincipal        int32
	DestinationPrincipal   int32
	SourceNamespace        int32
	DestinationNamespace   int32
	SourceCluster          int32
	DestinationCluster     int32
	IdentityNamespace      int32
	IdentityServiceAccount int32
}

func boolToInt32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

// offsetsConfigMap returns the BPF offsets-config map, or nil when the loader did not expose it.
func (s *ztunnelIdentitySource) offsetsConfigMap() *ebpf.Map {
	if s.collector == nil || s.collector.alc == nil || s.collector.alc.BPF == nil {
		return nil
	}
	return s.collector.alc.BPF.ZtunnelOffsetsConfigMap
}

// pushOffsetsConfig writes the resolved offsets into the BPF map keyed by the ztunnel pid, which
// switches the probe from shipping the 520 byte full window to the ~88 byte compact event. Failing
// to push is not fatal: the probe simply keeps shipping the full window and the full-window handler
// keeps decoding it, so the identity path still works, just without the byte saving.
func (s *ztunnelIdentitySource) pushOffsetsConfig(pid int32, offsets *ztunneltool.Offsets) {
	m := s.offsetsConfigMap()
	if m == nil || pid <= 0 {
		return
	}
	cfg := ztunnelOffsetsConfig{
		Valid:          1,
		Src:            int32(offsets.Src),
		Dst:            int32(offsets.Dst),
		Reporter:       int32(offsets.Reporter),
		SecurityPolicy: int32(offsets.SecurityPolicy),
		// derive has_direction from whether the reporter offset was resolved, NOT from the separate
		// HasDirection struct field, so the compact BPF path and the full-window Decode()(which keys
		// DirectionKnown on Reporter != OffsetAbsent) can never disagree about whether the direction
		// is known - even if a future resolver sets Reporter without also flipping HasDirection.
		HasDirection:           boolToInt32(offsets.Reporter != ztunneltool.OffsetAbsent),
		SourcePrincipal:        int32(offsets.SourcePrincipal),
		DestinationPrincipal:   int32(offsets.DestinationPrincipal),
		SourceNamespace:        int32(offsets.SourceNamespace),
		DestinationNamespace:   int32(offsets.DestinationNamespace),
		SourceCluster:          int32(offsets.SourceCluster),
		DestinationCluster:     int32(offsets.DestinationCluster),
		IdentityNamespace:      int32(offsets.IdentityNamespace),
		IdentityServiceAccount: int32(offsets.IdentityServiceAccount),
	}
	if err := m.Update(uint32(pid), &cfg, ebpf.UpdateAny); err != nil {
		ztunnelLog.Warnf("cannot push the resolved ztunnel identity offsets to BPF(pid %d); the probe "+
			"will keep shipping the full window: %v", pid, err)
		return
	}
	ztunnelLog.Infof("pushed resolved ztunnel identity offsets to BPF(pid %d); the probe now ships the "+
		"compact identity event", pid)
}

// HandleCompactEvent is the compact-queue counterpart of HandleEvent: the probe has already decoded
// the addresses and direction and shipped the identity string POINTERS, so there is no window to
// scan and no offsets to apply here - only the pointers to follow into ztunnel's memory, using the
// same string cache and reader as the full path.
func (s *ztunnelIdentitySource) HandleCompactEvent(event *events.ZTunnelConnectionResultCompactEvent) {
	s.events.Add(1)
	if s.downgraded.Load() {
		return
	}
	mem := s.memReaderFor(int32(event.PID))
	sample := s.decodeCompact(event, mem)
	if sample == nil {
		// The probe ships the identity string pointers straight off ztunnel's ConnectionResult, so a
		// NON-NULL pointer that decodes to no plausible identity means the resolved offsets no longer
		// land on an ArcStr for this build - the same "the offsets do not match" signal the full
		// window path raises in Decode, and the reason the compact path needs its OWN downgrade net:
		// once offsets are pushed the full path stops running, so nothing else would ever catch a
		// calibration/table set that decoded the first sample but is wrong for the rest. A connection
		// that legitimately carries no identity(a non-mTLS leg) ships ALL-NULL pointers, so it is not
		// counted and ordinary traffic can never trip the fallback.
		if compactShippedIdentityPointer(event) {
			s.decodeFailures.Add(1)
			ztunnelAccessLog.Debugf("ztunnel access log entry [source=uprobe]: compact event carried " +
				"non-null identity pointers but none decoded to a plausible identity, the offsets may " +
				"not match this ztunnel build")
			if s.consecutiveFails.Add(1) >= int64(ZTunnelIdentityDecodeFailureLimit) {
				s.downgrade(fmt.Sprintf("%d consecutive compact events carried identity pointers that did "+
					"not decode to a plausible identity, the resolved offsets do not match this ztunnel build",
					ZTunnelIdentityDecodeFailureLimit))
			}
		}
		return
	}
	s.consecutiveFails.Store(0)
	s.decoded.Add(1)
	ztunnelAccessLog.Debugf("ztunnel access log entry [source=uprobe]: src=%s:%d dst=%s:%d direction=%s "+
		"mtls=%t src.identity=%s dst.identity=%s",
		sample.SrcIP, sample.SrcPort, sample.DstIP, sample.DstPort, directionLabel(sample),
		sample.MutualTLS, identitySummary(sample.Source), identitySummary(sample.Destination))
	s.apply(sample)
}

// decodeCompact turns a compact event into a sample. It mirrors ztunnelIdentityDecoder.Decode, but
// on pre-extracted fields: the addresses and direction come straight off the event, and each
// identity is resolved by following the shipped pointers rather than reading them out of a window.
func (s *ztunnelIdentitySource) decodeCompact(event *events.ZTunnelConnectionResultCompactEvent,
	mem memoryReader) *ztunnelProbeSample {
	// the source address keys the sample onto a monitored socket; without it there is nothing to
	// correlate, exactly as Decode refuses a window whose Src is not a usable IPv4 SocketAddr
	if event.SrcIP == 0 || event.SrcPort == 0 {
		return nil
	}
	sample := &ztunnelProbeSample{
		SrcIP:          formatZTunnelIPv4(event.SrcIP),
		SrcPort:        event.SrcPort,
		DirectionKnown: event.HasDirection != 0,
		MutualTLS:      true,
	}
	if event.DstIP != 0 && event.DstPort != 0 {
		sample.DstIP = formatZTunnelIPv4(event.DstIP)
		sample.DstPort = event.DstPort
	}
	if event.HasDirection != 0 {
		sample.Outbound = event.Reporter == ztunnelReporterSource
	}
	// the security-policy byte is only trustworthy when the resolved offsets actually located it. A
	// runtime-calibrated set can recover the reporter(it flips between outbound and inbound) but not
	// the policy(it is constant on mesh traffic, so nothing pins its offset), and the probe then
	// ships whatever byte sits at the absent(-1) offset. Mesh traffic whose identity ztunnel fills is
	// mTLS by definition, so leave MutualTLS true rather than reading that unplaced byte.
	if d := s.decoder.Load(); d != nil && d.offsets.SecurityPolicy != ztunneltool.OffsetAbsent {
		sample.MutualTLS = event.SecurityPolicy == ztunnelSecurityPolicyMutualTLS
	}

	sample.Source = decodeIdentityFromPointers(s.strings, mem,
		event.SrcPrincipalNsPtr, event.SrcPrincipalSaPtr, event.SrcNamespacePtr, event.SrcClusterPtr)
	sample.Destination = decodeIdentityFromPointers(s.strings, mem,
		event.DstPrincipalNsPtr, event.DstPrincipalSaPtr, event.DstNamespacePtr, event.DstClusterPtr)
	if sample.Source == nil && sample.Destination == nil {
		return nil
	}
	return sample
}

// compactShippedIdentityPointer reports whether the probe extracted ANY non-null identity pointer
// for this event. A non-null pointer means ztunnel's ConnectionResult actually held an identity at
// the resolved offset, so a failure to decode it is evidence the offsets are wrong and is counted
// towards the downgrade; when every pointer is null the connection simply had no identity to report
// (a non-mTLS leg), which is a normal miss that must NOT push the path towards the access-log fallback.
func compactShippedIdentityPointer(e *events.ZTunnelConnectionResultCompactEvent) bool {
	return e.SrcPrincipalNsPtr != 0 || e.SrcPrincipalSaPtr != 0 ||
		e.DstPrincipalNsPtr != 0 || e.DstPrincipalSaPtr != 0 ||
		e.SrcNamespacePtr != 0 || e.DstNamespacePtr != 0 ||
		e.SrcClusterPtr != 0 || e.DstClusterPtr != 0
}

// decodeIdentityFromPointers resolves one side's identity from the pointers the probe extracted,
// applying the same skip-missing semantics as ztunnelIdentityDecoder.decodeIdentity. Nil means
// nothing was readable.
func decodeIdentityFromPointers(strings *arcStrCache, mem memoryReader,
	principalNsPtr, principalSaPtr, namespaceLabelPtr, clusterPtr uint64) *WorkloadIdentity {
	id := &WorkloadIdentity{}
	ns, nsOK := strings.decodeArcStr(mem, principalNsPtr)
	sa, saOK := strings.decodeArcStr(mem, principalSaPtr)
	if nsOK && saOK {
		id.Namespace, id.ServiceAccount = ns, sa
	}
	if id.Namespace == "" {
		if v, valid := strings.decodeArcStr(mem, namespaceLabelPtr); valid {
			id.Namespace = v
		}
	}
	if v, valid := strings.decodeArcStr(mem, clusterPtr); valid {
		id.Cluster = v
	}
	if id.Namespace == "" && id.ServiceAccount == "" && id.Cluster == "" {
		return nil
	}
	return id
}

// formatZTunnelIPv4 renders the u32 the probe assembled(octets 2..5 of the SocketAddr, most
// significant first) as a dotted IPv4 string, matching user space's decodeSockAddrV4.
func formatZTunnelIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff)
}

// The ztunnel identity fields are Rust `Strng`(= arcstr::ArcStr) values. An ArcStr is a
// #[repr(transparent)] NonNull pointer to
//
//	#[repr(C, align(8))] struct ThinInner { len_flag: PackedFlagUint, count_flag: AtomicUsize, data: [u8; 0] }
//
// where PackedFlagUint packs (flag | len << 1) into one usize. So the string length is
// word0>>1 and the bytes start at OFFSET_DATA = 2 * sizeof(usize) = 16. This layout comes
// from the arcstr crate(locked at 1.2.0 by ztunnel's Cargo.lock), NOT from ztunnel itself,
// so it does not move with the ztunnel version the way the struct field offsets do.
const (
	arcStrLenFlagOffset = 0
	arcStrDataOffset    = 16
	// arcStrMaxLen bounds a plausible identity string(namespace / service account / cluster
	// id / trust domain). A decoded length outside this bound means the pointer was not an
	// ArcStr at all - the offsets are wrong - so the read is rejected instead of allocating
	// a huge buffer from a garbage length.
	arcStrMaxLen = 256
)

// memoryReader reads bytes out of a monitored process' address space. It is an interface so
// the ArcStr decoding can be unit tested against an in-memory fake instead of a live process.
type memoryReader interface {
	ReadAt(p []byte, addr uint64) error
}

// procMemReader reads a process' memory through /proc/<pid>/mem, which supports pread at an
// arbitrary virtual address. The agent already mounts the host /proc(ROVER_HOST_PROC_MAPPING),
// so this needs no capability beyond what the collector already has.
type procMemReader struct {
	pid  int32
	once sync.Once
	file *os.File
	err  error
}

func newProcMemReader(pid int32) *procMemReader {
	return &procMemReader{pid: pid}
}

func (p *procMemReader) ReadAt(buf []byte, addr uint64) error {
	p.once.Do(func() {
		p.file, p.err = os.Open(host.GetHostProcInHost(fmt.Sprintf("%d/mem", p.pid)))
	})
	if p.err != nil {
		return p.err
	}
	// #nosec G115 -- a userspace virtual address always fits in the positive int64 range
	n, err := p.file.ReadAt(buf, int64(addr))
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("short read at 0x%x: %d of %d bytes", addr, n, len(buf))
	}
	return nil
}

func (p *procMemReader) Close() {
	if p.file != nil {
		_ = p.file.Close()
	}
}

// arcStrCache memoizes pointer -> string. The identity strings a ztunnel reports are owned by
// the long-lived Workload entries in its xDS state, so the SAME ArcStr pointer recurs for every
// connection to the same workload. Caching by pointer therefore collapses the steady-state cost
// of the whole identity path to a single map lookup per connection, and is what makes reading
// the strings from userspace(instead of inside the BPF probe) cheap enough.
//
// Keying by raw pointer is only sound while the buffer is alive. These buffers are refcounted and
// held by the workload state, so they outlive any single connection; a workload removed from the
// state could in principle have its address reused by another allocation, so entries are bounded
// by an LRU and every decoded value is still validated by the caller before use.
type arcStrCache struct {
	cache *lru.Cache
}

func newArcStrCache(size int) *arcStrCache {
	c, err := lru.New(size)
	if err != nil {
		// lru.New only fails on a non-positive size, which is a programming error here
		panic(fmt.Sprintf("cannot create the ztunnel ArcStr cache: %v", err))
	}
	return &arcStrCache{cache: c}
}

// decodeArcStr resolves one ztunnel `Strng` to its Go string. ptr is the ArcStr pointer value
// read out of the probed struct; a zero pointer is the None of an Option<Strng>(niche) and
// yields an empty string with ok=true, since "the field is absent" is a normal outcome rather
// than a decoding failure.
func (a *arcStrCache) decodeArcStr(r memoryReader, ptr uint64) (string, bool) {
	if ptr == 0 {
		return "", true
	}
	// an ArcStr points at an align(8) ThinInner, so a misaligned value is definitely not one
	if ptr%8 != 0 {
		return "", false
	}
	if v, ok := a.cache.Get(ptr); ok {
		return v.(string), true
	}
	header := make([]byte, arcStrDataOffset)
	if err := r.ReadAt(header, ptr); err != nil {
		return "", false
	}
	lenFlag := binary.LittleEndian.Uint64(header[arcStrLenFlagOffset:])
	strLen := lenFlag >> 1
	if strLen == 0 || strLen > arcStrMaxLen {
		return "", false
	}
	data := make([]byte, strLen)
	if err := r.ReadAt(data, ptr+arcStrDataOffset); err != nil {
		return "", false
	}
	if !isPlausibleIdentityBytes(data) {
		return "", false
	}
	s := string(data)
	a.cache.Add(ptr, s)
	return s, true
}

// isPlausibleIdentityBytes is the first line of the "did we read the right offsets" defense:
// every field the identity addition needs(namespace, service account, cluster id, SPIFFE
// identity) is printable ASCII. Garbage produced by a wrong offset is overwhelmingly not, so
// rejecting it here turns a version/ABI mismatch into a miss - and eventually into the
// access-log downgrade - instead of into a wrong identity reported to the backend.
func isPlausibleIdentityBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
