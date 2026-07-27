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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// identityStats renders the identity-addition counters for the periodic stats line: the SHARE of
// identity-needing connections(outbound DST_* + inbound PEER_*) whose identity was resolved(from
// the identity cache the uprobe/access-log fill) vs missed, plus the raw per-category counters.
func (z *Collector) identityStats() string {
	dstResolved, dstMiss := z.dstIdentityByAccessLog.Load(), z.dstIdentityMissed.Load()
	peerResolved, peerMiss := z.peerIdentityByAccessLog.Load(), z.peerIdentityMissed.Load()

	resolved := dstResolved + peerResolved
	missed := dstMiss + peerMiss
	total := resolved + missed
	pct := func(v int64) float64 {
		if total == 0 {
			return 0
		}
		return float64(v) * 100 / float64(total)
	}
	return fmt.Sprintf("resolved: %d(%.1f%%), missed: %d(%.1f%%) of %d; "+
		"dst resolved: %d, dst missed: %d, peer resolved: %d, peer missed: %d",
		resolved, pct(resolved), missed, pct(missed), total,
		dstResolved, dstMiss, peerResolved, peerMiss)
}

// refreshWorkloadIdentities rebuilds the IP -> identity index from a parsed ztunnel /config_dump and
// atomically replaces the whole map, so readers never observe a partially-built index. The index is
// the known-good data runtime calibration recognizes the ConnectionResult field offsets by(see
// calibrationTruth); it is kept current on any node whose ztunnel the offset table does not cover.
func (z *Collector) refreshWorkloadIdentities(dump *ztunnelConfigDump) {
	m := buildWorkloadIdentities(dump)
	z.workloadIdentities.Store(&m)
}

// eastWestGatewayServiceAccount is the identity a cross-network destination is attributed to. When a
// service is backed only by SplitHorizonWorkload endpoints the traffic never reaches the remote
// workload from this node: it terminates at the remote network's east-west gateway, and the remote
// cluster's own agent reports the gateway -> workload hop. Attributing the local hop to the gateway
// is what keeps the two halves from double counting the destination workload's inbound traffic.
const eastWestGatewayServiceAccount = "ambient-east-west-gateway"

// splitHorizonWorkloadMarker is the uid segment ztunnel gives an endpoint that is only reachable
// through a remote network's east-west gateway.
const splitHorizonWorkloadMarker = "SplitHorizonWorkload"

// splitHorizonIndex answers "is this destination VIP served only through a cross-network east-west
// gateway, and if so which namespace is that gateway in". The config_dump VIPs are NETWORK SCOPED
// ("<network>/<ip>"), so lookups are keyed by this ztunnel's own network: the same IP on another
// network is a different address and must never match.
type splitHorizonIndex struct {
	network string
	byVIP   map[string]string
}

// ztunnelDumpConfig and ztunnelServiceEntry are the "config"/"services" sections of the combined
// ztunnelConfigDump(see ztunnel_admin.go): this ztunnel's own network, and each service's VIPs and
// endpoint uids, used to build the split-horizon index.
type ztunnelDumpConfig struct {
	Network string `json:"network"`
}

type ztunnelServiceEntry struct {
	Vips      []string                   `json:"vips"`
	Endpoints map[string]json.RawMessage `json:"endpoints"`
}

// buildSplitHorizonGateways builds the VIP -> east-west gateway namespace index from a parsed
// config_dump.
func buildSplitHorizonGateways(dump *ztunnelConfigDump) *splitHorizonIndex {
	idx := &splitHorizonIndex{network: dump.Config.Network, byVIP: make(map[string]string)}
	for i := range dump.Services {
		svc := &dump.Services[i]
		gatewayNS, ok := splitHorizonGatewayNamespace(svc.Endpoints)
		if !ok {
			continue
		}
		for _, vip := range svc.Vips {
			if vip != "" {
				idx.byVIP[vip] = gatewayNS
			}
		}
	}
	return idx
}

// parseSplitHorizonGateways unmarshals a config_dump body and builds the split-horizon index. Kept
// for the tests that exercise the parse from raw JSON; the poller builds it from the shared parse.
func parseSplitHorizonGateways(body []byte) (*splitHorizonIndex, error) {
	var dump ztunnelConfigDump
	if err := json.Unmarshal(body, &dump); err != nil {
		return nil, err
	}
	return buildSplitHorizonGateways(&dump), nil
}

// splitHorizonGatewayNamespace returns the east-west gateway namespace a service's endpoints sit
// behind, and ok=false unless EVERY endpoint is a split-horizon one. A service that still has a
// local endpoint can be served on this node, so it is deliberately left out of the index rather
// than attributed to a gateway its traffic may never traverse.
func splitHorizonGatewayNamespace(endpoints map[string]json.RawMessage) (string, bool) {
	gatewayNS := ""
	for uid := range endpoints {
		ns, ok := gatewayNamespaceFromSplitHorizonUID(uid)
		if !ok {
			return "", false
		}
		gatewayNS = ns
	}
	return gatewayNS, gatewayNS != ""
}

// gatewayNamespaceFromSplitHorizonUID pulls the gateway namespace out of a split-horizon endpoint
// uid, whose shape is
// "<network>/SplitHorizonWorkload/<gateway-ns>/<gateway-name>/<gateway-ip>/<svc-ns>/<svc-hostname>".
// It scans for the marker rather than indexing fixed positions, so a network name is never assumed
// to be a single segment.
func gatewayNamespaceFromSplitHorizonUID(uid string) (string, bool) {
	parts := strings.Split(uid, "/")
	for i, part := range parts {
		if part == splitHorizonWorkloadMarker && i+1 < len(parts) {
			return parts[i+1], parts[i+1] != ""
		}
	}
	return "", false
}

// refreshSplitHorizonGateways rebuilds the split-horizon index from a parsed /config_dump and swaps
// the whole index atomically, so readers never observe a half-built one.
func (z *Collector) refreshSplitHorizonGateways(dump *ztunnelConfigDump) {
	z.splitHorizonGateways.Store(buildSplitHorizonGateways(dump))
}

// lookupSplitHorizonGateway reports the east-west gateway namespace a destination VIP is served
// through, or ok=false when the destination is reachable on this network.
func (z *Collector) lookupSplitHorizonGateway(destIP string) (string, bool) {
	idx := z.splitHorizonGateways.Load()
	if idx == nil || idx.network == "" || destIP == "" {
		return "", false
	}
	ns, ok := idx.byVIP[idx.network+"/"+destIP]
	return ns, ok
}

// resolveDstIdentity resolves the outbound DST identity: the access-log cached identity, rewritten
// to the east-west gateway when the destination is a cross-network service. Shared by the
// attach-time build and the flush-time fill so the two can never disagree on what the identity is.
func (z *Collector) resolveDstIdentity(connection *common.ConnectionInfo) *WorkloadIdentity {
	if connection.Socket == nil {
		return nil
	}
	var cached *WorkloadIdentity
	if obj, ok := z.dstIdentityCache.Get(
		z.buildSrcOnlyCacheKey(connection.Socket.SrcIP, int(connection.Socket.SrcPort))); ok {
		cached = obj.(*WorkloadIdentity)
	}
	gatewayNS, isSplitHorizon := z.lookupSplitHorizonGateway(connection.Socket.DestIP)
	if !isSplitHorizon {
		return cached
	}
	// the namespace/account describe the GATEWAY(resolved from the config_dump, so they are known
	// before any access-log line lands); the cluster still has to come from the access log - the
	// config_dump carries no usable cluster for a gateway workload, its clusterId is either this
	// local cluster or the "Kubernetes" placeholder
	id := &WorkloadIdentity{Namespace: gatewayNS, ServiceAccount: eastWestGatewayServiceAccount}
	if cached != nil {
		id.Cluster = cached.Cluster
	}
	return id
}

// additionHasKey reports whether an addition already carries a key.
func additionHasKey(kvs []*keyStringValuePair, key string) bool {
	for _, kv := range kvs {
		if kv.GetKey() == key {
			return true
		}
	}
	return false
}

// accessLogEnabled reports whether an access-log line can still arrive for a connection on this node,
// i.e. the tailer currently has a ztunnel access log open and is following it. It deliberately does
// NOT test "a line was parsed recently": on an idle node the only line that would satisfy such a test
// is the connection's OWN line, which is written at connection close and parsed a poll later - after
// the flush decision - so a recency test disables the deferral for exactly the connections that need
// it. A node with no ztunnel log to follow reports false, so nothing is ever deferred for nothing.
func (z *Collector) accessLogEnabled() bool {
	// The identity uprobe fires when ztunnel writes its access-log line, which is still AFTER the
	// connection may reach its flush decision - so a deferral is just as necessary when the
	// identity comes from the probe as when it comes from the log file. Treating an active probe
	// as "an identity can still arrive" is what keeps the DST_* addition from being dropped on
	// nodes where the tailer is deliberately not running.
	return z.accessLogFollowing.Load() || (z.identitySource != nil && z.identitySource.Active())
}

// buildConnectionAddition builds the identity Addition for a resolved ztunnel connection: DST_* for
// the outbound leg(the real destination), PEER_* for the inbound leg(the L3 peer). Returns nil when
// no identity is resolvable(the caller then attaches none).
func (z *Collector) buildConnectionAddition(connection *common.ConnectionInfo,
	address *LoadBalanceAddress) []*keyStringValuePair {
	switch address.From {
	case v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC:
		return z.buildDstAddition(connection)
	case v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_INBOUND_FUNC:
		return z.buildPeerAddition(connection)
	default:
		return nil
	}
}

// buildDstAddition resolves the outbound destination identity from the identity cache(dst.identity
// keyed by the downstream source), which the ConnectionResult uprobe and the access-log tailer both
// fill via cacheDstIdentity.
func (z *Collector) buildDstAddition(connection *common.ConnectionInfo) []*keyStringValuePair {
	// the access-log DST hit/miss is NOT counted here: the identity can still arrive after this
	// attachment is built(filled at flush by isDstIdentityPending), so the outcome is tallied once
	// from the settled attachment in FinalizeConnection. Here we only resolve whatever is known.
	id := z.resolveDstIdentity(connection)
	if id != nil {
		ztunnelAccessLog.Debugf("attached DST identity to connection: %s", identitySummary(id))
	}
	return identityToKVs("DST", id)
}

// identityFromAccessLog builds a WorkloadIdentity from an access-log line's cluster + SPIFFE
// identity, or nil when neither is usable(no cluster and an unparseable identity). A partial
// identity(cluster only, or identity only) is kept: the addition builder emits whichever fields are
// present. Shared by the DST and PEER cache-fill helpers so both parse the line the same way.
func identityFromAccessLog(cluster, identity string) *WorkloadIdentity {
	ns, sa, ok := parseSpiffeNsSa(identity)
	if cluster == "" && !ok {
		return nil
	}
	id := &WorkloadIdentity{Cluster: cluster}
	if ok {
		id.Namespace = ns
		id.ServiceAccount = sa
	}
	return id
}

// cacheDstIdentityFromAccessLog caches the outbound destination identity parsed from an access-log
// line(dst.cluster + dst.identity) as the DST_* fallback, keyed by the downstream source.
func (z *Collector) cacheDstIdentityFromAccessLog(srcIP string, srcPort int, cluster, identity string) {
	z.cacheDstIdentity(srcIP, srcPort, identityFromAccessLog(cluster, identity))
}

// cacheDstIdentity stores an already-resolved outbound destination identity under the
// downstream-source key. Both identity sources - the access-log tailer and the
// ConnectionResult uprobe - funnel through here, so switching the source cannot change the
// keying or the TTL that everything downstream depends on.
func (z *Collector) cacheDstIdentity(srcIP string, srcPort int, id *WorkloadIdentity) {
	if id == nil {
		return
	}
	z.dstIdentityCache.Set(z.buildSrcOnlyCacheKey(srcIP, srcPort), id, ZTunnelSrcOnlyMappingExpireDuration)
}

// buildPeerAddition resolves the inbound PEER_* identity(the original client) from the peer identity
// cache(src.identity keyed by the peer source IP), which the ConnectionResult uprobe and the
// access-log tailer both fill - a best-effort join, since only the source IP(not the connection) is
// shared between the identity source and the monitored socket.
func (z *Collector) buildPeerAddition(connection *common.ConnectionInfo) []*keyStringValuePair {
	if connection.Socket == nil {
		return nil
	}
	// like the DST leg, the access-log PEER hit/miss is tallied once in FinalizeConnection from the
	// settled attachment, not here(the identity may still be filled after this build).
	if obj, ok := z.peerIdentityCache.Get(connection.Socket.DestIP); ok {
		id := obj.(*WorkloadIdentity)
		ztunnelAccessLog.Debugf("attached PEER identity to connection: %s", identitySummary(id))
		return identityToKVs("PEER", id)
	}
	return nil
}

// cachePeerIdentityFromAccessLog stores the ORIGINAL client identity parsed from an INBOUND
// access-log line(src.cluster + src.identity), keyed by the source IP(the L3 peer), as the PEER_*
// source. Best-effort by IP: a later line from the same IP overwrites the entry, which is correct
// when the IP is a single workload and last-write-wins otherwise. Skips entries with nothing usable.
func (z *Collector) cachePeerIdentityFromAccessLog(srcIP, cluster, identity string) {
	z.cachePeerIdentity(srcIP, identityFromAccessLog(cluster, identity))
}

// cachePeerIdentity stores an already-resolved inbound peer identity keyed by the peer source
// IP, the same best-effort by-IP join the access-log path uses. Shared by both identity sources
// so the uprobe cannot drift from the access-log semantics.
func (z *Collector) cachePeerIdentity(srcIP string, id *WorkloadIdentity) {
	if id == nil || srcIP == "" {
		return
	}
	z.peerIdentityCache.Set(srcIP, id, ZTunnelSrcOnlyMappingExpireDuration)
}

// keyStringValuePair aliases the common goapi key-value type carried by
// ZTunnelAttachmentEnvironment.Addition, so the addition-building helpers read tersely.
type keyStringValuePair = commonv3.KeyStringValuePair

// identityToKVs renders a workload identity as the addition key-value pairs, keyed by prefix
// ("DST" for the outbound destination, "PEER" for the inbound L3 peer): <prefix>_CLUSTER /
// <prefix>_NS / <prefix>_SERVICE (SERVICE holds the service-account value). A nil identity or an
// empty individual field is skipped so only the fields actually known are emitted.
func identityToKVs(prefix string, id *WorkloadIdentity) []*keyStringValuePair {
	if id == nil {
		return nil
	}
	var kvs []*keyStringValuePair
	kvs = appendKV(kvs, prefix+"_CLUSTER", id.Cluster)
	kvs = appendKV(kvs, prefix+"_NS", id.Namespace)
	kvs = appendKV(kvs, prefix+"_SERVICE", id.ServiceAccount)
	return kvs
}

// appendKV appends a key-value pair unless the value is empty (skip-missing semantics).
func appendKV(kvs []*keyStringValuePair, key, value string) []*keyStringValuePair {
	if value == "" {
		return kvs
	}
	return append(kvs, &keyStringValuePair{Key: key, Value: value})
}

// WorkloadIdentity is the subset of a ztunnel workload the addition needs: the identity a peer
// IP resolves to. Sourced from the ztunnel admin /config_dump "workloads" section.
type WorkloadIdentity struct {
	Cluster        string
	Namespace      string
	ServiceAccount string
}

// ztunnelWorkloadEntry is one entry of the "workloads" section of the combined ztunnelConfigDump
// (see ztunnel_admin.go). Only the fields the addition needs are decoded; the rest is ignored.
type ztunnelWorkloadEntry struct {
	ClusterID      string   `json:"clusterId"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"serviceAccount"`
	WorkloadIps    []string `json:"workloadIps"`
}

// buildWorkloadIdentities returns an index from every workload IP to its identity, from a parsed
// config_dump. Entries without a concrete IP (e.g. the SplitHorizon/NetworkGateway abstract
// workloads carry an empty workloadIps) are skipped: they cannot match a real socket peer.
func buildWorkloadIdentities(dump *ztunnelConfigDump) map[string]*WorkloadIdentity {
	out := make(map[string]*WorkloadIdentity)
	for i := range dump.Workloads {
		w := &dump.Workloads[i]
		if len(w.WorkloadIps) == 0 {
			continue
		}
		id := &WorkloadIdentity{
			Cluster:        w.ClusterID,
			Namespace:      w.Namespace,
			ServiceAccount: w.ServiceAccount,
		}
		for _, ip := range w.WorkloadIps {
			if ip == "" {
				continue
			}
			out[ip] = id
		}
	}
	return out
}

// parseWorkloadIdentities unmarshals a config_dump body and builds the IP -> identity index. Kept
// for the tests that exercise the parse from raw JSON; the poller builds it from the shared parse.
func parseWorkloadIdentities(body []byte) (map[string]*WorkloadIdentity, error) {
	var dump ztunnelConfigDump
	if err := json.Unmarshal(body, &dump); err != nil {
		return nil, err
	}
	return buildWorkloadIdentities(&dump), nil
}

// parseSpiffeNsSa extracts the namespace and service account from a SPIFFE identity of the
// canonical Istio form "spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>".
// It returns ok=false unless both segments are present and non-empty (a partial identity is
// unusable for the DST_*/PEER_* addition, so the caller skips it rather than emitting blanks).
func parseSpiffeNsSa(spiffe string) (ns, sa string, ok bool) {
	if !strings.HasPrefix(spiffe, "spiffe://") {
		return "", "", false
	}
	ns = spiffePathSegment(spiffe, "/ns/")
	sa = spiffePathSegment(spiffe, "/sa/")
	if ns == "" || sa == "" {
		return "", "", false
	}
	return ns, sa, true
}

// spiffePathSegment returns the path segment immediately following key (e.g. "/ns/") up to the
// next "/" or the end of the string, or "" if the key is absent or the segment is empty.
func spiffePathSegment(s, key string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	if end := strings.IndexByte(rest, '/'); end >= 0 {
		return rest[:end]
	}
	return rest
}
