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

package collector

import (
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

func clientConn(srcIP string, srcPort uint16, dstIP string, dstPort uint16) *common.ConnectionInfo {
	return &common.ConnectionInfo{
		Socket: &ip.SocketPair{
			Role:     enums.ConnectionRoleClient,
			SrcIP:    srcIP,
			SrcPort:  srcPort,
			DestIP:   dstIP,
			DestPort: dstPort,
		},
		RPCConnection: &v3.AccessLogConnection{},
	}
}

func TestReadyToFlushConnectionSrcDstHitRetained(t *testing.T) {
	z := NewZTunnelCollector(time.Minute)
	key := z.buildIPMappingCacheKey("10.0.0.5", 45000, "10.96.0.10", 9080)
	z.ipMappingCache.Set(key, &ZTunnelLoadBalanceAddress{
		IP: "10.244.0.20", Port: 9080,
		From: v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC, Source: sourceTrackOutbound,
	}, time.Minute)

	conn := clientConn("10.0.0.5", 45000, "10.96.0.10", 9080)
	z.ReadyToFlushConnection(conn, nil)

	att := conn.RPCConnection.Attachment.GetZTunnel()
	if att == nil || att.RealDestinationIp != "10.244.0.20" {
		t.Fatalf("expected the src+dst mapping to attach the real pod, got %+v", conn.RPCConnection.Attachment)
	}
	// a src+dst mapping is discriminated by the ClusterIP, so it is safe to keep after use
	if _, ok := z.ipMappingCache.Get(key); !ok {
		t.Fatal("a src+dst mapping should be retained after resolving a connection")
	}
}

func TestReadyToFlushConnectionSrcOnlyFallbackRetainsEntry(t *testing.T) {
	z := NewZTunnelCollector(time.Minute)
	srcKey := z.buildSrcOnlyCacheKey("10.0.0.5", 45000)
	z.ipMappingCache.Set(srcKey, &ZTunnelLoadBalanceAddress{
		IP: "10.244.0.21", Port: 15008,
		From: v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC, Source: sourceConnectionResult,
	}, time.Minute)

	// no src+dst entry exists for this connection, so it must fall back to the src-only mapping
	conn := clientConn("10.0.0.5", 45000, "10.96.0.11", 9080)
	z.ReadyToFlushConnection(conn, nil)

	att := conn.RPCConnection.Attachment.GetZTunnel()
	if att == nil || att.RealDestinationIp != "10.244.0.21" {
		t.Fatalf("expected the src-only fallback to attach the real pod, got %+v", conn.RPCConnection.Attachment)
	}
	if att.SecurityPolicy != v3.ZTunnelAttachmentSecurityPolicy_MTLS {
		t.Fatalf("expected MTLS for the port-15008 outbound leg, got %v", att.SecurityPolicy)
	}
	// the src-only entry is retained after consume(NOT evicted): a later connection that reuses
	// the same ephemeral src port to the same service must still resolve from it instead of
	// becoming a degenerate "-|service|-" node while its own uprobe event is still in flight
	if _, ok := z.ipMappingCache.Get(srcKey); !ok {
		t.Fatal("a src-only mapping should be retained after resolving a connection, not evicted")
	}
}

func TestReadyToFlushConnectionNoMappingLeavesUnattached(t *testing.T) {
	z := NewZTunnelCollector(time.Minute)
	// a non-empty cache(so the empty-cache short circuit does not fire) with no matching key
	z.ipMappingCache.Set("src:9.9.9.9:1", &ZTunnelLoadBalanceAddress{IP: "10.244.0.99"}, time.Minute)

	conn := clientConn("10.0.0.5", 45000, "10.96.0.12", 9080)
	z.ReadyToFlushConnection(conn, nil)
	if conn.RPCConnection.Attachment != nil {
		t.Fatal("a connection with no matching mapping must be left unattached(raw service IP)")
	}
}

func TestReadyToFlushConnectionAlreadyAttachedIsNoop(t *testing.T) {
	z := NewZTunnelCollector(time.Minute)
	srcKey := z.buildSrcOnlyCacheKey("10.0.0.5", 45000)
	z.ipMappingCache.Set(srcKey, &ZTunnelLoadBalanceAddress{IP: "10.244.0.21", Source: sourceConnectionResult}, time.Minute)

	conn := clientConn("10.0.0.5", 45000, "10.96.0.11", 9080)
	existing := &v3.ConnectionAttachment{}
	conn.RPCConnection.Attachment = existing
	z.ReadyToFlushConnection(conn, nil)

	if conn.RPCConnection.Attachment != existing {
		t.Fatal("an already-attached connection must not be re-resolved")
	}
	// it must not consume(evict) the src-only entry either, since it early-returned
	if _, ok := z.ipMappingCache.Get(srcKey); !ok {
		t.Fatal("the src-only mapping must be untouched when the connection was already attached")
	}
}

func mappingEvent(srcIP uint32, srcPort uint16, origIP uint32, origPort uint16, lbIP uint32, lbPort uint16) *events.ZTunnelSocketMappingEvent {
	return &events.ZTunnelSocketMappingEvent{
		OriginalSrcIP: srcIP, OriginalSrcPort: srcPort,
		OriginalDestIP: origIP, OriginalDestPort: origPort,
		LoadBalancedDestIP: lbIP, LoadBalancedDestPort: lbPort,
	}
}

func TestIsPlausibleMapping(t *testing.T) {
	// IPs are stored high-byte-first(see convertBPFIPToString): 0x0A....=10.x, 0x7F...=127.x
	full := mappingEvent(0x0A000005, 45000, 0x0A600010, 9080, 0x0AF40014, 9080)
	if !isPlausibleLBMapping(full) || !isPlausibleSrcOnlyMapping(full) {
		t.Fatal("a fully populated, non-loopback mapping should be plausible")
	}

	if isPlausibleLBMapping(mappingEvent(0, 45000, 0x0A600010, 9080, 0x0AF40014, 9080)) {
		t.Fatal("a zero source IP must be rejected")
	}
	if isPlausibleSrcOnlyMapping(mappingEvent(0x0A000005, 45000, 0, 0, 0, 9080)) {
		t.Fatal("a zero load-balanced IP must be rejected for a src-only mapping")
	}

	loopback := mappingEvent(0x0A000005, 45000, 0x0A600010, 9080, 0x7F000001, 9080)
	if isPlausibleLBMapping(loopback) || isPlausibleSrcOnlyMapping(loopback) {
		t.Fatal("a loopback(127.x) load-balanced destination must be rejected(ABI-mismatch guard)")
	}

	// a src-only mapping relaxes exactly the two original-ClusterIP checks
	srcOnly := mappingEvent(0x0A000005, 45000, 0, 0, 0x0AF40014, 9080)
	if !isPlausibleSrcOnlyMapping(srcOnly) {
		t.Fatal("a src-only mapping tolerates a zero original ClusterIP")
	}
	if isPlausibleLBMapping(srcOnly) {
		t.Fatal("an lb mapping requires a non-zero original ClusterIP")
	}
}

func TestBuildSrcOnlyCacheKey(t *testing.T) {
	z := NewZTunnelCollector(time.Minute)
	if got := z.buildSrcOnlyCacheKey("10.0.0.5", 45000); got != "src:10.0.0.5:45000" {
		t.Fatalf("buildSrcOnlyCacheKey = %q, want src:10.0.0.5:45000", got)
	}
	// the src-only key lives in a distinct namespace from the src+dst key so they never collide
	if z.buildSrcOnlyCacheKey("10.0.0.5", 45000) == z.buildIPMappingCacheKey("10.0.0.5", 45000, "10.0.0.5", 45000) {
		t.Fatal("the src-only and src+dst keys must not collide")
	}
}
