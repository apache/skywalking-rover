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
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

	"github.com/shirou/gopsutil/process"
)

func rawIPRemoteConnection() *common.ConnectionInfo {
	return &common.ConnectionInfo{
		Socket: &ip.SocketPair{Role: enums.ConnectionRoleClient},
		RPCConnection: &v3.AccessLogConnection{
			Remote: &v3.ConnectionAddress{
				Address: &v3.ConnectionAddress_Ip{
					Ip: &v3.IPAddress{Host: "10.96.0.10", Port: 9080},
				},
			},
		},
	}
}

func TestIsResolutionPending(t *testing.T) {
	// a collector with no ztunnel process being collected never reports pending
	t.Run("no ztunnel process is not pending", func(t *testing.T) {
		z := NewCollector(time.Minute)
		if z.IsResolutionPending(rawIPRemoteConnection()) {
			t.Fatal("should not be pending when no ztunnel process is collecting")
		}
	})

	// arm a collecting process for the remaining cases
	armed := func() *Collector {
		z := NewCollector(time.Minute)
		z.collectingProcess.Store(&process.Process{Pid: 4242})
		return z
	}

	t.Run("raw IP client leg without attachment is pending", func(t *testing.T) {
		if !armed().IsResolutionPending(rawIPRemoteConnection()) {
			t.Fatal("an unresolved raw-IP client leg should be pending while ztunnel is active")
		}
	})

	t.Run("nil connection is not pending", func(t *testing.T) {
		if armed().IsResolutionPending(nil) {
			t.Fatal("nil connection should not be pending")
		}
	})

	t.Run("already attached is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.RPCConnection.Attachment = &v3.ConnectionAttachment{}
		if armed().IsResolutionPending(conn) {
			t.Fatal("an already-attached connection should not be pending")
		}
	})

	t.Run("server leg is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.Socket.Role = enums.ConnectionRoleServer
		if armed().IsResolutionPending(conn) {
			t.Fatal("the server(inbound) leg does not go through the outbound lb mapping")
		}
	})

	t.Run("conntrack-resolved is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.Socket.ConnTrackResolved = true
		if armed().IsResolutionPending(conn) {
			t.Fatal("a conntrack-resolved connection needs no ztunnel wait")
		}
	})

	t.Run("kubernetes-resolved remote is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.RPCConnection.Remote = &v3.ConnectionAddress{
			Address: &v3.ConnectionAddress_Kubernetes{
				Kubernetes: &v3.KubernetesProcessAddress{ServiceName: "reviews"},
			},
		}
		if armed().IsResolutionPending(conn) {
			t.Fatal("a remote already resolved to a local pod is not a raw service IP")
		}
	})
}

func attachedOutboundConn(srcIP string, srcPort uint16) *common.ConnectionInfo {
	return &common.ConnectionInfo{
		Socket: &ip.SocketPair{Role: enums.ConnectionRoleClient, SrcIP: srcIP, SrcPort: srcPort},
		RPCConnection: &v3.AccessLogConnection{
			Remote: &v3.ConnectionAddress{
				Address: &v3.ConnectionAddress_Ip{Ip: &v3.IPAddress{Host: "10.96.0.10", Port: 3306}},
			},
			Attachment: &v3.ConnectionAttachment{
				Environment: &v3.ConnectionAttachment_ZTunnel{
					ZTunnel: &v3.ZTunnelAttachmentEnvironment{
						By: v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
					},
				},
			},
		},
	}
}

// An attached outbound leg keeps pending until its access-log DST identity is cached, so a short
// connection does not flush the real destination with no identity(the tailer/flush-cycle race that
// leaves ~1 in 5 short connections identity-less). Gated on the access log actually being enabled.
func TestIsResolutionPendingDstIdentity(t *testing.T) {
	armedWithAccessLog := func() *Collector {
		z := NewCollector(time.Minute)
		z.collectingProcess.Store(&process.Process{Pid: 4242})
		z.accessLogFollowing.Store(true) // the tailer is following a ztunnel access log
		return z
	}

	t.Run("attached outbound leg pends while dst identity not yet cached", func(t *testing.T) {
		if !armedWithAccessLog().IsResolutionPending(attachedOutboundConn("10.0.0.5", 45000)) {
			t.Fatal("an attached outbound leg should pend until the access-log dst identity is cached")
		}
	})

	t.Run("attached outbound leg not pending once dst identity is cached", func(t *testing.T) {
		z := armedWithAccessLog()
		z.dstIdentityCache.Set(z.buildSrcOnlyCacheKey("10.0.0.5", 45000), &WorkloadIdentity{Cluster: "c"}, time.Minute)
		if z.IsResolutionPending(attachedOutboundConn("10.0.0.5", 45000)) {
			t.Fatal("a cached dst identity should stop the pending")
		}
	})

	t.Run("stops pending once the src's access-log line was seen even without identity", func(t *testing.T) {
		z := armedWithAccessLog()
		// the line arrived but carried no usable identity(dstIdentityCache stays empty)
		z.accessLogSeenSrcs.Set(z.buildSrcOnlyCacheKey("10.0.0.5", 45000), struct{}{}, time.Minute)
		if z.IsResolutionPending(attachedOutboundConn("10.0.0.5", 45000)) {
			t.Fatal("once the outbound line was parsed(identity or not) there is nothing more to wait for")
		}
	})

	t.Run("no pending when the access log is disabled", func(t *testing.T) {
		z := NewCollector(time.Minute)
		z.collectingProcess.Store(&process.Process{Pid: 4242}) // armed but NO access-log line ever seen
		if z.IsResolutionPending(attachedOutboundConn("10.0.0.5", 45000)) {
			t.Fatal("must not defer for an identity that will never come when access log is off")
		}
	})

	t.Run("attached inbound leg is not pending", func(t *testing.T) {
		conn := attachedOutboundConn("10.0.0.5", 45000)
		conn.RPCConnection.Attachment.GetZTunnel().By = v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_INBOUND_FUNC
		if armedWithAccessLog().IsResolutionPending(conn) {
			t.Fatal("the inbound(peer) leg is not covered by the outbound dst-identity defer")
		}
	})
}

// After a connection attaches via the uprobe mapping with the DST identity still missing, the later
// access-log identity must be filled into the existing attachment(not dropped): ReadyToFlushConnection
// on an already-attached, identity-empty outbound leg fills the addition once the identity is cached.
// The DST identity that arrives after the attachment is filled lazily in the pending check(the flush
// goroutine, right before the log is sent) so the connection proto carries the Addition to OAP. The
// check defers while the Addition is empty and no identity is cached, and fills+stops once it is.
func TestIsDstIdentityPendingFillsAddition(t *testing.T) {
	newArmed := func() *Collector {
		z := NewCollector(time.Minute)
		z.collectingProcess.Store(&process.Process{Pid: 4242})
		z.accessLogFollowing.Store(true)
		return z
	}

	t.Run("defers while the Addition is empty and no identity is cached", func(t *testing.T) {
		z := newArmed()
		conn := attachedOutboundConn("10.0.0.5", 45000)
		conn.RPCConnection.Attachment.GetZTunnel().Addition = nil
		if !z.IsResolutionPending(conn) {
			t.Fatal("must defer while the DST Addition is empty and no identity is cached")
		}
		if len(conn.RPCConnection.GetAttachment().GetZTunnel().GetAddition()) != 0 {
			t.Fatal("must not fabricate an Addition when nothing is cached")
		}
	})

	t.Run("fills the Addition from the cache and stops deferring", func(t *testing.T) {
		z := newArmed()
		conn := attachedOutboundConn("10.0.0.5", 45000)
		conn.RPCConnection.Attachment.GetZTunnel().Addition = nil
		z.dstIdentityCache.Set(z.buildSrcOnlyCacheKey("10.0.0.5", 45000),
			&WorkloadIdentity{Cluster: "tsb-dev-3", Namespace: "database", ServiceAccount: "default"}, time.Minute)
		if z.IsResolutionPending(conn) {
			t.Fatal("a cached identity should fill the Addition and stop the deferral")
		}
		if len(conn.RPCConnection.GetAttachment().GetZTunnel().GetAddition()) == 0 {
			t.Fatal("expected the DST Addition to be filled from the cache in the pending check")
		}
		// filling does NOT count - the hit is tallied once at FinalizeConnection from the settled Addition
		if z.dstIdentityByAccessLog.Load() != 0 {
			t.Fatalf("fill must not count; got dstIdentityByAccessLog=%d", z.dstIdentityByAccessLog.Load())
		}
	})
}

// FinalizeConnection tallies the DST/PEER identity outcome exactly once from the settled attachment:
// a filled addition is a hit, an empty one is a miss, and a connection with no ztunnel attachment is
// not an identity case at all.
func TestFinalizeConnectionCountsIdentityOnce(t *testing.T) {
	t.Run("filled outbound addition counts one dst hit", func(t *testing.T) {
		z := NewCollector(time.Minute)
		conn := attachedOutboundConn("10.0.0.5", 45000)
		conn.RPCConnection.Attachment.GetZTunnel().Addition = identityToKVs("DST", &WorkloadIdentity{Cluster: "c"})
		z.FinalizeConnection(conn)
		if z.dstIdentityByAccessLog.Load() != 1 || z.dstIdentityMissed.Load() != 0 {
			t.Fatalf("hit=%d miss=%d, want 1/0", z.dstIdentityByAccessLog.Load(), z.dstIdentityMissed.Load())
		}
	})

	t.Run("empty outbound addition counts one dst miss", func(t *testing.T) {
		z := NewCollector(time.Minute)
		conn := attachedOutboundConn("10.0.0.5", 45000)
		conn.RPCConnection.Attachment.GetZTunnel().Addition = nil
		z.FinalizeConnection(conn)
		if z.dstIdentityMissed.Load() != 1 || z.dstIdentityByAccessLog.Load() != 0 {
			t.Fatalf("hit=%d miss=%d, want 0/1", z.dstIdentityByAccessLog.Load(), z.dstIdentityMissed.Load())
		}
	})

	t.Run("no ztunnel attachment is not an identity outcome", func(t *testing.T) {
		z := NewCollector(time.Minute)
		z.FinalizeConnection(rawIPRemoteConnection()) // no attachment
		if z.dstIdentityMissed.Load() != 0 || z.dstIdentityByAccessLog.Load() != 0 {
			t.Fatalf("a mapping-miss(no attachment) must not count as an identity outcome")
		}
	})
}

// REGRESSION: on an idle node the tailer may not have parsed a single line yet - the only line that
// would prove access logging is on is the connection's OWN, written at close and parsed a poll later,
// i.e. AFTER the flush decision. Gating the deferral on "a line was parsed recently" therefore left
// exactly the first-after-idle connection unprotected, racing the 1s tailer poll: it reached OAP with
// the real destination but no DST identity Addition. The gate must be "the tailer is following a
// ztunnel access log" instead, so that connection is held until its identity lands.
func TestDefersOnAnIdleNodeBeforeAnyLineIsParsed(t *testing.T) {
	z := NewCollector(time.Minute)
	z.collectingProcess.Store(&process.Process{Pid: 4242})
	z.accessLogFollowing.Store(true) // following the ztunnel log, but NO line parsed yet
	conn := attachedOutboundConn("10.0.0.5", 45000)
	conn.RPCConnection.Attachment.GetZTunnel().Addition = nil

	if !z.IsResolutionPending(conn) {
		t.Fatal("must defer on an idle node while the tailer follows the log but no line has arrived yet")
	}
}

// The flip side: with no ztunnel access log to follow on this node, no identity can ever arrive, so
// nothing may be held back - the connection flushes immediately with whatever it has.
func TestDoesNotDeferWhenNoAccessLogIsFollowed(t *testing.T) {
	z := NewCollector(time.Minute)
	z.collectingProcess.Store(&process.Process{Pid: 4242})
	// accessLogFollowing stays false: the tailer found no ztunnel access log on this node
	conn := attachedOutboundConn("10.0.0.5", 45000)
	conn.RPCConnection.Attachment.GetZTunnel().Addition = nil

	if z.IsResolutionPending(conn) {
		t.Fatal("must not defer when there is no ztunnel access log to follow")
	}
}
