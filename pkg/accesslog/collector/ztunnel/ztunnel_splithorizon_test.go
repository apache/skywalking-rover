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
	"testing"
	"time"

	"github.com/shirou/gopsutil/process"
)

// mustParseDump parses a /config_dump fixture into the same *ztunnelConfigDump the admin poller
// hands to refreshSplitHorizonGateways/refreshWorkloadIdentities, so the tests exercise those with
// the exact type the production caller passes(the poller now parses the body once, up front).
func mustParseDump(t *testing.T, body string) *ztunnelConfigDump {
	t.Helper()
	dump := &ztunnelConfigDump{}
	if err := json.Unmarshal([]byte(body), dump); err != nil {
		t.Fatalf("cannot parse the config_dump fixture: %v", err)
	}
	return dump
}

// splitHorizonDumpFixture mirrors the shape of a real ztunnel /config_dump on a node whose mesh
// spans two networks: "database" is backed ONLY by a SplitHorizonWorkload(its endpoints live behind
// the remote network's east-west gateway), while "client-2" is an ordinary same-network service.
// "httpbin" reproduces the case of a service that has NO VIP on the local network at all.
const splitHorizonDumpFixture = `{
  "config": {"network": "nw-tsb-dev-2", "clusterId": "tsb-dev-2"},
  "services": [
    {
      "hostname": "database.database.svc.cluster.local",
      "vips": ["nw-tsb-dev-2/10.47.247.56", "nw-tsb-dev-3/10.3.244.73"],
      "endpoints": {
        "nw-tsb-dev-3/SplitHorizonWorkload/xcp-multicluster/ambient-ew-gw-tsb-dev-3/136.66.237.44/database/database.database.svc.cluster.local": {
          "workloadUid": "nw-tsb-dev-3/SplitHorizonWorkload/xcp-multicluster/ambient-ew-gw-tsb-dev-3/136.66.237.44/database/database.database.svc.cluster.local",
          "status": "Healthy"
        }
      }
    },
    {
      "hostname": "httpbin.database.svc.cluster.local",
      "vips": ["nw-tsb-dev-3/10.3.250.24"],
      "endpoints": {
        "nw-tsb-dev-3/SplitHorizonWorkload/xcp-multicluster/ambient-ew-gw-tsb-dev-3/136.66.237.44/database/httpbin.database.svc.cluster.local": {
          "workloadUid": "nw-tsb-dev-3/SplitHorizonWorkload/xcp-multicluster/ambient-ew-gw-tsb-dev-3/136.66.237.44/database/httpbin.database.svc.cluster.local",
          "status": "Healthy"
        }
      }
    },
    {
      "hostname": "client-2.client-2.svc.cluster.local",
      "vips": ["nw-tsb-dev-2/10.47.254.121"],
      "endpoints": {
        "tsb-dev-2//Pod/client-2/client-2-77df657b76-zfsb2": {
          "workloadUid": "tsb-dev-2//Pod/client-2/client-2-77df657b76-zfsb2",
          "status": "Healthy"
        }
      }
    }
  ]
}`

func TestParseSplitHorizonGateways(t *testing.T) {
	idx, err := parseSplitHorizonGateways([]byte(splitHorizonDumpFixture))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if idx.network != "nw-tsb-dev-2" {
		t.Fatalf("the local network must come from the config block, got %q", idx.network)
	}
	if ns := idx.byVIP["nw-tsb-dev-2/10.47.247.56"]; ns != "xcp-multicluster" {
		t.Fatalf("a split-horizon backed VIP must map to the gateway namespace, got %q", ns)
	}
	if _, ok := idx.byVIP["nw-tsb-dev-2/10.47.254.121"]; ok {
		t.Fatal("an ordinary same-network service must not be indexed as split-horizon")
	}
}

// The VIPs are network scoped: an entry that exists only on a REMOTE network must never be matched
// by a local destination IP, otherwise a same-IP workload on this network is mis-attributed.
func TestLookupSplitHorizonGatewayIsNetworkScoped(t *testing.T) {
	z := NewCollector(time.Minute)
	z.refreshSplitHorizonGateways(mustParseDump(t, splitHorizonDumpFixture))

	if ns, ok := z.lookupSplitHorizonGateway("10.47.247.56"); !ok || ns != "xcp-multicluster" {
		t.Fatalf("the local-network split-horizon VIP must match, got (%q, %v)", ns, ok)
	}
	// httpbin's only VIP is on nw-tsb-dev-3, so this node can never reach it by that address
	if _, ok := z.lookupSplitHorizonGateway("10.3.250.24"); ok {
		t.Fatal("a VIP that exists only on a remote network must not match locally")
	}
	if _, ok := z.lookupSplitHorizonGateway("10.47.254.121"); ok {
		t.Fatal("an ordinary same-network service VIP must not match")
	}
}

// When the destination is a split-horizon service the traffic terminates, on THIS node, at the
// remote network's east-west gateway - so the DST identity describes the gateway(namespace from the
// config_dump, service account fixed) and only the cluster keeps coming from the access log.
func TestBuildDstAdditionUsesEastWestGateway(t *testing.T) {
	z := NewCollector(time.Minute)
	z.refreshSplitHorizonGateways(mustParseDump(t, splitHorizonDumpFixture))

	conn := attachedOutboundConn("10.44.8.22", 41244)
	conn.Socket.DestIP = "10.47.247.56"
	conn.Socket.DestPort = 3306
	// the access log has already landed and carries the remote cluster + the real workload identity
	z.cacheDstIdentityFromAccessLog("10.44.8.22", 41244, "tsb-dev-3",
		"spiffe://cluster.local/ns/database/sa/default")

	kvs := z.buildDstAddition(conn)

	got := kvsToMap(kvs)
	if got["DST_SERVICE"] != eastWestGatewayServiceAccount {
		t.Fatalf("DST_SERVICE must be the fixed east-west gateway account, got %q", got["DST_SERVICE"])
	}
	if got["DST_NS"] != "xcp-multicluster" {
		t.Fatalf("DST_NS must be the gateway namespace, got %q", got["DST_NS"])
	}
	if got["DST_CLUSTER"] != "tsb-dev-3" {
		t.Fatalf("DST_CLUSTER must still come from the access log, got %q", got["DST_CLUSTER"])
	}
}

// A destination that is NOT split-horizon keeps the access-log identity verbatim.
func TestBuildDstAdditionKeepsAccessLogIdentityForLocalService(t *testing.T) {
	z := NewCollector(time.Minute)
	z.refreshSplitHorizonGateways(mustParseDump(t, splitHorizonDumpFixture))

	conn := attachedOutboundConn("10.44.8.22", 41250)
	conn.Socket.DestIP = "10.47.254.121"
	z.cacheDstIdentityFromAccessLog("10.44.8.22", 41250, "tsb-dev-2",
		"spiffe://cluster.local/ns/client-2/sa/default")

	got := kvsToMap(z.buildDstAddition(conn))
	if got["DST_NS"] != "client-2" || got["DST_SERVICE"] != "default" {
		t.Fatalf("a same-network destination must keep the access-log identity, got %v", got)
	}
}

// Filling the gateway namespace/account from the config_dump must NOT release the flush deferral:
// the cluster still only ever arrives on the access log, so releasing on "the Addition is non-empty"
// would send the connection to OAP without DST_CLUSTER.
func TestDeferralWaitsForClusterEvenAfterGatewayFill(t *testing.T) {
	z := NewCollector(time.Minute)
	z.collectingProcess.Store(&process.Process{Pid: 4242})
	z.accessLogFollowing.Store(true)
	z.refreshSplitHorizonGateways(mustParseDump(t, splitHorizonDumpFixture))

	conn := attachedOutboundConn("10.44.8.22", 41244)
	conn.Socket.DestIP = "10.47.247.56"
	// attach time: no access log yet, so only the gateway namespace/account are known
	conn.RPCConnection.GetAttachment().GetZTunnel().Addition = z.buildDstAddition(conn)

	if len(conn.RPCConnection.GetAttachment().GetZTunnel().GetAddition()) == 0 {
		t.Fatal("the gateway namespace/account must be attached even before the access log lands")
	}
	if !z.IsResolutionPending(conn) {
		t.Fatal("must keep deferring until DST_CLUSTER arrives from the access log")
	}

	// the access-log line lands: the deferral releases and the cluster is filled in
	z.cacheDstIdentityFromAccessLog("10.44.8.22", 41244, "tsb-dev-3",
		"spiffe://cluster.local/ns/database/sa/default")
	if z.IsResolutionPending(conn) {
		t.Fatal("must stop deferring once the cluster is resolvable")
	}
	got := kvsToMap(conn.RPCConnection.GetAttachment().GetZTunnel().GetAddition())
	if got["DST_CLUSTER"] != "tsb-dev-3" {
		t.Fatalf("DST_CLUSTER must be filled at flush, got %q", got["DST_CLUSTER"])
	}
	if got["DST_SERVICE"] != eastWestGatewayServiceAccount || got["DST_NS"] != "xcp-multicluster" {
		t.Fatalf("the flush-time fill must keep the gateway identity, got %v", got)
	}
}

func kvsToMap(kvs []*keyStringValuePair) map[string]string {
	out := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		out[kv.Key] = kv.Value
	}
	return out
}
