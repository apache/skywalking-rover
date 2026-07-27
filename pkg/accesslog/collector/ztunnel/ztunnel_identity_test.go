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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/ip"
)

func kvJoin(kvs []*keyStringValuePair) string {
	s := ""
	for _, kv := range kvs {
		s += kv.GetKey() + "=" + kv.GetValue() + ";"
	}
	return s
}

func TestHandleAccessLogLineFillsDstIdentity(t *testing.T) {
	z := NewCollector(time.Minute)
	// CRI "<ts> <stream> F <payload>" with a real istio key=value outbound "connection complete"
	// line carrying dst.cluster + dst.identity (tabs are the istio field separators)
	line := "2026-07-16T09:04:42Z stderr F 2026-07-16T09:04:42.066860Z\terror\taccess\tconnection complete\t" +
		`src.addr=10.0.0.5:45000 dst.hbone_addr=10.244.0.20:9080 ` +
		`dst.identity="spiffe://demo.tsb.local/ns/xcp-multicluster/sa/ambient-east-west-gateway" ` +
		`dst.cluster="Kubernetes" direction="outbound"` + "\n"
	z.handleAccessLogLine(line)

	obj, ok := z.dstIdentityCache.Get(z.buildSrcOnlyCacheKey("10.0.0.5", 45000))
	if !ok {
		t.Fatal("expected the access-log dst identity to be cached")
	}
	if got := *obj.(*WorkloadIdentity); got != (WorkloadIdentity{"Kubernetes", "xcp-multicluster", "ambient-east-west-gateway"}) {
		t.Fatalf("cached dst identity = %+v", got)
	}
}

func TestHandleAccessLogLineInboundFillsPeer(t *testing.T) {
	z := NewCollector(time.Minute)
	// a real istio key=value INBOUND "connection complete" line carrying the original client identity
	line := "2026-07-16T09:09:28Z stderr F 2026-07-16T09:09:28.118Z\tinfo\taccess\tconnection complete\t" +
		`src.addr=10.0.43.21:60962 ` +
		`src.identity="spiffe://tsb-dev-3.tsb.local/ns/client-2/sa/default" ` +
		`src.cluster="tsb-dev-2" dst.addr=10.0.43.16:15008 direction="inbound"` + "\n"
	z.handleAccessLogLine(line)

	// cached keyed by the SOURCE IP(the L3 peer), not src.addr:port
	obj, ok := z.peerIdentityCache.Get("10.0.43.21")
	if !ok {
		t.Fatal("expected the inbound peer identity to be cached by src IP")
	}
	if got := *obj.(*WorkloadIdentity); got != (WorkloadIdentity{"tsb-dev-2", "client-2", "default"}) {
		t.Fatalf("cached peer identity = %+v", got)
	}
}

func TestBuildDstAddition(t *testing.T) {
	z := NewCollector(time.Minute)
	// DST_* is resolved from the identity cache(the uprobe/access-log fill it), keyed by the
	// downstream source, and is a miss when that source has no cached identity.
	conn := &common.ConnectionInfo{Socket: &ip.SocketPair{SrcIP: "10.0.0.5", SrcPort: 45000}}

	t.Run("identity cache resolves DST", func(t *testing.T) {
		z.dstIdentityCache.Set(z.buildSrcOnlyCacheKey("10.0.0.5", 45000),
			&WorkloadIdentity{Cluster: "demo", Namespace: "client-1", ServiceAccount: "default"}, time.Minute)
		got := kvJoin(z.buildDstAddition(conn))
		want := "DST_CLUSTER=demo;DST_NS=client-1;DST_SERVICE=default;"
		if got != want {
			t.Fatalf("buildDstAddition = %q, want %q", got, want)
		}
	})

	t.Run("miss when the source has no cached identity", func(t *testing.T) {
		other := &common.ConnectionInfo{Socket: &ip.SocketPair{SrcIP: "9.9.9.9", SrcPort: 1}}
		if got := z.buildDstAddition(other); got != nil {
			t.Fatalf("buildDstAddition should miss, got %v", got)
		}
	})
}

func TestIdentityStatsRatios(t *testing.T) {
	z := NewCollector(time.Minute)
	z.dstIdentityByAccessLog.Store(120)
	z.dstIdentityMissed.Store(15)
	z.peerIdentityByAccessLog.Store(647)
	z.peerIdentityMissed.Store(7)
	// resolved = 120 + 647 = 767, missed = 15 + 7 = 22, total = 789
	got := z.identityStats()
	for _, want := range []string{
		"resolved: 767(97.2%)",
		"missed: 22(2.8%)",
		"of 789",
		"dst resolved: 120",
		"peer resolved: 647",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("identityStats() = %q, missing %q", got, want)
		}
	}
}

func TestIdentityStatsZeroSafe(t *testing.T) {
	z := NewCollector(time.Minute)
	got := z.identityStats()
	if !strings.Contains(got, "of 0") || !strings.Contains(got, "resolved: 0(0.0%)") {
		t.Fatalf("identityStats() with no data = %q", got)
	}
}

func TestCacheDstIdentityFromAccessLog(t *testing.T) {
	z := NewCollector(time.Minute)
	get := func(ipStr string, port int) (*WorkloadIdentity, bool) {
		obj, ok := z.dstIdentityCache.Get(z.buildSrcOnlyCacheKey(ipStr, port))
		if !ok {
			return nil, false
		}
		return obj.(*WorkloadIdentity), true
	}

	t.Run("cluster and identity", func(t *testing.T) {
		z.cacheDstIdentityFromAccessLog("10.0.0.5", 45000, "Kubernetes",
			"spiffe://td/ns/xcp-multicluster/sa/ambient-east-west-gateway")
		id, ok := get("10.0.0.5", 45000)
		if !ok || *id != (WorkloadIdentity{"Kubernetes", "xcp-multicluster", "ambient-east-west-gateway"}) {
			t.Fatalf("got %+v ok=%v", id, ok)
		}
	})

	t.Run("cluster only, no identity", func(t *testing.T) {
		z.cacheDstIdentityFromAccessLog("10.0.0.6", 1, "demo", "")
		id, ok := get("10.0.0.6", 1)
		if !ok || *id != (WorkloadIdentity{Cluster: "demo"}) {
			t.Fatalf("got %+v ok=%v", id, ok)
		}
	})

	t.Run("nothing usable is not cached", func(t *testing.T) {
		z.cacheDstIdentityFromAccessLog("10.0.0.7", 1, "", "garbage")
		if _, ok := get("10.0.0.7", 1); ok {
			t.Fatal("expected no cache entry for unusable identity")
		}
	})
}

func TestBuildPeerAddition(t *testing.T) {
	z := NewCollector(time.Minute)
	// config_dump disabled: PEER_* comes from the inbound access-log cache keyed by the peer IP;
	// the config_dump index is present but must be ignored
	m := map[string]*WorkloadIdentity{
		"10.0.43.21": {Cluster: "ignored", Namespace: "ignored", ServiceAccount: "ignored"},
	}
	z.workloadIdentities.Store(&m)

	t.Run("access-log resolves PEER by peer IP", func(t *testing.T) {
		z.peerIdentityCache.Set("10.0.43.21",
			&WorkloadIdentity{Cluster: "tsb-dev-2", Namespace: "client-2", ServiceAccount: "default"}, time.Minute)
		conn := &common.ConnectionInfo{Socket: &ip.SocketPair{SrcIP: "10.0.43.16", SrcPort: 3306, DestIP: "10.0.43.21", DestPort: 50000}}
		got := kvJoin(z.buildPeerAddition(conn))
		want := "PEER_CLUSTER=tsb-dev-2;PEER_NS=client-2;PEER_SERVICE=default;"
		if got != want {
			t.Fatalf("buildPeerAddition = %q, want %q", got, want)
		}
	})

	t.Run("peer IP miss", func(t *testing.T) {
		conn := &common.ConnectionInfo{Socket: &ip.SocketPair{SrcIP: "10.0.43.16", SrcPort: 3306, DestIP: "127.0.0.6", DestPort: 50000}}
		if got := z.buildPeerAddition(conn); got != nil {
			t.Fatalf("buildPeerAddition miss = %v, want nil", got)
		}
	})
}

func TestIdentityToKVs(t *testing.T) {
	kvString := func(kvs []*keyStringValuePair) string {
		s := ""
		for _, kv := range kvs {
			s += kv.GetKey() + "=" + kv.GetValue() + ";"
		}
		return s
	}
	cases := []struct {
		name, prefix string
		id           *WorkloadIdentity
		want         string
	}{
		{"nil identity", "DST", nil, ""},
		{"full dst", "DST", &WorkloadIdentity{Cluster: "Kubernetes", Namespace: "xcp-multicluster", ServiceAccount: "ambient-east-west-gateway"},
			"DST_CLUSTER=Kubernetes;DST_NS=xcp-multicluster;DST_SERVICE=ambient-east-west-gateway;"},
		{"full peer", "PEER", &WorkloadIdentity{Cluster: "tsb-dev-3", Namespace: "database", ServiceAccount: "default"},
			"PEER_CLUSTER=tsb-dev-3;PEER_NS=database;PEER_SERVICE=default;"},
		{"missing cluster is skipped", "DST", &WorkloadIdentity{Namespace: "database", ServiceAccount: "default"},
			"DST_NS=database;DST_SERVICE=default;"},
		{"only sa", "DST", &WorkloadIdentity{ServiceAccount: "default"}, "DST_SERVICE=default;"},
		{"all empty", "DST", &WorkloadIdentity{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := kvString(identityToKVs(c.prefix, c.id)); got != c.want {
				t.Fatalf("identityToKVs(%q, %+v) = %q, want %q", c.prefix, c.id, got, c.want)
			}
		})
	}
}

func TestParseWorkloadIdentities(t *testing.T) {
	body := []byte(`{"workloads":[
	  {"clusterId":"demo","namespace":"xcp-multicluster","serviceAccount":"ambient-east-west-gateway","workloadIps":["10.4.68.3"]},
	  {"clusterId":"tsb-dev-3","namespace":"database","serviceAccount":"default","workloadIps":["10.0.43.16","10.0.43.99"]},
	  {"clusterId":"skip","namespace":"skip","serviceAccount":"skip","workloadIps":[]}
	]}`)
	got, err := parseWorkloadIdentities(body)
	if err != nil {
		t.Fatalf("parseWorkloadIdentities error: %v", err)
	}
	want := map[string]*WorkloadIdentity{
		"10.4.68.3":  {Cluster: "demo", Namespace: "xcp-multicluster", ServiceAccount: "ambient-east-west-gateway"},
		"10.0.43.16": {Cluster: "tsb-dev-3", Namespace: "database", ServiceAccount: "default"},
		"10.0.43.99": {Cluster: "tsb-dev-3", Namespace: "database", ServiceAccount: "default"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWorkloadIdentities = %#v, want %#v", got, want)
	}
}

func TestParseSpiffeNsSa(t *testing.T) {
	cases := []struct {
		name, spiffe, wantNS, wantSA string
		wantOK                       bool
	}{
		{"full identity", "spiffe://tsb-dev-3.tsb.local/ns/xcp-multicluster/sa/ambient-east-west-gateway",
			"xcp-multicluster", "ambient-east-west-gateway", true},
		{"default sa", "spiffe://demo.tsb.local/ns/client-1/sa/default", "client-1", "default", true},
		{"empty", "", "", "", false},
		{"missing sa", "spiffe://td.local/ns/only-ns", "", "", false},
		{"missing ns", "spiffe://td.local/sa/only-sa", "", "", false},
		{"not spiffe", "http://example.com/ns/x/sa/y", "", "", false},
		{"empty ns segment", "spiffe://td.local/ns//sa/y", "", "", false},
		{"empty sa segment", "spiffe://td.local/ns/x/sa/", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ns, sa, ok := parseSpiffeNsSa(c.spiffe)
			if ns != c.wantNS || sa != c.wantSA || ok != c.wantOK {
				t.Fatalf("parseSpiffeNsSa(%q) = (%q, %q, %v), want (%q, %q, %v)",
					c.spiffe, ns, sa, ok, c.wantNS, c.wantSA, c.wantOK)
			}
		})
	}
}
