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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/netns"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var (
	// ZTunnelNetnsPollInterval is the interval of polling the ztunnel admin config dump
	ZTunnelNetnsPollInterval = time.Second * 10
	// ZTunnelAdminConfigDumpURL is the ztunnel admin address inside the ztunnel pod network namespace
	ZTunnelAdminConfigDumpURL = "http://127.0.0.1:15000/config_dump"
)

// ztunnelConfigDump is the single parse of a ztunnel /config_dump. One body feeds three different
// indexes(the workload identities, the split-horizon gateways and the active connection mappings),
// so it is unmarshalled ONCE into this combined view and shared, instead of parsing the same body
// three times. The "workloadState" section is the per-workload active connections tracked by the
// ConnectionManager; "workloads"/"services"/"config" back the identity and split-horizon indexes.
type ztunnelConfigDump struct {
	Config        ztunnelDumpConfig               `json:"config"`
	Workloads     []ztunnelWorkloadEntry          `json:"workloads"`
	Services      []ztunnelServiceEntry           `json:"services"`
	WorkloadState map[string]ztunnelWorkloadState `json:"workloadState"`
}

type ztunnelWorkloadState struct {
	Connections *ztunnelConnectionDump `json:"connections"`
}

type ztunnelConnectionDump struct {
	Inbound  []ztunnelConnection `json:"inbound"`
	Outbound []ztunnelConnection `json:"outbound"`
}

type ztunnelConnection struct {
	Src         string `json:"src"`
	OriginalDst string `json:"originalDst"`
	ActualDst   string `json:"actualDst"`
	Protocol    string `json:"protocol"`
}

func (z *Collector) startNetnsPollers() {
	if z.pollersStarted || z.collectingProcess.Load() == nil {
		return
	}
	z.pollersStarted = true
	go func() {
		// Run one poll cycle IMMEDIATELY at attach, before the first tick. The connections
		// established in the window between the app-side capture arming and this ztunnel uprobe
		// attaching never produced an open-time uprobe mapping event; the admin /config_dump lists
		// the connections ztunnel still has open, so this earliest snapshot resolves the ones that
		// are still alive at attach instead of waiting a full poll interval(by which the short,
		// keepalive-less connections are already gone).
		if !z.runNetnsPollCycle() {
			return
		}
		ticker := time.NewTicker(ZTunnelNetnsPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if z.collectingProcess.Load() == nil {
					continue
				}
				if !z.runNetnsPollCycle() {
					return
				}
			case <-z.ctx.Done():
				return
			}
		}
	}()
}

// runNetnsPollCycle runs one admin config-dump poll inside the ztunnel network namespace and
// returns false if the collector is shutting down. The netns work runs in a throwaway goroutine:
// RunInNetNS may fail to switch the OS thread back to the original namespace and then keep it
// locked so the Go runtime discards it - but that only happens when the goroutine EXITS, so doing
// each cycle in its own goroutine lets a poisoned thread be discarded instead of pinning this
// long-lived poller in the ztunnel namespace.
func (z *Collector) runNetnsPollCycle() bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := z.pollAdminConfigDump(); err != nil {
			ztunnelLog.Warnf("failed to poll the ztunnel admin config dump: %v", err)
		}
	}()
	select {
	case <-done:
		return true
	case <-z.ctx.Done():
		return false
	}
}

// pollAdminConfigDump fetches the ztunnel /config_dump ONCE and refreshes everything derived from
// it: the IP -> identity index, the split-horizon gateway index, and the active outbound connection
// mappings. Parsing the(potentially large) body a single time and fanning the parsed dump out to
// the three consumers is why this is not three separate polls. It works without any dependency on
// the ztunnel binary symbols, but only sees the connections still alive.
func (z *Collector) pollAdminConfigDump() error {
	body, err := z.httpGetInZTunnelNetNS(ZTunnelAdminConfigDumpURL)
	if err != nil {
		return err
	}
	dump := &ztunnelConfigDump{}
	if err := json.Unmarshal(body, dump); err != nil {
		return fmt.Errorf("unmarshal the ztunnel config dump: %w", err)
	}
	// Refresh the IP -> identity index. It is not read for the DST_*/PEER_* additions(those come
	// from the identity cache the uprobe/access-log fill), but it is the known-good data runtime
	// calibration recognizes the ConnectionResult field offsets by, so it is kept current on any
	// node whose ztunnel is not covered by the pre-generated offset table.
	z.refreshWorkloadIdentities(dump)
	// the cross-network(east-west gateway) destination index: it decides whether an outbound DST_*
	// addition describes the remote workload or the gateway it goes through.
	z.refreshSplitHorizonGateways(dump)
	// the outbound (src, originalDst) -> actualDst mappings, into the same IP mapping cache the
	// uprobe based event fills.
	z.applyAdminConnectionMappings(dump)
	return nil
}

// applyAdminConnectionMappings feeds the config_dump's per-workload OUTBOUND connections into the
// IP mapping cache and records the alive inbound count for stats.
func (z *Collector) applyAdminConnectionMappings(dump *ztunnelConfigDump) {
	var aliveInboundCount int64
	for _, workload := range dump.WorkloadState {
		if workload.Connections == nil {
			continue
		}
		for _, conn := range workload.Connections.Outbound {
			srcIP, srcPort, err := parseZTunnelAddress(conn.Src)
			if err != nil {
				continue
			}
			origIP, origPort, err := parseZTunnelAddress(conn.OriginalDst)
			if err != nil {
				continue
			}
			actualIP, actualPort, err := parseZTunnelAddress(conn.ActualDst)
			if err != nil {
				continue
			}

			key := z.buildIPMappingCacheKey(srcIP, srcPort, origIP, origPort)
			if _, exist := z.ipMappingCache.Get(key); !exist {
				z.adminOutboundMappingCount.Add(1)
				ztunnelLog.Debugf("found ztunnel outbound connection from admin dump: %s:%d -> %s:%d, actual: %s:%d",
					srcIP, srcPort, origIP, origPort, actualIP, actualPort)
			}
			// always re-set to refresh the expiration for still-alive connections
			z.ipMappingCache.Set(key, &LoadBalanceAddress{
				IP:     actualIP,
				Port:   uint16(actualPort),
				From:   v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
				Source: sourceAdminDump,
			}, z.ipMappingExpireDuration)
		}
		// the inbound entries contain the real client address(src), but not the
		// ephemeral 127.0.0.6 leg the application accepts, so they cannot be
		// correlated to a specific accepted connection, only count them for stats
		aliveInboundCount += int64(len(workload.Connections.Inbound))
	}
	// gauge semantic: the count of alive inbound connections seen in the latest poll
	z.adminInboundSeenCount.Store(aliveInboundCount)
}

func (z *Collector) httpGetInZTunnelNetNS(rawURL string) ([]byte, error) {
	proc := z.collectingProcess.Load()
	if proc == nil {
		return nil, fmt.Errorf("no ztunnel process is collecting")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url %s error: %w", rawURL, err)
	}
	netnsPath := host.GetHostProcInHost(fmt.Sprintf("%d/ns/net", proc.Pid))

	var body []byte
	err = netns.RunInNetNS(netnsPath, func() error {
		// IMPORTANT: dial synchronously on THIS(setns'd) OS thread. net/http.Transport
		// dials new connections in a separate goroutine("go dialConnFor"), which runs
		// on another thread that is NOT switched into the ztunnel network namespace, so
		// the socket would be created in the agent's(host) netns and the connect would
		// be refused. net.DialTimeout to a literal IP:port dials inline on the calling
		// goroutine, keeping the socket in the target namespace.
		conn, err := net.DialTimeout("tcp", parsed.Host, time.Second*5)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(time.Second * 5)); err != nil {
			return err
		}

		req, err := http.NewRequest(http.MethodGet, rawURL, http.NoBody)
		if err != nil {
			return err
		}
		if err := req.Write(conn); err != nil {
			return err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
		body, err = io.ReadAll(resp.Body)
		return err
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

func parseZTunnelAddress(addr string) (ip string, port int, err error) {
	if addr == "" {
		return "", 0, fmt.Errorf("empty address")
	}
	ip, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return ip, port, nil
}
