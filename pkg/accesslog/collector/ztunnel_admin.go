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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/netns"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var (
	// ZTunnelNetnsPollInterval is the interval of polling the ztunnel admin config dump and metrics
	ZTunnelNetnsPollInterval = time.Second * 10
	// ZTunnelAdminConfigDumpURL is the ztunnel admin address inside the ztunnel pod network namespace
	ZTunnelAdminConfigDumpURL = "http://127.0.0.1:15000/config_dump"
	// ZTunnelMetricsURL is the ztunnel prometheus metrics address inside the ztunnel pod network namespace
	ZTunnelMetricsURL = "http://127.0.0.1:15020/metrics"
	// ztunnelTCPOpenedMetricName is used to cross-check how many connections the ztunnel have proxied
	ztunnelTCPOpenedMetricName = "istio_tcp_connections_opened_total"
)

// ztunnelConfigDump is the subset of the ztunnel admin /config_dump response,
// the "workloadState" section is reported by the ztunnel in-pod admin handler
// and contains the per-workload active connections tracked by the ConnectionManager
type ztunnelConfigDump struct {
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

func (z *ZTunnelCollector) startNetnsPollers() {
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

// runNetnsPollCycle runs one admin-dump + metrics poll inside the ztunnel network namespace and
// returns false if the collector is shutting down. The netns work runs in a throwaway goroutine:
// RunInNetNS may fail to switch the OS thread back to the original namespace and then keep it
// locked so the Go runtime discards it - but that only happens when the goroutine EXITS, so doing
// each cycle in its own goroutine lets a poisoned thread be discarded instead of pinning this
// long-lived poller in the ztunnel namespace.
func (z *ZTunnelCollector) runNetnsPollCycle() bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := z.pollAdminConnectionDump(); err != nil {
			ztunnelLog.Warnf("failed to poll the ztunnel admin connection dump: %v", err)
		}
		if err := z.pollZTunnelMetrics(); err != nil {
			ztunnelLog.Warnf("failed to poll the ztunnel metrics: %v", err)
		}
	}()
	select {
	case <-done:
		return true
	case <-z.ctx.Done():
		return false
	}
}

// pollAdminConnectionDump reads the active connections tracked by the ztunnel ConnectionManager
// through the admin API, and feeds the outbound (src, originalDst) -> actualDst mappings into
// the IP mapping cache, the same cache the uprobe based event fills. This works without any
// dependency on the ztunnel binary symbols, but only contains the connections still alive.
func (z *ZTunnelCollector) pollAdminConnectionDump() error {
	body, err := z.httpGetInZTunnelNetNS(ZTunnelAdminConfigDumpURL)
	if err != nil {
		return err
	}
	dump := &ztunnelConfigDump{}
	if err := json.Unmarshal(body, dump); err != nil {
		return fmt.Errorf("unmarshal the config dump error: %w", err)
	}

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
			z.ipMappingCache.Set(key, &ZTunnelLoadBalanceAddress{
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
	return nil
}

// pollZTunnelMetrics reads the total proxied connection count from the ztunnel prometheus
// metrics, used as a cross-check signal in the periodic stats log: when the ztunnel keeps
// opening connections but the agent attaches no ztunnel mapping, the correlation is broken
func (z *ZTunnelCollector) pollZTunnelMetrics() error {
	body, err := z.httpGetInZTunnelNetNS(ZTunnelMetricsURL)
	if err != nil {
		return err
	}
	sum, found := sumPrometheusCounter(string(body), ztunnelTCPOpenedMetricName)
	if found {
		z.metricsOpenedConnections.Store(int64(sum))
	}
	return nil
}

func (z *ZTunnelCollector) httpGetInZTunnelNetNS(rawURL string) ([]byte, error) {
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

// sumPrometheusCounter sums all samples of the given counter family
// from a prometheus text format payload
func sumPrometheusCounter(body, metricName string) (float64, bool) {
	var sum float64
	var found bool
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, metricName) {
			continue
		}
		// require a metric-name boundary after the prefix so a sibling series that
		// merely starts with the same name(e.g. <name>_created, <name>_bucket) is not
		// summed in: the counter name is followed by '{'(labels) or whitespace
		if rest := line[len(metricName):]; rest != "" && rest[0] != '{' && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		sum += value
		found = true
	}
	return sum, found
}
