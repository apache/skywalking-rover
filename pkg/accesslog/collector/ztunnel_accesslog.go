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
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var (
	// ZTunnelAccessLogPodsGlob is the per-pod sub-path(UNDER the kubelet pod-log directory) of the
	// ztunnel DaemonSet's access log. The pod-log directory itself(/var/log/pods on the host) is
	// resolved through host.GetHostVarLogPodsInHost, so the in-container mount point is injected via
	// ROVER_HOST_VAR_LOG_PODS_MAPPING and NOT hard-coded. The kubelet writes every container's log
	// under /var/log/pods for ALL CRI runtimes(containerd, CRI-O, cri-dockerd), so this is runtime
	// independent. Tailing it is the ultimate, symbol-independent fallback mapping source: ztunnel
	// emits an access log line for EVERY proxied connection("connection complete" at INFO,
	// "connection opened" at DEBUG) carrying src.addr and dst.hbone_addr(the real backend pod), so
	// it recovers the (downstream src -> real pod) mapping even on a ztunnel build where the uprobe
	// symbols are stripped/renamed and both uprobes fail to attach. The container sub-dir is
	// wildcarded so any container name matches; the ztunnel pod has a single container.
	ZTunnelAccessLogPodsGlob = "istio-system_ztunnel-*/*/*.log"
	// ZTunnelAccessLogPollInterval is how often the tailer polls for new log content / rotation
	ZTunnelAccessLogPollInterval = time.Second
)

const (
	// the two access log messages ztunnel emits per proxied outbound connection(see the
	// ZTunnelAccessLogPodsGlob doc): "connection complete" at INFO, "connection opened" at DEBUG
	msgConnectionComplete = "connection complete"
	msgConnectionOpened   = "connection opened"
)

// startAccessLogTailer starts a background goroutine that tails the local ztunnel access log
// and feeds the (downstream src -> real pod) mappings into the same ipMappingCache the uprobe
// fills, keyed by the source address alone(like the ConnectionResult::new source). It is a
// best-effort fallback: if the log file is absent(no mount / logging disabled) it simply idles.
//
//nolint:gocyclo // linear tail state machine(rotation/truncation/EOF); splitting obscures the flow
func (z *ZTunnelCollector) startAccessLogTailer() {
	if z.accessLogTailerStarted {
		return
	}
	z.accessLogTailerStarted = true
	// lines older than this are the pre-agent backlog and are skipped(see accessLogBacklogCutoff).
	z.accessLogBacklogCutoff = time.Now().Add(-30 * time.Second)
	// resolve the full pod-log glob through the host mapping(ROVER_HOST_VAR_LOG_PODS_MAPPING) so
	// the /var/log/pods mount point is configurable and not hard-coded into the binary.
	glob := host.GetHostVarLogPodsInHost(ZTunnelAccessLogPodsGlob)
	go func() {
		var current string // currently tailed file path
		var reader *bufio.Reader
		var file *os.File
		var offset int64
		defer func() {
			if file != nil {
				_ = file.Close()
			}
		}()
		ticker := time.NewTicker(ZTunnelAccessLogPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-z.ctx.Done():
				return
			case <-ticker.C:
			}

			// nothing to tail until a ztunnel is being collected on this node; skip the glob so a
			// non-ztunnel node does not scan the log dir every tick(the ztunnel log only exists
			// where a ztunnel runs, so this changes no outcome, only avoids the wasted stat)
			if z.collectingProcess.Load() == nil {
				continue
			}

			// (re)resolve the newest ztunnel log file; the kubelet rotates N.log files
			latest := newestMatch(glob)
			if latest == "" {
				continue
			}
			// decide whether to (re)open the file. Reopen on a new newest path(rotation to a new
			// N.log), OR when the same path is now backed by a DIFFERENT inode: kubelet size-based
			// rotation renames the active file and recreates it at the same path, so keying the
			// reopen on the path string alone(latest != current) would leave the tailer pinned to
			// the stale renamed inode and silently stop seeing new lines. os.SameFile compares the
			// underlying inode, catching that case.
			reopen := file == nil || latest != current
			if !reopen {
				if latestInfo, statErr := os.Stat(latest); statErr == nil {
					if openInfo, err := file.Stat(); err != nil || !os.SameFile(latestInfo, openInfo) {
						reopen = true
					}
				}
			}
			if reopen {
				if file != nil {
					_ = file.Close()
				}
				f, err := os.Open(latest)
				if err != nil {
					ztunnelLog.Debugf("cannot open ztunnel access log %s: %v", latest, err)
					continue
				}
				file, reader, current, offset = f, bufio.NewReader(f), latest, 0
				ztunnelLog.Infof("tailing ztunnel access log as a fallback mapping source: %s", latest)
			} else if file != nil {
				// same inode: detect truncation-in-place(file shrank) and restart from the beginning
				if fi, err := file.Stat(); err == nil && fi.Size() < offset {
					_, _ = file.Seek(0, io.SeekStart)
					reader.Reset(file)
					offset = 0
				}
			}
			if reader == nil {
				continue
			}
			for {
				line, err := reader.ReadString('\n')
				if line != "" {
					offset += int64(len(line))
					if strings.HasSuffix(line, "\n") {
						z.handleAccessLogLine(line)
					}
				}
				if err != nil {
					break // EOF or partial trailing line: wait for the next poll
				}
			}
		}
	}()
}

// newestMatch returns the glob match with the most recent modification time, or "".
func newestMatch(glob string) string {
	matches, err := filepath.Glob(glob)
	if err != nil || len(matches) == 0 {
		return ""
	}
	var newest string
	var newestMod time.Time
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if newest == "" || fi.ModTime().After(newestMod) {
			newest, newestMod = m, fi.ModTime()
		}
	}
	return newest
}

// handleAccessLogLine parses one CRI log line and, if it is an outbound ztunnel access log
// event, feeds its (src -> real pod) mapping into the cache keyed by the source address.
//
//nolint:gocyclo // linear parser over 2 on-disk + 2 payload formats; helpers wouldn't cut complexity
func (z *ZTunnelCollector) handleAccessLogLine(line string) {
	// The kubelet writes container logs in one of two on-disk formats depending on the runtime:
	//   - CRI(containerd / CRI-O / cri-dockerd): "<rfc3339-ts> <stream> <F|P> <payload>", where a
	//     partial(P) line is a fragment - ztunnel access log lines are short and never split, so
	//     only full(F) lines are taken;
	//   - docker json-file(legacy dockershim): {"log":"<payload>\n","stream":"...","time":"<ts>"}.
	// Extract (timestamp, payload) from whichever it is so the tailer is runtime independent.
	line = strings.TrimRight(line, "\n")
	var lineTimestamp, payload string
	if strings.HasPrefix(line, "{") {
		var m map[string]string
		if json.Unmarshal([]byte(line), &m) != nil {
			return
		}
		lineTimestamp, payload = m["time"], strings.TrimRight(m["log"], "\n")
	} else {
		fields := strings.SplitN(line, " ", 4)
		if len(fields) < 4 || fields[2] != "F" {
			return
		}
		lineTimestamp, payload = fields[0], fields[3]
	}
	if payload == "" {
		return
	}
	// skip the pre-agent backlog(see accessLogBacklogCutoff): re-parsing/caching the large history
	// the ztunnel logged before this agent started - which the e2e maximizes by running traffic
	// BEFORE the agent - delays the tailer from reaching the RECENT close lines it actually needs,
	// past the startup connections' resolution-defer/delete window, leaving them degenerate.
	if !z.accessLogBacklogCutoff.IsZero() {
		if ts, err := time.Parse(time.RFC3339Nano, lineTimestamp); err == nil && ts.Before(z.accessLogBacklogCutoff) {
			z.accessLogBacklogSkipped.Add(1)
			return
		}
	}

	var srcAddr, podAddr, direction, message string
	if strings.HasPrefix(strings.TrimSpace(payload), "{") {
		// ztunnel is configured with LOG_FORMAT=json: the payload is a JSON object
		var m map[string]interface{}
		if json.Unmarshal([]byte(payload), &m) != nil {
			return
		}
		srcAddr, _ = m["src.addr"].(string)
		podAddr, _ = m["dst.hbone_addr"].(string)
		if podAddr == "" {
			podAddr, _ = m["dst.addr"].(string)
		}
		direction, _ = m["direction"].(string)
		message, _ = m["message"].(string)
	} else {
		// default plain "key=value" istio format(tab separated header + space separated fields)
		if !strings.Contains(payload, "\taccess\t") {
			return
		}
		srcAddr = extractLogField(payload, "src.addr=")
		podAddr = extractLogField(payload, "dst.hbone_addr=")
		if podAddr == "" {
			podAddr = extractLogField(payload, "dst.addr=")
		}
		direction = strings.Trim(extractLogField(payload, "direction="), "\"")
		if strings.Contains(payload, msgConnectionComplete) {
			message = msgConnectionComplete
		} else if strings.Contains(payload, msgConnectionOpened) {
			message = msgConnectionOpened
		}
	}

	// only the outbound leg carries (app src -> real target pod); inbound has the reverse
	if direction != "outbound" || srcAddr == "" || podAddr == "" {
		return
	}
	if message != msgConnectionComplete && message != msgConnectionOpened {
		return
	}
	srcIP, sp, err := parseZTunnelAddress(srcAddr)
	if err != nil {
		return
	}
	podIP, pp, err := parseZTunnelAddress(podAddr)
	if err != nil {
		return
	}
	if podIP == "" || strings.HasPrefix(podIP, "127.") {
		return
	}

	// the access-log source is functional regardless of whether it ever wins a resolution;
	// count every parsed outbound mapping so the stats prove the fallback is live even when
	// the uprobes already cover everything
	z.accessLogParsedCount.Add(1)
	key := z.buildSrcOnlyCacheKey(srcIP, sp)
	// as a fallback, only fill a gap the uprobes did not already cover: do not overwrite a
	// live uprobe mapping(that would mis-attribute the resolution source and waste writes)
	if _, exist := z.ipMappingCache.Get(key); exist {
		return
	}
	z.mappingEventCount.Add(1)
	ztunnelLog.Debugf("access-log fallback mapping resolved a gap: %s:%d -> %s:%d", srcIP, sp, podIP, pp)
	z.ipMappingCache.Set(key, &ZTunnelLoadBalanceAddress{
		IP:     podIP,
		Port:   uint16(pp),
		From:   v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
		Source: sourceAccessLog,
	}, ZTunnelSrcOnlyMappingExpireDuration)
	// push: resolve any still-held connection for this source now(same as the uprobe path)
	z.retroResolve(srcIP, uint16(sp))
}

// extractLogField returns the value following key(e.g. "src.addr=") up to the next space, or "".
func extractLogField(s, key string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	if end := strings.IndexAny(rest, " \t"); end >= 0 {
		return rest[:end]
	}
	return rest
}
