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
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// ztunnelAccessLog is a dedicated logger module("accesslog.collector.ztunnel.accesslog") so the
// per-line ztunnel access-log PARSE debug logs can be enabled on their own(logger.debug_modules)
// without turning on the rest of the higher-volume ztunnel correlation debug logs.
var ztunnelAccessLog = logger.GetLogger("accesslog", "collector", "ztunnel", "accesslog")

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
func (z *Collector) startAccessLogTailer() {
	// reachable from the identity-probe event goroutines(which start the tailer when they give
	// up on the uprobe path) as well as from the collector startup, so the one-time guard is
	// taken under a mutex
	z.accessLogTailerMutex.Lock()
	defer z.accessLogTailerMutex.Unlock()
	if z.accessLogTailerStarted {
		return
	}
	z.accessLogTailerStarted = true
	// lines older than this are the pre-agent backlog and are skipped(see accessLogBacklogCutoff).
	z.accessLogBacklogCutoff = time.Now().Add(-30 * time.Second)
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
				z.accessLogFollowing.Store(false)
				continue
			}
			// scope the glob to a SINGLE ztunnel pod - the current one on THIS node - each tick(see
			// resolveAccessLogGlob), so the tailer only ever reads one pod UID's logs
			glob := z.resolveAccessLogGlob()

			// (re)resolve the newest ztunnel log file; the kubelet rotates N.log files
			latest := newestMatch(glob)
			if latest == "" {
				// no ztunnel access log to follow on this node: nothing will ever arrive, so the
				// DST identity deferral must not hold anything back
				z.accessLogFollowing.Store(false)
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
					// drain the file we are leaving BEFORE switching(rotation to a new N.log or a
					// ztunnel restart): read its still-unread tail so the lines written between the
					// last poll and the switch are not lost when we jump to the new file at offset 0
					if reader != nil {
						z.drainReader(reader)
					}
					_ = file.Close()
				}
				f, err := os.Open(latest)
				if err != nil {
					ztunnelLog.Debugf("cannot open ztunnel access log %s: %v", latest, err)
					continue
				}
				file, reader, current, offset = f, bufio.NewReader(f), latest, 0
				// a ztunnel access log is open and being followed: a line can arrive for any
				// connection on this node, so the DST identity deferral is worth doing
				z.accessLogFollowing.Store(true)
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
			offset += z.drainReader(reader)
		}
	}()
}

// drainReader reads and handles every complete(\n-terminated) line currently available from reader,
// stopping at EOF or a partial trailing line, and returns the number of bytes consumed(so the caller
// can advance its offset). A partial trailing line waits for the next poll.
func (z *Collector) drainReader(reader *bufio.Reader) int64 {
	var consumed int64
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			consumed += int64(len(line))
			if strings.HasSuffix(line, "\n") {
				z.handleAccessLogLine(line)
			}
		}
		if err != nil {
			break // EOF or partial trailing line: wait for the next poll
		}
	}
	return consumed
}

// resolveAccessLogGlob returns a glob scoped to a SINGLE ztunnel pod's logs: the one currently being
// written on THIS node(the pod directory of the newest matching log file). It reads the local
// /var/log/pods - NOT the ztunnel process - so it stays node-local even where /proc is shared across
// nodes(kind multi-node, where the agent would otherwise see every node's ztunnel), and it pins the
// tailer to that one pod so it never flips to another pod directory(an old restarted ztunnel pod's
// leftover rotated logs). Falls back to the broad glob(any ztunnel pod on this node) when no log
// file is found yet.
//
// It scopes by the directory PATH, not a parsed pod UID, so it needs no assumption about the pod-UID
// format(regular UUID vs mirror-pod hash) and no per-runtime handling: the "<namespace>_<name>_<uid>"
// pod-log layout is a KUBELET convention(the kubelet passes this LogDirectory to the CRI runtime via
// the sandbox config), identical on containerd / CRI-O / cri-dockerd and across cloud providers.
func (z *Collector) resolveAccessLogGlob() string {
	if scoped := scopedGlobForNewest(newestMatch(host.GetHostVarLogPodsInHost(ZTunnelAccessLogPodsGlob))); scoped != "" {
		return scoped
	}
	return host.GetHostVarLogPodsInHost(ZTunnelAccessLogPodsGlob)
}

// scopedGlobForNewest turns a pod-log file path ".../pods/<poddir>/<container>/<n>.log" into a glob
// "<...>/<poddir>/*/*.log" that matches only THAT pod's log files, or "" for an empty input.
func scopedGlobForNewest(newestLogFile string) string {
	if newestLogFile == "" {
		return ""
	}
	// .../<poddir>/<container>/<n>.log -> pin to <poddir>/*/*.log
	return filepath.Join(filepath.Dir(filepath.Dir(newestLogFile)), "*", "*.log")
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

// ztunnelAccessLogFields is the subset of a ztunnel access-log line the collector consumes.
type ztunnelAccessLogFields struct {
	srcAddr, podAddr, direction, message             string
	dstCluster, dstIdentity, srcCluster, srcIdentity string
}

// parseZTunnelAccessLogFields extracts those fields from either the JSON(LOG_FORMAT=json) or the
// default plain "key=value" ztunnel payload. ok is false when the payload is not a usable access line.
func parseZTunnelAccessLogFields(payload string) (ztunnelAccessLogFields, bool) {
	var f ztunnelAccessLogFields
	if strings.HasPrefix(strings.TrimSpace(payload), "{") {
		// ztunnel is configured with LOG_FORMAT=json: the payload is a JSON object
		var m map[string]interface{}
		if json.Unmarshal([]byte(payload), &m) != nil {
			return f, false
		}
		f.srcAddr, _ = m["src.addr"].(string)
		f.podAddr, _ = m["dst.hbone_addr"].(string)
		if f.podAddr == "" {
			f.podAddr, _ = m["dst.addr"].(string)
		}
		f.direction, _ = m["direction"].(string)
		f.message, _ = m["message"].(string)
		f.dstCluster, _ = m["dst.cluster"].(string)
		f.dstIdentity, _ = m["dst.identity"].(string)
		f.srcCluster, _ = m["src.cluster"].(string)
		f.srcIdentity, _ = m["src.identity"].(string)
		return f, true
	}
	// default plain "key=value" istio format(tab separated header + space separated fields)
	if !strings.Contains(payload, "\taccess\t") {
		return f, false
	}
	f.srcAddr = extractLogField(payload, "src.addr=")
	f.podAddr = extractLogField(payload, "dst.hbone_addr=")
	if f.podAddr == "" {
		f.podAddr = extractLogField(payload, "dst.addr=")
	}
	f.direction = strings.Trim(extractLogField(payload, "direction="), "\"")
	f.dstCluster = strings.Trim(extractLogField(payload, "dst.cluster="), "\"")
	f.dstIdentity = strings.Trim(extractLogField(payload, "dst.identity="), "\"")
	f.srcCluster = strings.Trim(extractLogField(payload, "src.cluster="), "\"")
	f.srcIdentity = strings.Trim(extractLogField(payload, "src.identity="), "\"")
	if strings.Contains(payload, msgConnectionComplete) {
		f.message = msgConnectionComplete
	} else if strings.Contains(payload, msgConnectionOpened) {
		f.message = msgConnectionOpened
	}
	return f, true
}

// handleAccessLogLine parses one CRI log line and, if it is an outbound ztunnel access log
// event, feeds its (src -> real pod) mapping into the cache keyed by the source address.
//
//nolint:gocyclo // linear parser over 2 on-disk + 2 payload formats; helpers wouldn't cut complexity
func (z *Collector) handleAccessLogLine(line string) {
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

	fields, ok := parseZTunnelAccessLogFields(payload)
	if !ok {
		return
	}
	srcAddr, podAddr, direction, message := fields.srcAddr, fields.podAddr, fields.direction, fields.message
	dstCluster, dstIdentity := fields.dstCluster, fields.dstIdentity
	srcCluster, srcIdentity := fields.srcCluster, fields.srcIdentity

	// one debug line for every successfully-parsed ztunnel access-log line(both directions), on the
	// dedicated "accesslog.collector.ztunnel.accesslog" module so it can be enabled on its own. It
	// names the source[file] so it reads side by side with the uprobe's [source=uprobe] entries -
	// the same module shows both, which is how an operator confirms which path a node is reading.
	ztunnelAccessLog.Debugf("ztunnel access log entry [source=file]: direction=%q message=%q "+
		"src.addr=%s dst=%s src.identity=%q src.cluster=%q dst.identity=%q dst.cluster=%q",
		direction, message, srcAddr, podAddr, srcIdentity, srcCluster, dstIdentity, dstCluster)

	// the INBOUND leg carries the ORIGINAL client identity(src.identity/src.cluster): cache it as the
	// PEER_* source, keyed by the source IP(the L3 peer) for the best-effort by-IP join. The rest of
	// this function handles the outbound leg(app src -> real target pod), so return after caching.
	if direction == directionInbound {
		if srcIP, _, err := parseZTunnelAddress(srcAddr); err == nil && srcIP != "" {
			z.cachePeerIdentityFromAccessLog(srcIP, srcCluster, srcIdentity)
		}
		return
	}

	// only the outbound leg carries (app src -> real target pod)
	if direction != directionOutbound || srcAddr == "" || podAddr == "" {
		return
	}
	if message != msgConnectionComplete && message != msgConnectionOpened {
		return
	}
	srcIP, sp, err := parseZTunnelAddress(srcAddr)
	if err != nil {
		ztunnelAccessLog.Debugf("ztunnel access log entry [source=file]: skipped, cannot parse "+
			"src.addr %q: %v", srcAddr, err)
		return
	}
	podIP, pp, err := parseZTunnelAddress(podAddr)
	if err != nil {
		ztunnelAccessLog.Debugf("ztunnel access log entry [source=file]: skipped, cannot parse "+
			"dst.addr %q: %v", podAddr, err)
		return
	}
	if podIP == "" || strings.HasPrefix(podIP, "127.") {
		return
	}

	// the access-log source is functional regardless of whether it ever wins a resolution;
	// count every parsed outbound mapping so the stats prove the fallback is live even when
	// the uprobes already cover everything
	z.accessLogParsedCount.Add(1)
	// cache the destination identity for the DST_* addition fallback, keyed by the same downstream
	// source key. Done independently of the lb mapping below(which early-returns when it already
	// exists) so the identity is available even when the lb mapping came from another source.
	z.cacheDstIdentityFromAccessLog(srcIP, sp, dstCluster, dstIdentity)
	key := z.buildSrcOnlyCacheKey(srcIP, sp)
	// record that an outbound line was seen for this src(identity or not) so a deferred connection
	// stops waiting once its line arrives, even when the line carried no usable identity
	z.accessLogSeenSrcs.Set(key, struct{}{}, ZTunnelSrcOnlyMappingExpireDuration)
	// fill a mapping gap the uprobes did not already cover, WITHOUT overwriting a live uprobe mapping
	// (that would mis-attribute the resolution source and waste writes)
	if _, exist := z.ipMappingCache.Get(key); !exist {
		z.mappingEventCount.Add(1)
		ztunnelLog.Debugf("access-log fallback mapping resolved a gap: %s:%d -> %s:%d", srcIP, sp, podIP, pp)
		z.ipMappingCache.Set(key, &LoadBalanceAddress{
			IP:     podIP,
			Port:   uint16(pp),
			From:   v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
			Source: sourceAccessLog,
		}, ZTunnelSrcOnlyMappingExpireDuration)
	}
	// push: re-offer any still-held UNATTACHED connection for this source so it attaches to the mapping
	// now(instead of waiting for its own next flush). An already-attached connection is skipped here -
	// its late-arriving DST identity is filled at flush time by isDstIdentityPending.
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
