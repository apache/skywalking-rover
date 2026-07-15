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
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/cache"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools/elf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

	"github.com/cilium/ebpf"
	"github.com/shirou/gopsutil/process"
)

var (
	// ZTunnelProcessFinderInterval is the interval to find ztunnel process
	ZTunnelProcessFinderInterval = time.Second * 30
	// ztunnelMappingQueuePerCPUBufferPages / ztunnelMappingQueueMinParallels tune the ztunnel mapping
	// perf queue so the doubled(track_outbound + ConnectionResult) event stream is drained promptly:
	// a large per-CPU ring plus one reader goroutine per CPU keep the delivery latency well within
	// the resolution-defer window(measured via the open->resolution latency buckets), instead of the
	// events backing up and arriving after a short connection has already flushed the raw ClusterIP.
	ztunnelMappingQueuePerCPUBufferPages = 16
	ztunnelMappingQueueMinParallels      = 4
	// ZTunnelTrackBoundSymbolPrefix is the prefix of the symbol name to track outbound connections in ztunnel process
	// ztunnel::proxy::connection_manager::ConnectionManager::track_outbound
	ZTunnelTrackBoundSymbolPrefix = "_ZN7ztunnel5proxy18connection_manager17ConnectionManager14track_outbound"
	// ZTunnelConnectionResultNewSymbolPrefix is the prefix of ztunnel::proxy::metrics::ConnectionResult::new,
	// an associated function ztunnel constructs UNCONDITIONALLY for every proxied connection - including the
	// outbound legs that skip track_outbound through an early-return - so it is a strictly-higher-coverage,
	// log-level-independent source of the (downstream src -> real pod) mapping(the same data ztunnel prints
	// as the access log, captured at construction regardless of log level). Attached best-effort alongside
	// track_outbound so the two sources cover each other across ztunnel versions.
	ZTunnelConnectionResultNewSymbolPrefix = "_ZN7ztunnel5proxy7metrics16ConnectionResult3new"
	// ZTunnelIPMappingExpireDuration is how long an outbound(service IP -> real pod IP)
	// mapping captured from the ztunnel uprobe is kept before a connection flush claims
	// it. Empirically raising this does NOT reduce the residual unresolved rate: the
	// leftover misses are short-lived client connections whose uprobe mapping event is
	// processed slightly AFTER the connection has already flushed(a pipeline race), not
	// mappings that expired - so a longer TTL only grows the cache for no benefit.
	ZTunnelIPMappingExpireDuration = time.Minute
	// ZTunnelSrcOnlyMappingExpireDuration is the TTL for a source-address-only mapping(from
	// ConnectionResult::new or the access-log fallback). The src-only entry is written at
	// connection-open but only CONSUMED when the connection flushes, so it is sized generously above
	// the flush / resolution-defer window - a connection that flushes a little late still finds its
	// mapping present instead of degrading to a degenerate "-|service|-" node. A src-only key carries
	// no destination discriminator, but a reused ephemeral src port almost always targets the same
	// service(whose ClusterIP load-balances over the same pods) and overwrites the entry with its own
	// fresh mapping anyway, so the longer TTL does not cause mis-attribution.
	ZTunnelSrcOnlyMappingExpireDuration = time.Minute * 5
)

// ztunnelLog is a dedicated module("accesslog.collector.ztunnel") so the ambient
// correlation debug logs can be enabled on their own(logger.debug_modules)
// without turning on the high volume accesslog.collector.* debug logs.
var ztunnelLog = logger.GetLogger("accesslog", "collector", "ztunnel")

var zTunnelCollectInstance = NewZTunnelCollector(ZTunnelIPMappingExpireDuration)

// ZTunnelCollector is a collector for ztunnel process in the Ambient Istio scenario
type ZTunnelCollector struct {
	ctx    context.Context
	cancel context.CancelFunc
	alc    *common.AccessLogContext

	// collectingProcess is written by the finder-ticker goroutine on (re)discovery
	// and read concurrently by OnConnectEvent / ReadyToFlushConnection / the netns
	// pollers, so it is guarded by an atomic pointer(same idiom as the counters).
	collectingProcess       atomic.Pointer[process.Process]
	ipMappingCache          *cache.Expiring
	ipMappingExpireDuration time.Duration

	// counters for observability of the ztunnel correlation pipeline
	mappingEventCount   atomic.Int64
	mappingHitCount     atomic.Int64
	mappingMissCount    atomic.Int64
	emptyCacheMissCount atomic.Int64
	// count of uprobe mappings rejected by the plausibility check, a growing value
	// signals the ztunnel binary's track_outbound ABI no longer matches what the
	// uprobe expects(version mismatch)
	invalidMappingCount atomic.Int64

	// resolvedBySource counts, per redundant source, whose cached mapping actually resolved a
	// connection at flush time(reported as a share in the periodic stats). It holds only the
	// four resolution sources, so a nil-safe lookup skips non-resolution tags like sourceInbound.
	resolvedBySource map[ztunnelMappingSource]*atomic.Int64
	// accessLogParsedCount counts the outbound mappings the access-log fallback tailer parsed
	// from the ztunnel log; it proves the fallback is functional even when the uprobes cover
	// everything and it therefore never wins a resolution
	accessLogParsedCount atomic.Int64

	// admin/metrics pollers inside the ztunnel network namespace
	pollersStarted bool
	// accessLogTailerStarted guards the one-time start of the ztunnel access-log fallback tailer
	accessLogTailerStarted bool
	// accessLogBacklogCutoff is set at tailer start; ztunnel access-log lines timestamped before it
	// are the pre-agent backlog(connections proxied before this agent and its uprobes existed, which
	// are not in the connection manager). They are skipped: caching them is wasted, and worse,
	// re-parsing the huge backlog that accumulates when the e2e starts traffic BEFORE the agent
	// delays the tailer from reaching the RECENT close lines(for the startup connections still being
	// resolved) until after they are flushed/deleted, leaving them as degenerate nodes.
	accessLogBacklogCutoff    time.Time
	accessLogBacklogSkipped   atomic.Int64
	adminOutboundMappingCount atomic.Int64
	adminInboundSeenCount     atomic.Int64
	metricsOpenedConnections  atomic.Int64

	// count of connect events observed from the ztunnel process itself, used to
	// diagnose whether the BPF `tgid_is_ztunnel` gate is actually capturing the
	// ztunnel's connect() to the local workload(the inbound correlation source)
	ztunnelConnectEventSeen  atomic.Int64
	ztunnelInboundTaggedSeen atomic.Int64
}

func NewZTunnelCollector(expireTime time.Duration) *ZTunnelCollector {
	return &ZTunnelCollector{
		ipMappingCache:          cache.NewExpiring(),
		ipMappingExpireDuration: expireTime,
		resolvedBySource: map[ztunnelMappingSource]*atomic.Int64{
			sourceTrackOutbound:    new(atomic.Int64),
			sourceConnectionResult: new(atomic.Int64),
			sourceAccessLog:        new(atomic.Int64),
			sourceAdminDump:        new(atomic.Int64),
		},
	}
}

func (z *ZTunnelCollector) Start(_ *module.Manager, ctx *common.AccessLogContext) error {
	z.ctx, z.cancel = context.WithCancel(ctx.RuntimeContext)
	z.alc = ctx
	ctx.ConnectionMgr.RegisterNewFlushListener(z)

	err := z.findZTunnelProcessAndCollect()
	if err != nil {
		return err
	}

	// NOTE: even if the ztunnel process not found at startup, still needs to register
	// the event reader and the finder ticker, the ztunnel process could start later
	// This queue now carries TWO events per connection(track_outbound + ConnectionResult::new), so
	// a single reader with the default 1-page buffer falls behind under a high connection rate(the
	// extra waypoint hop): the mapping events are then read tens of seconds late, after the
	// connection has already flushed with the raw ClusterIP - the dominant residual "-|service|-"
	// cause. Give it a larger per-CPU buffer and a few reader goroutines so mappings are delivered
	// promptly, within the connection's resolution-defer window.
	ctx.BPF.ReadEventAsyncWithBufferSize(ctx.BPF.ZtunnelLbSocketMappingEventQueue, func(data interface{}) {
		event := data.(*events.ZTunnelSocketMappingEvent)
		localIP := z.convertBPFIPToString(event.OriginalSrcIP)
		localPort := event.OriginalSrcPort
		lbIP := z.convertBPFIPToString(event.LoadBalancedDestIP)
		z.mappingEventCount.Add(1)

		// A ConnectionResult::new event has no original service ClusterIP(OriginalDestIP == 0):
		// it carries only the (downstream src -> real pod) pair and is keyed by the source
		// address alone(the app's ephemeral src port is unique per connection). This is the
		// higher-coverage source that also captures the outbound legs track_outbound skips via
		// its early-returns.
		if event.OriginalDestIP == 0 {
			if !isPlausibleSrcOnlyMapping(event) {
				z.invalidMappingCount.Add(1)
				return
			}
			ztunnelLog.Debugf("received ztunnel src-only mapping event: %s:%d -> lb: %s:%d", localIP, localPort, lbIP, event.LoadBalancedDestPort)
			srcOnlyKey := z.buildSrcOnlyCacheKey(localIP, int(localPort))
			z.ipMappingCache.Set(srcOnlyKey, &ZTunnelLoadBalanceAddress{
				IP:     lbIP,
				Port:   event.LoadBalancedDestPort,
				From:   v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
				Source: sourceConnectionResult,
			}, ZTunnelSrcOnlyMappingExpireDuration)
			// push: resolve any connection already held in the manager for this source right now,
			// instead of waiting for its next flush to pull the cache(closes the late-event race)
			z.retroResolve(localIP, localPort)
			return
		}

		remoteIP := z.convertBPFIPToString(event.OriginalDestIP)
		remotePort := event.OriginalDestPort
		ztunnelLog.Debugf("received ztunnel lb socket mapping event: %s:%d -> %s:%d, lb: %s", localIP, localPort, remoteIP, remotePort, lbIP)

		// the uprobe reads ztunnel's version-specific Rust internals(track_outbound
		// arg registers + SocketAddr layout). A ztunnel that changed the function
		// signature or the struct layout would make it read the wrong offsets and
		// produce a GARBAGE mapping, which is worse than no mapping(it would attribute
		// traffic to a wrong/non-existent pod). Reject implausible mappings so such a
		// case degrades safely to "unresolved"(the raw service IP the backend can still
		// name at the service level) instead of silently wrong data.
		if !isPlausibleLBMapping(event) {
			z.invalidMappingCount.Add(1)
			ztunnelLog.Warnf("dropping implausible ztunnel lb mapping(possible ztunnel version/ABI mismatch): %s:%d -> %s:%d, lb: %s:%d",
				localIP, localPort, remoteIP, remotePort, lbIP, event.LoadBalancedDestPort)
			return
		}

		key := z.buildIPMappingCacheKey(localIP, int(localPort), remoteIP, int(remotePort))
		z.ipMappingCache.Set(key, &ZTunnelLoadBalanceAddress{
			IP:     lbIP,
			Port:   event.LoadBalancedDestPort,
			From:   v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
			Source: sourceTrackOutbound,
		}, z.ipMappingExpireDuration)
	}, os.Getpagesize()*ztunnelMappingQueuePerCPUBufferPages, ztunnelMappingQueueParallels(), func() interface{} {
		return &events.ZTunnelSocketMappingEvent{}
	})
	go func() {
		ticker := time.NewTicker(ZTunnelProcessFinderInterval)
		var lastMissCount, lastEmptyCacheMissCount int64
		for {
			select {
			case <-ticker.C:
				err := z.findZTunnelProcessAndCollect()
				if err != nil {
					ztunnelLog.Error("failed to find and collect ztunnel process: ", err)
				}
				missCount, emptyCacheMissCount := z.mappingMissCount.Load(), z.emptyCacheMissCount.Load()
				logFunc := ztunnelLog.Debugf
				// promote to info level when new un-correlated connections appeared in this interval,
				// so the resolve failures are visible without enabling the debug level
				if missCount > lastMissCount || emptyCacheMissCount > lastEmptyCacheMissCount {
					logFunc = ztunnelLog.Infof
				}
				logFunc("ztunnel correlation stats: uprobe mapping events received: %d, invalid mappings dropped: %d, "+
					"admin dump outbound mappings: %d, admin dump inbound connections seen: %d, ztunnel-pid connect events seen: %d, "+
					"inbound legs tagged: %d, attach hits: %d, attach misses: %d, empty cache misses: %d, "+
					"ztunnel reported opened connections(metrics): %d, resolution by source: {%s}",
					z.mappingEventCount.Load(), z.invalidMappingCount.Load(), z.adminOutboundMappingCount.Load(),
					z.adminInboundSeenCount.Load(), z.ztunnelConnectEventSeen.Load(), z.ztunnelInboundTaggedSeen.Load(),
					z.mappingHitCount.Load(), missCount, emptyCacheMissCount, z.metricsOpenedConnections.Load(),
					z.resolutionSourceStats())
				lastMissCount, lastEmptyCacheMissCount = missCount, emptyCacheMissCount
			case <-z.ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	// start the symbol-independent access-log fallback tailer(best-effort: idles if the log
	// file is not mounted / access logging is off), so a ztunnel build where both uprobes
	// fail to attach still resolves the ClusterIP hops
	z.startAccessLogTailer()
	return nil
}

func (z *ZTunnelCollector) OnConnectEvent(e *events.SocketConnectEvent, s *ip.SocketPair) bool {
	proc := z.collectingProcess.Load()
	if proc == nil || e == nil || s == nil || uint32(proc.Pid) != e.PID {
		return true
	}
	// any connect event from the ztunnel process reaching here means the BPF
	// `tgid_is_ztunnel` gate is armed and capturing, record it for diagnosis
	z.ztunnelConnectEventSeen.Add(1)
	if s.Role != enums.ConnectionRoleClient {
		return true
	}
	// this is the ztunnel client side connect to the local workload(the inbound leg),
	// revert the source and dest so it matches the workload application accept, and tag
	// the correlated connection as ztunnel inbound
	z.ztunnelInboundTaggedSeen.Add(1)
	key := z.buildIPMappingCacheKey(s.DestIP, int(s.DestPort), s.SrcIP, int(s.SrcPort))
	z.ipMappingCache.Set(key, &ZTunnelLoadBalanceAddress{
		From:   v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_INBOUND_FUNC,
		Source: sourceInbound,
	}, z.ipMappingExpireDuration)
	ztunnelLog.Debugf("found the ztunnel inbound connection, "+
		"connection ID: %d, randomID: %d, pid: %d, fd: %d, role: %s, local: %s:%d, remote: %s:%d",
		e.ConID, e.RandomID, e.PID, e.SocketFD, enums.ConnectionRole(e.Role), s.SrcIP, s.SrcPort, s.DestIP, s.DestPort)
	return false
}

func (z *ZTunnelCollector) ReadyToFlushConnection(connection *common.ConnectionInfo, _ events.Event) {
	if connection == nil || connection.Socket == nil || connection.RPCConnection == nil || connection.RPCConnection.Attachment != nil {
		return
	}
	if z.ipMappingCache.Len() == 0 {
		if z.collectingProcess.Load() != nil {
			z.emptyCacheMissCount.Add(1)
			ztunnelLog.Debugf("the ztunnel IP mapping cache is empty, cannot attach ztunnel address for connection ID: %d, random ID: %d",
				connection.ConnectionID, connection.RandomID)
		}
		return
	}
	key := z.buildIPMappingCacheKey(connection.Socket.SrcIP, int(connection.Socket.SrcPort),
		connection.Socket.DestIP, int(connection.Socket.DestPort))
	lbIPObj, found := z.ipMappingCache.Get(key)
	if !found {
		// fall back to the source-only mapping(from ConnectionResult::new / the access-log
		// fallback), which resolves the outbound connections that skipped track_outbound and
		// therefore have no src+ClusterIP entry - this is what lifts the coverage from
		// track_outbound's ~90% towards 100%
		lbIPObj, found = z.ipMappingCache.Get(z.buildSrcOnlyCacheKey(connection.Socket.SrcIP, int(connection.Socket.SrcPort)))
	}
	if !found {
		z.mappingMissCount.Add(1)
		ztunnelLog.Debugf("there no ztunnel mapped IP address found for connection ID: %d, random ID: %d",
			connection.ConnectionID, connection.RandomID)
		return
	}
	z.mappingHitCount.Add(1)
	address := lbIPObj.(*ZTunnelLoadBalanceAddress)
	// attribute the resolution to the source whose cached mapping actually won, so the periodic
	// stats can report each source's share(non-resolution tags like sourceInbound are absent
	// from the map and skipped)
	if c := z.resolvedBySource[address.Source]; c != nil {
		c.Add(1)
	}
	ztunnelLog.Debugf("found the ztunnel load balanced IP for the connection: %s(source: %s), connectionID: %d, randomID: %d",
		address.String(), address.Source, connection.ConnectionID, connection.RandomID)
	securityPolicy := v3.ZTunnelAttachmentSecurityPolicy_NONE
	// if the target port is 15008, this mean ztunnel have use mTLS
	if address.From == v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC && address.Port == 15008 {
		securityPolicy = v3.ZTunnelAttachmentSecurityPolicy_MTLS
	}
	connection.RPCConnection.Attachment = &v3.ConnectionAttachment{
		Environment: &v3.ConnectionAttachment_ZTunnel{
			ZTunnel: &v3.ZTunnelAttachmentEnvironment{
				RealDestinationIp: address.IP,
				By:                address.From,
				SecurityPolicy:    securityPolicy,
			},
		},
	}
	// diagnostic: record how long this connection took from open to resolution, to LOCATE the
	// late-mapping-event problem(a mass in the >=15s bucket = events delivered too slowly)
	if z.alc != nil && z.alc.ConnectionMgr != nil {
		z.alc.ConnectionMgr.RecordResolutionLatency(connection)
	}
	// NOTE: the src-only entry is deliberately NOT evicted on consume. Evicting it would stop a
	// later connection that reuses the same ephemeral src port from borrowing this mapping - but a
	// reused port almost always targets the SAME service, whose ClusterIP load-balances over the
	// same pods, so the "stale" entry still resolves that connection to a correct pod. What
	// eviction reliably DOES cause is a miss for the reused-port connection when its own uprobe
	// event has not landed yet, leaving it unresolved as a degenerate "-|service|-" node. The
	// short ZTunnelSrcOnlyMappingExpireDuration TTL bounds the staleness instead. (Measured:
	// evict-on-consume raised the unresolved rate ~0.65% -> ~1.7%, all to single-replica services.)
}

// IsResolutionPending implements common.ResolutionAwareFlusher. It reports true while a
// connection's real destination could still be filled by the ztunnel outbound lb mapping
// but has not been yet, so the runner defers the connection's logs a little instead of
// emitting them with the raw service IP(which would create a degenerate "-|service|-"
// entity). It is deliberately conservative - only the client(outbound) leg to a raw,
// not-yet-attached, not-conntrack-resolved remote qualifies - and is bounded by the
// per-connection grace deadline in ShouldDeferForResolution so a genuinely external
// destination is delayed at most one grace period.
func (z *ZTunnelCollector) IsResolutionPending(connection *common.ConnectionInfo) bool {
	// only meaningful while a ztunnel is actually being collected on this node, otherwise
	// no mapping will ever arrive and deferring would only add latency
	if z.collectingProcess.Load() == nil {
		return false
	}
	if connection == nil || connection.RPCConnection == nil || connection.Socket == nil {
		return false
	}
	// already correlated to the real destination
	if connection.RPCConnection.Attachment != nil {
		return false
	}
	// only the client(outbound) leg goes through the ztunnel outbound lb mapping
	if connection.Socket.Role != enums.ConnectionRoleClient {
		return false
	}
	// the conntrack query already rewrote the address to the real peer, no ztunnel wait needed
	if connection.Socket.ConnTrackResolved {
		return false
	}
	// a remote resolved to a local monitored pod is a Kubernetes address(no raw IP); only a
	// raw IP remote(the service VIP) is a candidate for the ztunnel lb mapping
	remote := connection.RPCConnection.GetRemote()
	if remote == nil || remote.GetIp() == nil {
		return false
	}
	return true
}

// UnresolvedReason implements common.ResolutionAwareFlusher: it categorizes WHY a connection that
// reached the end of its lifetime without a ztunnel attachment is still unresolved, so the periodic
// resolve summary can point at the environment/source that did not provide the mapping.
func (z *ZTunnelCollector) UnresolvedReason(connection *common.ConnectionInfo) string {
	if z.collectingProcess.Load() == nil {
		// no ztunnel process was discovered on this node, so the ambient outbound mapping can never
		// exist here - from this agent's point of view the remote is genuinely just a raw IP
		return "no-ztunnel-process-on-node"
	}
	if !z.IsResolutionPending(connection) {
		// only a raw-IP client(outbound) leg goes through the ztunnel outbound lb mapping; a server
		// leg / conntrack-resolved / already-attached / non-raw remote is not a ztunnel miss
		return "not-a-ztunnel-outbound-leg"
	}
	if z.ipMappingCache.Len() == 0 {
		// ztunnel is being collected but NO mapping was ever captured - the whole correlation source
		// is producing nothing(uprobes not attached / not firing and the log/admin fallbacks empty)
		return "ztunnel-mapping-cache-empty"
	}
	// ztunnel is collecting and mappings exist, but none matched this socket(neither the src+dst
	// track_outbound key nor the src-only ConnectionResult / access-log key) before the connection
	// reached the end of its lifetime: the correlation gap is on the event-capture side - ztunnel
	// emitted no usable event for this source(a track_outbound early-return AND no ConnectionResult,
	// or a BPF miss).
	return "no-ztunnel-mapping-for-socket"
}

// retroResolve pushes a just-cached source mapping to any connection still held in the manager for
// that source, so a late mapping event does not miss the connection's flush(see RetroResolveBySrc).
// It nil-guards the context so unit tests that construct a bare collector do not panic.
// ztunnelMappingQueueParallels is the reader-goroutine count for the mapping perf queue: one per
// CPU(floored at ztunnelMappingQueueMinParallels) so the doubled event stream is drained in parallel.
func ztunnelMappingQueueParallels() int {
	if n := runtime.NumCPU(); n > ztunnelMappingQueueMinParallels {
		return n
	}
	return ztunnelMappingQueueMinParallels
}

func (z *ZTunnelCollector) retroResolve(srcIP string, srcPort uint16) {
	if z.alc == nil || z.alc.ConnectionMgr == nil {
		return
	}
	z.alc.ConnectionMgr.RetroResolveBySrc(srcIP, srcPort)
}

func (z *ZTunnelCollector) convertBPFIPToString(ipAddr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ipAddr>>24, ipAddr>>16&0xff, ipAddr>>8&0xff, ipAddr&0xff)
}

func (z *ZTunnelCollector) buildIPMappingCacheKey(localIP string, localPort int, remoteIP string, remotePort int) string {
	return fmt.Sprintf("%s:%d-%s:%d", localIP, localPort, remoteIP, remotePort)
}

// buildSrcOnlyCacheKey keys a mapping by the downstream source address alone, used by the
// ConnectionResult::new source(which carries the real pod but no original service ClusterIP,
// so it cannot be keyed by src+dst like track_outbound). The "src:" prefix keeps it in a
// distinct namespace from the src+dst keys.
func (z *ZTunnelCollector) buildSrcOnlyCacheKey(localIP string, localPort int) string {
	return fmt.Sprintf("src:%s:%d", localIP, localPort)
}

// resolutionSourceOrder fixes the print order of the per-source shares in the stats line.
var resolutionSourceOrder = []ztunnelMappingSource{
	sourceTrackOutbound, sourceConnectionResult, sourceAccessLog, sourceAdminDump,
}

// resolutionSourceStats reports the share each redundant source contributed to the resolved
// connections, plus how many mappings the access-log fallback tailer parsed(its liveness even
// when the uprobes win every resolution).
func (z *ZTunnelCollector) resolutionSourceStats() string {
	var total int64
	for _, s := range resolutionSourceOrder {
		total += z.resolvedBySource[s].Load()
	}
	pct := func(v int64) float64 {
		if total == 0 {
			return 0
		}
		return float64(v) * 100 / float64(total)
	}
	parts := make([]string, 0, len(resolutionSourceOrder))
	for _, s := range resolutionSourceOrder {
		v := z.resolvedBySource[s].Load()
		parts = append(parts, fmt.Sprintf("%s: %d(%.1f%%)", s, v, pct(v)))
	}
	return fmt.Sprintf("%s; access_log lines parsed(fallback live): %d, pre-agent backlog skipped: %d",
		strings.Join(parts, ", "), z.accessLogParsedCount.Load(), z.accessLogBacklogSkipped.Load())
}

// isPlausibleLBMapping sanity-checks a ztunnel lb socket mapping decoded from the
// uprobe. The uprobe reads ztunnel's version-specific Rust ABI(the track_outbound
// argument registers and the SocketAddr byte layout); if a future ztunnel changes
// either, the decode yields garbage. Rejecting an implausible mapping keeps a
// version mismatch from silently attributing traffic to a wrong pod - it degrades
// to unresolved instead. A valid mapping has non-zero src / original-dst / lb-dst
// addresses and ports, and the lb destination(the selected pod) is never loopback.
func isPlausibleLBMapping(e *events.ZTunnelSocketMappingEvent) bool {
	// a valid lb mapping is a valid src-only mapping(non-zero src / lb-dst addr+port, non-loopback
	// pod) plus a non-zero original service ClusterIP destination
	return isPlausibleSrcOnlyMapping(e) && e.OriginalDestIP != 0 && e.OriginalDestPort != 0
}

// isPlausibleSrcOnlyMapping sanity-checks a ConnectionResult::new mapping(downstream src ->
// real pod), which has no original ClusterIP. Same guards as isPlausibleLBMapping minus the
// original-dest checks, so a ztunnel ABI change degrades to unresolved instead of wrong data.
func isPlausibleSrcOnlyMapping(e *events.ZTunnelSocketMappingEvent) bool {
	if e.OriginalSrcIP == 0 || e.LoadBalancedDestIP == 0 {
		return false
	}
	if e.OriginalSrcPort == 0 || e.LoadBalancedDestPort == 0 {
		return false
	}
	return e.LoadBalancedDestIP>>24 != 127
}

func (z *ZTunnelCollector) Stop() {
	if z.cancel != nil {
		z.cancel()
	}
}

func (z *ZTunnelCollector) findZTunnelProcessAndCollect() error {
	if current := z.collectingProcess.Load(); current != nil {
		running, err := current.IsRunning()
		if err == nil && running {
			// already collecting the process
			ztunnelLog.Debugf("found the ztunnel process and collecting ztunnel data from pid: %d", current.Pid)
			return nil
		}
		ztunnelLog.Warnf("detected ztunnel process is not running, should re-scan process to find and collect it")
	}

	processes, err := process.Processes()
	if err != nil {
		return err
	}
	var zTunnelProcess *process.Process
	for _, p := range processes {
		name, err := p.Exe()
		if err != nil {
			continue
		}
		if strings.HasSuffix(name, "/ztunnel") {
			zTunnelProcess = p
			break
		}
	}

	if zTunnelProcess == nil {
		// clear a now-dead process so the netns pollers stop entering the dead
		// /proc/<pid>/ns/net every interval until a ztunnel comes back
		z.collectingProcess.Store(nil)
		ztunnelLog.Debugf("ztunnel process not found is current node")
		return nil
	}

	ztunnelLog.Infof("ztunnel process founded in current node, pid: %d", zTunnelProcess.Pid)
	z.collectingProcess.Store(zTunnelProcess)
	// start the admin/metrics pollers even if the uprobe attaching failed,
	// the admin dump works without any dependency on the ztunnel binary symbols
	z.startNetnsPollers()
	// a missing track_outbound symbol(stripped or symbol-renamed ztunnel binary)
	// must NOT be fatal: returning the error here aborts the whole access-log
	// module on this node and defeats the symbol-independent admin-dump fallback
	// started above. Log it and keep the event reader / pollers running.
	if err := z.collectZTunnelProcess(zTunnelProcess); err != nil {
		ztunnelLog.Warnf("failed to attach the ztunnel uprobe, the admin-dump fallback still runs: %v", err)
	}
	return nil
}

func (z *ZTunnelCollector) collectZTunnelProcess(p *process.Process) error {
	pidExeFile := host.GetHostProcInHost(fmt.Sprintf("%d/exe", p.Pid))
	elfFile, err := elf.NewFile(pidExeFile)
	if err != nil {
		return fmt.Errorf("read executable file error: %v", err)
	}
	// the Rust compiler may emit multiple monomorphized/cloned copies of a symbol, so attach
	// to all of them to avoid missing the actually-called copy
	uprobeFile := z.alc.BPF.OpenUProbeExeFile(pidExeFile)
	// if the executable could not be opened the AddLink calls below are silent no-ops; fail here
	// instead of counting "symbols found" as attached and arming the BPF pid gate with zero
	// uprobes actually installed(which would log success while capturing nothing)
	if !uprobeFile.Found() {
		return fmt.Errorf("cannot open the ztunnel executable %s for uprobe attaching", pidExeFile)
	}
	attached := 0
	// attach the enter uprobe to every ELF symbol whose name starts with prefix, counting the
	// attaches so the caller can tell whether a source was found at all
	attach := func(prefix, label string, prog *ebpf.Program) {
		// The prefix also matches same-name NON-function symbols the Rust `tracing` macros emit -
		// the "__CALLSITE"/"__CALLSITE4META" static data symbols(e.g.
		// ...ConnectionResult3new10__CALLSITE17h..E) and inner "{{closure}}" bodies. Attaching a
		// uprobe to a DATA symbol fails and aborts the whole access_log module, and a closure
		// reads the wrong registers. A real function copy has the Rust legacy-mangled hash segment
		// "17h<hash>E" IMMEDIATELY after the demangled path, so require "17h" right after the
		// prefix: that keeps every monomorphized/cloned FUNCTION copy(onlyOneResult=false, so a
		// never-called copy is harmless) while excluding the __CALLSITE/closure symbols.
		for _, symbol := range elfFile.FilterSymbol(func(name string) bool {
			return strings.HasPrefix(name, prefix+"17h")
		}, false) {
			ztunnelLog.Infof("attaching ztunnel %s symbol: %s", label, symbol.Name)
			uprobeFile.AddLink(symbol.Name, prog, nil)
			attached++
		}
	}

	// source 1: track_outbound(src, ClusterIP, real pod) - the src+ClusterIP keyed mapping.
	// source 2: ConnectionResult::new(src, real pod) - the higher-coverage, src-keyed mapping
	// that also captures the outbound legs track_outbound misses. Attached best-effort: on a
	// ztunnel version where either symbol is absent/renamed the other still provides coverage.
	// AddLink accumulates any attach failure into the shared BPF linker, but the happy path never
	// inspects it - and `attached` only counts SYMBOLS MATCHED, not uprobes actually installed. So
	// a symbol that matched yet whose uprobe failed to install(the kernel/uprobe layer rejected it
	// for this particular ztunnel build) is otherwise completely invisible: the collector then
	// receives ZERO mapping events with no clue why. Snapshot the linker error before/after so a
	// NEW failure attributable to these two attaches is surfaced instead of silently swallowed.
	attachErrBefore := fmt.Sprintf("%v", z.alc.BPF.HasError())
	attach(ZTunnelTrackBoundSymbolPrefix, "track outbound", z.alc.BPF.ConnectionManagerTrackOutbound)
	attach(ZTunnelConnectionResultNewSymbolPrefix, "ConnectionResult::new", z.alc.BPF.ConnectionResultNew)

	if attached == 0 {
		return fmt.Errorf("failed to find any ztunnel outbound mapping symbol" +
			"(track_outbound / ConnectionResult::new) in ztunnel process")
	}
	if err := z.alc.BPF.HasError(); err != nil && fmt.Sprintf("%v", err) != attachErrBefore {
		ztunnelLog.Warnf("ztunnel uprobe attach reported error(s): one or more uprobes may NOT be "+
			"installed, which leaves the uprobe mapping event stream empty and makes the correlation "+
			"fall back to the admin-dump/access-log sources only: %v", err)
	}

	// setting the ztunnel pid in the BPF, this arms the `tgid_is_ztunnel` gate so the
	// ztunnel's own connect() to the local workload(the inbound leg) is captured
	if err = z.alc.BPF.ZtunnelProcessPid.Set(p.Pid); err != nil {
		return fmt.Errorf("failed to set ztunnel process pid in the BPF: %v", err)
	}
	// read back the value to confirm the BPF gate is actually armed with the expected pid,
	// this makes the "no ztunnel connect captured" problem diagnosable directly from the log
	var armedPid uint32
	if err = z.alc.BPF.ZtunnelProcessPid.Get(&armedPid); err != nil {
		ztunnelLog.Warnf("cannot read back the ztunnel process pid from the BPF: %v", err)
	} else {
		ztunnelLog.Infof("armed the ztunnel BPF pid gate, expected pid: %d, read back: %d", p.Pid, armedPid)
	}
	return nil
}

// ztunnelMappingSource identifies WHICH of the redundant sources produced a cached mapping,
// so the periodic stats can report the resolution share of each(uprobe vs access-log fallback).
type ztunnelMappingSource string

const (
	sourceTrackOutbound    ztunnelMappingSource = "track_outbound"
	sourceConnectionResult ztunnelMappingSource = "connection_result"
	sourceAccessLog        ztunnelMappingSource = "access_log"
	sourceAdminDump        ztunnelMappingSource = "admin_dump"
	sourceInbound          ztunnelMappingSource = "inbound"
)

type ZTunnelLoadBalanceAddress struct {
	IP     string
	Port   uint16
	From   v3.ZTunnelAttachmentEnvironmentDetectBy
	Source ztunnelMappingSource
}

func (z *ZTunnelLoadBalanceAddress) String() string {
	return fmt.Sprintf("%s:%d(%s)", z.IP, z.Port, z.From)
}
