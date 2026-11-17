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

package common //nolint:revive // package name is acceptable in this context

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/kubernetes"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/ip"
	"github.com/apache/skywalking-rover/pkg/tools/path"
	"github.com/apache/skywalking-rover/pkg/tools/shardmap"

	"github.com/cilium/ebpf"

	"k8s.io/apimachinery/pkg/util/cache"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

const (
	// clean the active connection in BPF interval
	cleanActiveConnectionInterval = time.Second * 20

	// in case the reading the data from BPF queue is disordered, so add a delay time to delete the
	// connection information. It is also the upper bound the resolution-defer grace must stay under
	// (see resolutionGraceFor): a connection has to survive in the manager for the whole time its
	// access log may be held waiting for the ztunnel lb mapping. Raised to 25s so the resolution
	// grace can reach the 20s the ztunnel identity(DST_*/PEER_*) addition waits for while the
	// connection still survives a margin beyond the grace before being deleted.
	connectionDeleteDelayTime = time.Second * 25

	// the connection check exist time
	connectionCheckExistTime = time.Second * 30

	// the interval of reporting the un-resolved remote address summary
	unresolvedRemoteReportInterval = time.Second * 30
	// the max count of distinct un-resolved remote addresses to track per interval
	unresolvedRemoteMaxTrack = 100
	// the max count of top un-resolved remote addresses in the report log
	unresolvedRemoteTopCount = 10

	// resolutionDeferMargin is added to the flush period to bound how long a connection whose remote
	// is still being resolved is held before its access log is sent with the raw service IP. It only
	// absorbs the short async delivery jitter of the ztunnel ConnectionResult mapping event(which is
	// promptly delivered now that the mapping perf queue is drained by several reader goroutines,
	// ztunnelMappingQueueParallels, and applied by the pull-per-flush-cycle plus the push in
	// RetroResolveBySrc). It is deliberately SHORT: a LONGER hold was measured to REGRESS the
	// strict no-degenerate check(grace 30s and 50s both produced MORE failures than 15s), because a
	// connection that still does not resolve emits its raw-IP log in a LATER minute-bucket, which
	// then lingers in the topology query window longer. So the residual is minimized at the source
	// (parallel readers + push), not by holding longer.
	//
	// Raised from 10s to 15s(grace = defaultFlushPeriod 5s + 15s = 20s) so the ztunnel identity
	// addition(DST_*/PEER_*) can wait the full 20s for its source(config_dump refresh / access-log
	// tailer) before the connection flushes. This deliberately trades a small no-degenerate regression
	// for the identity wait; the identity reuses this same resolution-defer rather than adding a
	// separate deadline.
	resolutionDeferMargin = time.Second * 15
	// defaultFlushPeriod is used to derive the resolution grace period when the configured
	// flush period cannot be parsed
	defaultFlushPeriod = time.Second * 5
)

type ConnectEventWithSocket struct {
	*events.SocketConnectEvent
	SocketPair *ip.SocketPair
}

type CloseEventWithNotify struct {
	*events.SocketCloseEvent
}

type ConnectionProcessFinishCallback func()

type ConnectionProcessor interface {
}

type FlusherListener interface {
	// ReadyToFlushConnection notify which connection ready to flush
	ReadyToFlushConnection(connection *ConnectionInfo, getConnectionFromEvent events.Event)
}

// ResolutionAwareFlusher is an optional interface a FlusherListener may implement to
// report that a connection's remote address is still being resolved(e.g. the ztunnel
// lb mapping has not been correlated yet). When any listener reports pending, the runner
// defers the connection's logs for a bounded grace period instead of emitting them with
// the raw service IP, which would leave a degenerate "-|service|-" entity in the backend.
type ResolutionAwareFlusher interface {
	IsResolutionPending(connection *ConnectionInfo) bool
	// FinalizeConnection is called EXACTLY ONCE per connection when it reaches its final state(just
	// before deletion), so a flusher can record a resolution outcome from the connection's final,
	// settled attachment instead of guessing at attach time(where a later-arriving identity would be
	// mis-counted, needing a fragile decrement). It must be idempotent-safe: called once per connection.
	FinalizeConnection(connection *ConnectionInfo)
	// UnresolvedReason returns a short category for WHY a connection reached the end of its
	// lifetime without its real destination being attached, so the periodic summary can attribute
	// the raw-IP socket pairs to a likely cause(which resolution source / environment did not
	// provide the mapping). An empty string means this flusher has no opinion for the connection.
	UnresolvedReason(connection *ConnectionInfo) string
}

type ProcessListener interface {
	OnNewProcessMonitoring(pid int32)
	OnProcessRemoved(pid int32)
}

type ConnectionManager struct {
	moduleMgr   *module.Manager
	processOP   process.Operator
	connections *shardmap.Map[ConnectionKey, *ConnectionInfo]
	// localIPWithPid cache all local monitoring process bind IP address
	// for checking the remote address is local or not
	localIPWithPid map[string]int32
	// monitoringProcesses management all monitoring processes
	monitoringProcesses   map[int32][]api.ProcessInterface
	monitoringProcessLock sync.RWMutex
	// monitoring process map in BPF
	processMonitorMap *ebpf.Map
	// processMonitorHint is set for a process before it is put into processMonitorMap (bpf.MonitorProcessHint)
	processMonitorHint  *ebpf.Map
	activeConnectionMap *ebpf.Map
	// h2cStreamMap follows the frames of a cleartext HTTP/2 active connection (drop_h2c_unused_frame,
	// skip_h2c_data_payload): its entry goes with the active connection
	h2cStreamMap *ebpf.Map
	// the h2c and HTTP/1 switches as the BPF side has them (a switch it could not be given is off), see
	// setupH2CFrames; only when one is on does h2cStreamMap have entries
	dropH2CUnusedFrame, skipH2CDataPayload, skipHTTP1BodyPayload bool
	// summarizeH2CPayload: summarize_h2c_payload as the BPF side has it
	summarizeH2CPayload bool
	// processNotMonitorMap and cgroupAllowlistMap are the two ways the fork/exec tracepoints decide
	// what to skip; which one is in force is settled once at startup, see processExecuteMonitorReady
	processNotMonitorMap *ebpf.Map
	cgroupAllowlistMap   *ebpf.Map
	// processExecuteMonitorReady records whether the tracepoints were attached at all
	processExecuteMonitorReady bool
	// cgroupSeeder resolves a container to its cgroup id; nil when the host cannot resolve them
	cgroupSeeder process.CgroupOperator
	// allowedCgroups counts which monitored pids live in each allowed cgroup, so a cgroup stays
	// allowed until the last of them is gone
	allowedCgroups map[uint64]map[int32]bool
	// processVerdicts remembers what was concluded about a process, so its access logs can outlive
	// it just long enough to be flushed
	processVerdicts *cache.Expiring

	monitorFilter MonitorFilter

	processors       []ConnectionProcessor
	processListeners []ProcessListener

	flushListeners []FlusherListener

	connectTracker *ip.ConnTrack

	connectionProtocolBreakMap *cache.Expiring

	// statistics of the remote address resolving, for the periodic summary report
	remoteAddressBuildCount      atomic.Int64
	unresolvedRemoteCount        atomic.Int64
	ztunnelResolvedRemoteCount   atomic.Int64
	conntrackResolvedRemoteCount atomic.Int64
	unresolvedRemoteLock         sync.Mutex
	unresolvedRemotes            map[string]int64
	unresolvedByReason           map[string]int64
	// resolutionLatency buckets the open->resolution delay of ztunnel-resolved connections, to
	// LOCATE the late-mapping-event problem: a mass in the >=15s(over-grace) bucket proves the
	// mapping events are being delivered too slowly(perf-queue reader backlog), which is exactly the
	// window in which a connection would have already flushed with the raw IP -> degenerate node.
	resolutionLatencyUnder1s  atomic.Int64
	resolutionLatency1to5s    atomic.Int64
	resolutionLatency5to15s   atomic.Int64
	resolutionLatencyOver15s  atomic.Int64
	resolutionLatencyMaxMilli atomic.Int64

	// resolutionGracePeriod is how long a connection whose remote is still being resolved
	// is deferred before its logs are flushed anyway; derived from the flush period + margin
	resolutionGracePeriod time.Duration
}

func (c *ConnectionManager) RegisterProcessor(processor ConnectionProcessor) {
	c.processors = append(c.processors, processor)
}

func (c *ConnectionManager) AddProcessListener(listener ProcessListener) {
	c.processListeners = append(c.processListeners, listener)
}

func (c *ConnectionManager) RegisterNewFlushListener(listener FlusherListener) {
	c.flushListeners = append(c.flushListeners, listener)
}

// ConnectionKey identifies a connection by its connection ID and random ID. It is the key of the
// connection maps looked up for every event, so it is a plain value that needs no allocation.
type ConnectionKey struct {
	ConnectionID uint64
	RandomID     uint64
}

func NewConnectionKey(conID, ranID uint64) ConnectionKey {
	return ConnectionKey{ConnectionID: conID, RandomID: ranID}
}

// Hash mixes both IDs, the connection ID alone is the pid and fd so it spreads badly over the shards
func (k ConnectionKey) Hash() uint32 {
	h := k.ConnectionID*0x9E3779B97F4A7C15 ^ k.RandomID*0xC2B2AE3D27D4EB4F
	return uint32(h ^ h>>32)
}

// String is the "connectionID_randomID" form the connection used to be keyed (and logged) by
func (k ConnectionKey) String() string {
	return fmt.Sprintf("%d_%d", k.ConnectionID, k.RandomID)
}

type ConnectionInfo struct {
	ConnectionID       uint64
	RandomID           uint64
	RPCConnection      *v3.AccessLogConnection
	MarkDeletable      bool
	PID                uint32
	Socket             *ip.SocketPair
	LastCheckExistTime time.Time
	DeleteAfter        *time.Time
	ProtocolBreak      bool
	// CreatedAt is when the connection was first seen by the manager; used to measure how long a
	// ClusterIP connection took to be resolved(open -> ztunnel mapping applied), which locates the
	// late-mapping-event problem: a large open-to-resolution latency means the mapping event was
	// delivered slowly(perf-queue reader backlog), not that it was missing.
	CreatedAt time.Time
	// ResolutionDeadline, once set, is the time until which this connection's access logs
	// are deferred waiting for a resolver(the ztunnel lb mapping) to attach the real pod
	// IP. It is set on the first deferred flush and bounds the wait PER CONNECTION: after
	// it passes the logs are emitted as-is(raw service IP) even if still unresolved, so a
	// genuinely un-resolvable remote is not delayed forever and a long-lived connection is
	// not re-deferred on every log.
	ResolutionDeadline *time.Time
	// rpcLock serializes the copy-on-write replacements of RPCConnection: the runner rebuilds it with a
	// new TLS mode or protocol while a ztunnel mapping may replace its attachment from another goroutine,
	// and neither may lose the other's change
	rpcLock sync.Mutex
}

// ReplaceAttachment sets the attachment of the connection (on a copy, see updateRPCConnection)
func (c *ConnectionInfo) ReplaceAttachment(attachment *v3.ConnectionAttachment) {
	c.updateRPCConnection(func(conn *v3.AccessLogConnection) bool {
		conn.Attachment = attachment
		return true
	})
}

// updateRPCConnection replaces RPCConnection with a copy changed by update, unless update returns false.
// The message may be shared with a batch the sender is marshaling, so it is never modified in place.
func (c *ConnectionInfo) updateRPCConnection(update func(conn *v3.AccessLogConnection) bool) {
	c.rpcLock.Lock()
	defer c.rpcLock.Unlock()
	original := c.RPCConnection
	updated := &v3.AccessLogConnection{
		Local:      original.Local,
		Remote:     original.Remote,
		Role:       original.Role,
		TlsMode:    original.TlsMode,
		Protocol:   original.Protocol,
		Attachment: original.Attachment,
	}
	if update(updated) {
		c.RPCConnection = updated
	}
}

func NewConnectionManager(config *Config, moduleMgr *module.Manager, bpfLoader *bpf.Loader, filter MonitorFilter) *ConnectionManager {
	track, err := ip.NewConnTrack()
	if err != nil {
		log.Warnf("cannot create the connection tracker, %v", err)
	}
	// derive the resolution grace period from the flush period(+margin): the ztunnel lb
	// mapping arrives asynchronously and normally lands within one flush period, so
	// waiting a flush period plus a small margin lets short connections resolve to the
	// real pod IP instead of being reported with the raw service IP
	flushPeriod := defaultFlushPeriod
	if config != nil {
		if parsed, perr := time.ParseDuration(config.Flush.Period); perr == nil && parsed > 0 {
			flushPeriod = parsed
		}
	}
	mgr := &ConnectionManager{
		moduleMgr:                  moduleMgr,
		processOP:                  moduleMgr.FindModule(process.ModuleName).(process.Operator),
		connections:                shardmap.New[ConnectionKey, *ConnectionInfo](),
		localIPWithPid:             make(map[string]int32),
		monitoringProcesses:        make(map[int32][]api.ProcessInterface),
		processMonitorMap:          bpfLoader.ProcessMonitorControl,
		processMonitorHint:         bpfLoader.ProcessMonitorHint,
		activeConnectionMap:        bpfLoader.ActiveConnectionMap,
		h2cStreamMap:               bpfLoader.H2cStreamMap,
		processNotMonitorMap:       bpfLoader.ProcessNotMonitor,
		cgroupAllowlistMap:         bpfLoader.CgroupMonitorAllowlist,
		processVerdicts:            cache.NewExpiring(),
		allowedCgroups:             make(map[uint64]map[int32]bool),
		monitorFilter:              filter,
		flushListeners:             make([]FlusherListener, 0),
		connectTracker:             track,
		connectionProtocolBreakMap: cache.NewExpiring(),
		unresolvedRemotes:          make(map[string]int64),
		unresolvedByReason:         make(map[string]int64),
		resolutionGracePeriod:      resolutionGraceFor(flushPeriod),
	}
	mgr.setupProcessExecuteMonitor(bpfLoader)
	mgr.dropH2CUnusedFrame, mgr.skipH2CDataPayload = setupH2CFrames(config, bpfLoader)
	mgr.summarizeH2CPayload = setupH2CSummary(config, bpfLoader, mgr.skipH2CDataPayload)
	mgr.skipHTTP1BodyPayload = setupHTTP1BodySkip(config, bpfLoader)
	setupEventReader(config, bpfLoader)
	return mgr
}

// setupProcessExecuteMonitor settles, once, how the kernel should filter the processes it reports,
// and whether reporting them is worth doing at all.
//
// The cgroup allowlist is the preferred filter because it rejects a host process without emitting
// anything, but it needs the process discovery to resolve cgroup ids, which in turn needs a cgroup
// v2 tree. Where that is missing the per-process rejection list still keeps the cost to one report
// per process, which is what makes these tracepoints affordable in the first place.
func (c *ConnectionManager) setupProcessExecuteMonitor(bpfLoader *bpf.Loader) {
	// Nothing is reported unless some active finder can actually act on it. This is not a
	// micro-optimisation: a finder that only ever monitors long-lived processes(the VM finder takes
	// a process only if it holds a listening port, which one living for milliseconds never does)
	// would reject every reported process *after* paying for a /proc read - all cost, no coverage.
	// That cost is precisely why these tracepoints were removed from this agent once before.
	if !c.processOP.ExecutingProcessesWanted() {
		log.Infof("not monitoring process execution: no active process finder can use it, so " +
			"short-lived processes stay discoverable only by the periodic scan")
		return
	}

	seeder, canSeedCgroups := c.processOP.(process.CgroupOperator)
	if canSeedCgroups {
		canSeedCgroups = seeder.CgroupResolvable()
	}
	c.cgroupSeeder = seeder

	enabled := uint32(0)
	if canSeedCgroups {
		enabled = 1
	}
	if err := bpfLoader.CgroupFilterEnabled.Set(enabled); err != nil {
		log.Warnf("cannot select the process execution filter, not monitoring process execution: %v", err)
		return
	}
	c.processExecuteMonitorReady = true
	if canSeedCgroups {
		log.Infof("monitoring process execution, filtering by the cgroups of the monitored containers")
	} else {
		log.Infof("monitoring process execution, filtering per process: no cgroup v2 tree is available, " +
			"so every process is reported once before it can be skipped")
	}
}

// resolutionGraceFor bounds the resolution-defer grace so it stays below connectionDeleteDelayTime
// (with one flush period of headroom). A connection is removed connectionDeleteDelayTime after it
// closes, and a deferred log can only be emitted at a flush cycle at or after its resolution
// deadline; a grace reaching past the delete time would let the connection be deleted first and its
// re-queued logs dropped. When even one flush period does not fit(an unusually large configured
// flush period), the grace is zero and ShouldDeferForResolution does not defer at all - the log is
// then emitted immediately with the raw IP, which is unresolved but never dropped.
func resolutionGraceFor(flushPeriod time.Duration) time.Duration {
	grace := flushPeriod + resolutionDeferMargin
	if maxGrace := connectionDeleteDelayTime - flushPeriod; grace > maxGrace {
		grace = maxGrace
	}
	if grace < 0 {
		grace = 0
	}
	return grace
}

// ShouldDeferForResolution reports whether the connection's access logs should be held
// back for one more flush cycle because a resolver(the ztunnel lb mapping) has not yet
// attached the real destination. It is bounded per connection: the first time a
// connection is found pending, a deadline(now + grace) is recorded, and once that
// deadline passes the logs are flushed as-is even if still unresolved. This closes the
// short-connection race where the asynchronous ztunnel mapping event is processed just
// after the connection has already been flushed with the raw service IP.
func (c *ConnectionManager) ShouldDeferForResolution(conn *ConnectionInfo) bool {
	// grace <= 0 means deferral is disabled(the flush period is too large to fit a grace below
	// connectionDeleteDelayTime, see resolutionGraceFor) - never hold a log back in that case
	if conn == nil || c.resolutionGracePeriod <= 0 {
		return false
	}
	pending := false
	for _, l := range c.flushListeners {
		if r, ok := l.(ResolutionAwareFlusher); ok && r.IsResolutionPending(conn) {
			pending = true
			break
		}
	}
	if !pending {
		// resolved(or no resolver is waiting) - do not defer
		return false
	}
	now := time.Now()
	if conn.ResolutionDeadline == nil {
		deadline := now.Add(c.resolutionGracePeriod)
		conn.ResolutionDeadline = &deadline
		return true
	}
	return now.Before(*conn.ResolutionDeadline)
}

// RecordResolutionLatency records how long a connection took from open to being resolved by the
// ztunnel correlation, into coarse buckets, so the periodic summary can show the open->resolution
// delay distribution. The >=15s bucket is the diagnostic smoking gun for the late-mapping-event
// problem(events delivered after the resolution-defer grace would have already flushed the raw IP).
func (c *ConnectionManager) RecordResolutionLatency(conn *ConnectionInfo) {
	if conn == nil || conn.CreatedAt.IsZero() {
		return
	}
	d := time.Since(conn.CreatedAt)
	switch {
	case d < time.Second:
		c.resolutionLatencyUnder1s.Add(1)
	case d < 5*time.Second:
		c.resolutionLatency1to5s.Add(1)
	case d < 15*time.Second:
		c.resolutionLatency5to15s.Add(1)
	default:
		c.resolutionLatencyOver15s.Add(1)
	}
	if ms := d.Milliseconds(); ms > c.resolutionLatencyMaxMilli.Load() {
		c.resolutionLatencyMaxMilli.Store(ms)
	}
}

func (c *ConnectionManager) Start(ctx context.Context, accessLogContext *AccessLogContext) {
	c.processOP.AddListener(c)
	c.startUnresolvedRemoteReporter(ctx)

	// starting to clean up the un-active connection in BPF
	go func() {
		ticker := time.NewTicker(cleanActiveConnectionInterval)
		for {
			select {
			case <-ticker.C:
				activeConnections := c.activeConnectionMap.Iterate()
				var conID uint64
				var activateConn ActiveConnection
				for activeConnections.Next(&conID, &activateConn) {
					// if the connection is existed, then check the next one
					pid, fd := events.ParseConnectionID(conID)
					if c.checkProcessFDExist(pid, fd) {
						continue
					}

					// if the connection is not existed, then delete it: unless the fd was reused meanwhile, by a
					// connection of another random id whose entry it now is
					var current ActiveConnection
					if err := c.activeConnectionMap.Lookup(conID, &current); err != nil || current.RandomID != activateConn.RandomID {
						continue
					}
					if err := c.activeConnectionMap.Delete(conID); err != nil {
						if !errors.Is(err, ebpf.ErrKeyNotExist) {
							log.Warnf("failed to delete the active connection, pid: %d, fd: %d, connection ID: %d, random ID: %d, error: %v",
								pid, fd, conID, activateConn.RandomID, err)
						}
						continue
					}
					log.Debugf("deleted the active connection as not exist in file system, pid: %d, fd: %d, connection ID: %d, random ID: %d",
						pid, fd, conID, activateConn.RandomID)
					// the BPF side never sees the close of this fd, so it never removes the entry itself
					if c.dropH2CUnusedFrame || c.skipH2CDataPayload {
						c.deleteH2CState(conID, activateConn.RandomID)
					}

					// building and send the close event
					wapperedEvent := c.OnConnectionClose(&events.SocketCloseEvent{
						ConnectionID: conID,
						RandomID:     activateConn.RandomID,
						StartTime:    0,
						EndTime:      0,
						PID:          activateConn.PID,
						SocketFD:     activateConn.SocketFD,
						Success:      0,
					})
					accessLogContext.Queue.AppendKernelLog(NewKernelLogEvent(LogTypeClose, wapperedEvent))
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *ConnectionManager) checkProcessFDExist(pid, fd uint32) bool {
	return path.Exists(host.GetHostProcInHost(fmt.Sprintf("%d/fd/%d", pid, fd)))
}

func (c *ConnectionManager) Stop() {
	c.processOP.DeleteListener(c)
}

// ProcessVerdict is what user space concluded about a process the kernel reported.
type ProcessVerdict int

const (
	// ProcessVerdictUnknown means no conclusion has been reached yet, either because the report is
	// still being handled or because the process vanished before it could be identified.
	ProcessVerdictUnknown ProcessVerdict = iota
	// ProcessVerdictMonitored means the process is currently monitored.
	ProcessVerdictMonitored
	// ProcessVerdictApproved means the process passed every filter and has since exited. Its logs
	// are still worth sending: the process being short-lived is the reason it is interesting.
	ProcessVerdictApproved
	// ProcessVerdictRejected means the process was positively identified as one we must not report.
	ProcessVerdictRejected
)

// processVerdictKeepTime is how long a verdict outlives the process. It only has to cover the gap
// between a process exiting and its last buffered access logs being flushed.
const processVerdictKeepTime = time.Minute

// ProcessExecuteMonitorReady reports whether user space can judge the processes the kernel would
// report, and therefore whether the fork/exec tracepoints are worth attaching at all.
func (c *ConnectionManager) ProcessExecuteMonitorReady() bool {
	return c.processExecuteMonitorReady
}

// OnNewProcessExecuting handles a process the kernel has just started and optimistically marked as
// monitored. Everything the kernel could capture is passed in, because the process may already be
// gone - that is precisely the case this exists for.
func (c *ConnectionManager) OnNewProcessExecuting(pid int32, cgroupID uint64, comm string) {
	// The cgroup id here is the kernel's own(bpf_get_current_cgroup_id), while the allowlist that
	// let this event through was seeded from a cgroup id user space read as a directory inode. The
	// two must be the same number for any of this to work, so log the kernel's side of it: paired
	// with the "cgroup mapping: id=... path=..." lines from the walk, it shows whether they agree.
	log.Debugf("process execution reported by the kernel: pid=%d cgroup=%d comm=%s", pid, cgroupID, comm)

	if c.processOP.ShouldMonitorExecuting(&api.ProcessExecuteContext{Pid: pid, CgroupID: cgroupID, Comm: comm}) {
		// the finder registered it; AddNewProcess arrives through the listener and records the
		// verdict, so there is nothing to undo here
		return
	}

	// Stop tracing it. Whether this counts as a positive rejection decides if its already buffered
	// access logs may be sent, so be careful about the difference: a process we could still see is
	// one we truly judged, while a process that vanished before we looked was never judged at all
	// and its logs must not be trusted.
	c.updateMonitorStatusForProcess(pid, false)
	if !path.Exists(host.GetHostProcInHost(fmt.Sprintf("%d", pid))) {
		log.Debugf("the process %d exited before it could be identified, its access logs will be dropped", pid)
		return
	}
	c.recordProcessVerdict(pid, ProcessVerdictRejected)
	// Remember the rejection in the kernel so the process stops being reported on every exec/fork.
	// Only meaningful in the fallback mode; with the cgroup allowlist the process never gets here.
	c.rejectProcessInBPF(pid)
}

// allowCgroupsOfProcesses lets the kernel report the processes that start inside these processes'
// cgroups, which is how a short-lived sibling - a `kubectl exec`, a CronJob - gets monitored from
// its very first syscall instead of waiting for the next discovery round to notice it.
//
// The pids sharing a cgroup are counted, because a container's cgroup must stay allowed until the
// last of its processes is gone; dropping it when any one process exits would blind the rest.
func (c *ConnectionManager) allowCgroupsOfProcesses(pid int32, processes []api.ProcessInterface) {
	if c.cgroupAllowlistMap == nil || c.cgroupSeeder == nil {
		return
	}
	for _, cgroupID := range c.cgroupIDsOf(processes) {
		pids := c.allowedCgroups[cgroupID]
		if pids == nil {
			pids = make(map[int32]bool)
			c.allowedCgroups[cgroupID] = pids
			if err := c.cgroupAllowlistMap.Update(cgroupID, uint32(1), ebpf.UpdateAny); err != nil {
				log.Warnf("failed to allow the cgroup %d, short-lived processes in it will only be "+
					"found by the periodic scan: %v", cgroupID, err)
				delete(c.allowedCgroups, cgroupID)
				continue
			}
			log.Debugf("allowing process execution reports from cgroup %d", cgroupID)
		}
		pids[pid] = true
	}
}

// disallowCgroupsOfProcesses drops a pid from its cgroups and stops the kernel reporting a cgroup
// once nothing monitored is left in it.
func (c *ConnectionManager) disallowCgroupsOfProcesses(pid int32, processes []api.ProcessInterface) {
	if c.cgroupAllowlistMap == nil || c.cgroupSeeder == nil {
		return
	}
	for _, cgroupID := range c.cgroupIDsOf(processes) {
		pids := c.allowedCgroups[cgroupID]
		if pids == nil {
			continue
		}
		delete(pids, pid)
		if len(pids) > 0 {
			continue
		}
		delete(c.allowedCgroups, cgroupID)
		if err := c.cgroupAllowlistMap.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Warnf("failed to disallow the cgroup %d: %v", cgroupID, err)
		}
	}
}

// cgroupIDsOf resolves the cgroups the given processes live in. Only Kubernetes processes have a
// container to resolve through, and a container whose cgroup is not mapped yet simply yields
// nothing, leaving the periodic scan to cover it.
func (c *ConnectionManager) cgroupIDsOf(processes []api.ProcessInterface) []uint64 {
	ids := make([]uint64, 0, 1)
	for _, p := range processes {
		if p.DetectType() != api.Kubernetes {
			continue
		}
		k8sProcess, ok := p.DetectProcess().(*kubernetes.Process)
		if !ok {
			continue
		}
		cgroupID, exist := c.cgroupSeeder.CgroupIDByContainer(k8sProcess.PodContainer().CGroupID())
		if !exist {
			continue
		}
		ids = append(ids, cgroupID)
	}
	return ids
}

// rejectProcessInBPF records a process as not worth reporting, so the tracepoints skip it from now
// on. Without it a busy unmonitored process would be re-reported and re-checked forever.
func (c *ConnectionManager) rejectProcessInBPF(pid int32) {
	if c.processNotMonitorMap == nil {
		return
	}
	if err := c.processNotMonitorMap.Update(uint32(pid), uint32(1), ebpf.UpdateAny); err != nil {
		log.Warnf("failed to record the process %d as not monitored: %v", pid, err)
	}
}

func (c *ConnectionManager) recordProcessVerdict(pid int32, verdict ProcessVerdict) {
	c.processVerdicts.Set(pid, verdict, processVerdictKeepTime)
}

// ProcessVerdictOf reports what was concluded about a process, so a caller can tell a process that
// is genuinely not ours from one we simply have not judged yet.
func (c *ConnectionManager) ProcessVerdictOf(pid uint32) ProcessVerdict {
	if c.ProcessIsMonitor(pid) {
		return ProcessVerdictMonitored
	}
	if v, exist := c.processVerdicts.Get(int32(pid)); exist {
		return v.(ProcessVerdict)
	}
	return ProcessVerdictUnknown
}

func (c *ConnectionManager) GetExcludeNamespaces() []string {
	return c.monitorFilter.ExcludeNamespaces()
}

func (c *ConnectionManager) Find(event events.Event) *ConnectionInfo {
	connectionKey := NewConnectionKey(event.GetConnectionID(), event.GetRandomID())
	connection, exist := c.connections.Get(connectionKey)
	if exist {
		c.connectionPostHandle(connection, event)
		return connection
	}
	// is current is connected event, then getting the socket pair
	if e, socket := getSocketPairFromConnectEvent(event); e != nil && socket != nil {
		var localAddress, remoteAddress *v3.ConnectionAddress
		localPID, _ := events.ParseConnectionID(event.GetConnectionID())
		localAddress = c.buildLocalAddress(localPID, socket.SrcPort, socket)
		remoteAddress = c.buildRemoteAddress(e, socket)
		if localAddress == nil || remoteAddress == nil {
			return nil
		}
		connection := c.buildConnection(e, socket, localAddress, remoteAddress, connectionKey)
		c.connections.Set(connectionKey, connection)
		if log.Enable(logrus.DebugLevel) {
			log.Debugf("building flushing connection, connection ID: %d, randomID: %d, role: %s, local: %s:%d, remote: %s:%d, "+
				"local address: %s, remote address: %s, protocol: %s",
				e.GetConnectionID(), e.GetRandomID(), socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort,
				localAddress.String(), remoteAddress.String(), connection.RPCConnection.Protocol.String())
		}
		c.connectionPostHandle(connection, event)
		return connection
	}
	return nil
}

func (c *ConnectionManager) buildRemoteAddress(e *events.SocketConnectEvent, socket *ip.SocketPair) *v3.ConnectionAddress {
	// if the remote address is local, then no needs to build the address(access log no need to send by communicate with self)
	if tools.IsLocalHostAddress(socket.DestIP) {
		return nil
	}

	// if the remote connection is need to use conntrack, then update the real peer address
	if socket.NeedConnTrack {
		if err := c.connectTracker.UpdateRealPeerAddress(socket); err != nil {
			log.Debugf("cannot update the real peer address, %v", err)
		}
	}

	c.remoteAddressBuildCount.Add(1)
	// found local address with pid
	if pid, exist := c.localIPWithPid[socket.DestIP]; exist && pid != 0 {
		return c.buildLocalAddress(uint32(pid), socket.DestPort, socket)
	}

	log.Debugf("building the remote address to unknown, connection: %d-%d, role: %s, local: %s:%d, remote: %s:%d",
		e.GetConnectionID(), e.GetRandomID(), socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort)
	return c.buildAddressFromRemote(socket.DestIP, socket.DestPort)
}

// recordConnectionResolveResult records the final remote address resolve result of the
// connection, it MUST be called when the connection is being deleted from the manager,
// at that point all resolvers are finalized: the conntrack rewriting happens on the
// address building, and the ztunnel correlation could attach the real destination on
// any later flush, so judging any earlier would mis-count the resolved connections
func (c *ConnectionManager) recordConnectionResolveResult(connection *ConnectionInfo) {
	if connection == nil || connection.RPCConnection == nil {
		return
	}
	// notify resolution-aware flushers of the final, settled state ONCE(before any early return
	// below), so they record the identity outcome from the finalized attachment
	for _, l := range c.flushListeners {
		if r, ok := l.(ResolutionAwareFlusher); ok {
			r.FinalizeConnection(connection)
		}
	}
	remote := connection.RPCConnection.GetRemote()
	if remote == nil || remote.GetIp() == nil {
		// the remote address is resolved to a local monitored process, not a raw IP
		return
	}
	if connection.RPCConnection.GetAttachment() != nil {
		// the ztunnel correlation attached the real destination
		c.ztunnelResolvedRemoteCount.Add(1)
		return
	}
	if connection.Socket != nil && connection.Socket.ConnTrackResolved {
		// the conntrack query already rewrote the address to the real peer(e.g. pod IP),
		// the address is sent as a raw IP but the backend could resolve it
		c.conntrackResolvedRemoteCount.Add(1)
		return
	}
	// ask the resolution-aware flusher(s) WHY this connection ended up unresolved, so the summary
	// can group the raw-IP socket pairs by the environment/source that failed to provide a mapping
	reason := "unresolved"
	for _, l := range c.flushListeners {
		if r, ok := l.(ResolutionAwareFlusher); ok {
			if rs := r.UnresolvedReason(connection); rs != "" {
				reason = rs
				break
			}
		}
	}
	src := "unknown"
	if connection.Socket != nil {
		src = fmt.Sprintf("%s:%d", connection.Socket.SrcIP, connection.Socket.SrcPort)
	}
	c.recordUnresolvedRemote(reason, fmt.Sprintf("%s->%s:%d", src, remote.GetIp().GetHost(), remote.GetIp().GetPort()))
}

// recordUnresolvedRemote records a socket pair(src->dst) that cannot be resolved by any of the
// resolvers(local process, conntrack, ztunnel correlation) - it would reach the backend as a raw
// IP - together with the categorized reason, for the periodic summary. The per-reason totals are
// always counted; the per-pair map is bounded so a flood of distinct pairs cannot grow it without
// limit.
func (c *ConnectionManager) recordUnresolvedRemote(reason, socketPair string) {
	c.unresolvedRemoteCount.Add(1)
	c.unresolvedRemoteLock.Lock()
	defer c.unresolvedRemoteLock.Unlock()
	c.unresolvedByReason[reason]++
	key := reason + " " + socketPair
	if _, exist := c.unresolvedRemotes[key]; !exist && len(c.unresolvedRemotes) >= unresolvedRemoteMaxTrack {
		return
	}
	c.unresolvedRemotes[key]++
}

// drainUnresolvedRemotes returns, since the last report, the top un-resolved socket pairs(each
// prefixed with its reason) and the full per-reason breakdown, and resets the tracking maps.
func (c *ConnectionManager) drainUnresolvedRemotes() (topPairs, byReason string) {
	c.unresolvedRemoteLock.Lock()
	pairs := c.unresolvedRemotes
	reasons := c.unresolvedByReason
	c.unresolvedRemotes = make(map[string]int64)
	c.unresolvedByReason = make(map[string]int64)
	c.unresolvedRemoteLock.Unlock()

	sortByCount := func(m map[string]int64, topN int) string {
		if len(m) == 0 {
			return "none"
		}
		type kv struct {
			k string
			v int64
		}
		sorted := make([]kv, 0, len(m))
		for k, v := range m {
			sorted = append(sorted, kv{k: k, v: v})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
		if topN > 0 && len(sorted) > topN {
			sorted = sorted[:topN]
		}
		items := make([]string, 0, len(sorted))
		for _, s := range sorted {
			items = append(items, fmt.Sprintf("%s=%d", s.k, s.v))
		}
		return strings.Join(items, ", ")
	}
	return sortByCount(pairs, unresolvedRemoteTopCount), sortByCount(reasons, 0)
}

// startUnresolvedRemoteReporter periodically reports the summary of remote addresses
// that cannot be resolved(by neither the conntrack nor the ztunnel correlation) at the info level
func (c *ConnectionManager) startUnresolvedRemoteReporter(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(unresolvedRemoteReportInterval)
		defer ticker.Stop()
		var lastUnresolvedCount int64
		for {
			select {
			case <-ticker.C:
				unresolvedCount := c.unresolvedRemoteCount.Load()
				if unresolvedCount == lastUnresolvedCount {
					continue
				}
				intervalUnresolved := unresolvedCount - lastUnresolvedCount
				lastUnresolvedCount = unresolvedCount
				conntrackStats := "not available"
				if c.connectTracker != nil {
					conntrackStats = c.connectTracker.StatsString()
				}
				topPairs, byReason := c.drainUnresolvedRemotes()
				// the built/resolved/unresolved totals and the latency buckets are cumulative since
				// start; the by-reason breakdown and the top socket pairs are drained and reset every
				// report. To keep the line internally consistent the unresolved count is shown as the
				// per-interval delta(which matches the by-reason breakdown's window) next to the
				// cumulative total, and each field states which window it describes.
				log.Infof("remote address resolve summary: total remote addresses built(cumulative): %d, "+
					"resolved by conntrack(cumulative): %d, resolved by ztunnel correlation(cumulative): %d, "+
					"unresolved(sent as raw IP) since last report: %d(cumulative total: %d), "+
					"conntrack stats(cumulative): {%s}, unresolved by reason since last report: {%s}, "+
					"open->resolution latency buckets(cumulative) {<1s: %d, 1-5s: %d, 5-15s: %d, >=15s: %d, max: %dms}, "+
					"top unresolved socket pairs since last report: %s",
					c.remoteAddressBuildCount.Load(), c.conntrackResolvedRemoteCount.Load(),
					c.ztunnelResolvedRemoteCount.Load(), intervalUnresolved, unresolvedCount,
					conntrackStats, byReason,
					c.resolutionLatencyUnder1s.Load(), c.resolutionLatency1to5s.Load(),
					c.resolutionLatency5to15s.Load(), c.resolutionLatencyOver15s.Load(),
					c.resolutionLatencyMaxMilli.Load(), topPairs)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// RetroResolveBySrc is the push side of the ztunnel correlation: when a source-keyed mapping
// arrives(a ConnectionResult / access-log event), the collector calls this so every connection
// still held in the manager for that source address is re-offered to the flush listeners right
// away, instead of waiting for the connection's own next flush cycle to pull the cache. This
// closes the window where a short connection's mapping event lands between its flush cycles or
// just as it would flush, which is the dominant residual "-|service|-" cause under high load.
func (c *ConnectionManager) RetroResolveBySrc(srcIP string, srcPort uint16) {
	c.connections.IterCb(func(_ ConnectionKey, connection *ConnectionInfo) {
		if connection == nil || connection.Socket == nil || connection.RPCConnection == nil {
			return
		}
		// only an unresolved client(outbound) leg for this exact source is a candidate - it gets the
		// mapping attached here; a DST identity that arrives after the attach is filled at flush time
		// by isDstIdentityPending, so an already-attached connection needs no re-offer
		if connection.RPCConnection.Attachment != nil ||
			connection.Socket.Role != enums.ConnectionRoleClient ||
			connection.Socket.SrcIP != srcIP || connection.Socket.SrcPort != srcPort {
			return
		}
		for _, flush := range c.flushListeners {
			flush.ReadyToFlushConnection(connection, nil)
		}
	})
}

func (c *ConnectionManager) connectionPostHandle(connection *ConnectionInfo, event events.Event) {
	if connection == nil {
		return
	}
	switch e := event.(type) {
	case *CloseEventWithNotify:
		connection.MarkDeletable = true
	case events.SocketDetail:
		tlsMode := connection.RPCConnection.TlsMode
		protocol := connection.RPCConnection.Protocol
		if e.GetSSL() == 1 && connection.RPCConnection.TlsMode == v3.AccessLogConnectionTLSMode_Plain {
			tlsMode = v3.AccessLogConnectionTLSMode_TLS
		}
		if !connection.ProtocolBreak && e.GetProtocol() != enums.ConnectionProtocolUnknown &&
			connection.RPCConnection.Protocol == v3.AccessLogProtocolType_TCP {
			switch e.GetProtocol() {
			case enums.ConnectionProtocolHTTP:
				protocol = v3.AccessLogProtocolType_HTTP_1
			case enums.ConnectionProtocolHTTP2:
				protocol = v3.AccessLogProtocolType_HTTP_2
			}
		}
		if connection.ProtocolBreak && connection.RPCConnection.Protocol != v3.AccessLogProtocolType_TCP {
			protocol = v3.AccessLogProtocolType_TCP
		}
		c.rebuildRPCConnectionWithTLSModeAndProtocol(connection, tlsMode, protocol)
	}

	// notify all flush listeners the connection is ready to flush
	for _, flush := range c.flushListeners {
		flush.ReadyToFlushConnection(connection, event)
	}
}

// According to https://github.com/golang/protobuf/issues/1609
// if the message is modified during marshaling, it may cause the error when send the message to the backend
// so, we need to clone the message and change it before sending it to the channel.
// Nothing changes for almost every event, and then the message is kept.
func (c *ConnectionManager) rebuildRPCConnectionWithTLSModeAndProtocol(connection *ConnectionInfo,
	tls v3.AccessLogConnectionTLSMode, protocol v3.AccessLogProtocolType) {
	// checked before taking the lock: ReplaceAttachment never changes the TLS mode or the protocol
	if original := connection.RPCConnection; original.TlsMode == tls && original.Protocol == protocol {
		return
	}
	connection.updateRPCConnection(func(conn *v3.AccessLogConnection) bool {
		if conn.TlsMode == tls && conn.Protocol == protocol {
			return false
		}
		conn.TlsMode, conn.Protocol = tls, protocol
		return true
	})
}

func (c *ConnectionManager) ProcessIsMonitor(pid uint32) bool {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	return len(c.monitoringProcesses[int32(pid)]) > 0
}

func (c *ConnectionManager) ProcessIsDetectBy(pid uint32, detectType api.ProcessDetectType) bool {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	for _, p := range c.monitoringProcesses[int32(pid)] {
		if p.DetectType() == detectType {
			return true
		}
	}
	return false
}

func (c *ConnectionManager) buildConnection(event *events.SocketConnectEvent, socket *ip.SocketPair,
	local, remote *v3.ConnectionAddress, conKey ConnectionKey) *ConnectionInfo {
	var role v32.DetectPoint
	switch socket.Role {
	case enums.ConnectionRoleClient:
		role = v32.DetectPoint_client
	case enums.ConnectionRoleServer:
		role = v32.DetectPoint_server
	}
	connection := &v3.AccessLogConnection{
		Local:    local,
		Remote:   remote,
		Role:     role,
		TlsMode:  v3.AccessLogConnectionTLSMode_Plain,
		Protocol: v3.AccessLogProtocolType_TCP,
	}
	val, exist := c.connectionProtocolBreakMap.Get(conKey)
	protocolBreak := false
	if exist {
		protocolBreak = val.(bool)
		c.connectionProtocolBreakMap.Delete(conKey)
	}
	return &ConnectionInfo{
		ConnectionID:       event.ConID,
		RandomID:           event.RandomID,
		RPCConnection:      connection,
		PID:                event.PID,
		Socket:             socket,
		LastCheckExistTime: time.Now(),
		CreatedAt:          time.Now(),
		ProtocolBreak:      protocolBreak,
	}
}

func (c *ConnectionManager) buildLocalAddress(pid uint32, port uint16, socket *ip.SocketPair) *v3.ConnectionAddress {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	for _, pi := range c.monitoringProcesses[int32(pid)] {
		if pi.DetectType() == api.Kubernetes {
			entity := pi.Entity()
			podContainer := pi.DetectProcess().(*kubernetes.Process).PodContainer()
			return &v3.ConnectionAddress{
				Address: &v3.ConnectionAddress_Kubernetes{
					Kubernetes: &v3.KubernetesProcessAddress{
						ServiceName:   entity.ServiceName,
						PodName:       podContainer.Pod.Name,
						ContainerName: podContainer.ContainerSpec.Name,
						ProcessName:   entity.ProcessName,
						Port:          int32(port),
					},
				},
			}
		}
	}
	return &v3.ConnectionAddress{
		Address: &v3.ConnectionAddress_Ip{
			Ip: &v3.IPAddress{
				Host: socket.SrcIP,
				Port: int32(port),
			},
		},
	}
}

func (c *ConnectionManager) buildAddressFromRemote(ipHost string, port uint16) *v3.ConnectionAddress {
	return &v3.ConnectionAddress{
		Address: &v3.ConnectionAddress_Ip{
			Ip: &v3.IPAddress{
				Host: ipHost,
				Port: int32(port),
			},
		},
	}
}

func (c *ConnectionManager) OnConnectionClose(event *events.SocketCloseEvent) *CloseEventWithNotify {
	return &CloseEventWithNotify{
		SocketCloseEvent: event,
	}
}

func (c *ConnectionManager) AddNewProcess(pid int32, entities []api.ProcessInterface) {
	// filtering the namespace
	monitorProcesses := c.shouldMonitorProcesses(entities)
	if len(monitorProcesses) == 0 {
		c.RemoveProcess(pid, entities)
		return
	}

	c.monitoringProcessLock.Lock()
	defer c.monitoringProcessLock.Unlock()

	// adding monitoring process and IP addresses
	var entity *api.ProcessEntity
	if len(entities) > 0 {
		entity = entities[0].Entity()
	}
	log.Infof("adding monitoring process, pid: %d, entity: %v", pid, entity)
	if _, ok := c.monitoringProcesses[pid]; ok {
		log.Infof("the process %d already monitoring, so no needs to add again", pid)
		return
	}
	c.monitoringProcesses[pid] = monitorProcesses
	c.updateMonitorStatusForProcess(pid, true)
	c.recordProcessVerdict(pid, ProcessVerdictMonitored)
	// Seeding the allowlist here, and nowhere earlier, is deliberate: this is the one point both the
	// finder and the monitor filter(exclude namespaces, clusters) have passed, so a cgroup can only
	// be allowed once everything agrees its processes are ours to report.
	c.allowCgroupsOfProcesses(pid, monitorProcesses)
	for _, entity := range monitorProcesses {
		for _, host := range entity.ExposeHosts() {
			c.localIPWithPid[host] = pid
		}
	}
	c.printTotalAddressesWithPid("adding monitoring process")
	for _, l := range c.processListeners {
		l.OnNewProcessMonitoring(pid)
	}
}

func (c *ConnectionManager) rebuildLocalIPWithPID() {
	result := make(map[string]int32)
	for pid, entities := range c.monitoringProcesses {
		for _, entity := range entities {
			for _, host := range entity.ExposeHosts() {
				result[host] = pid
			}
		}
	}
	c.localIPWithPid = result
}

func (c *ConnectionManager) printTotalAddressesWithPid(prefix string) {
	if !log.Enable(logrus.DebugLevel) {
		return
	}
	log.Debugf("%s, print all local address with pid", prefix)
	log.Debugf("----------------------------")
	log.Debugf("total local address with pid: %d", len(c.localIPWithPid))
	for k, v := range c.localIPWithPid {
		log.Debugf("local address: %s, pid: %d", k, v)
	}
	log.Debugf("----------------------------")
}

func (c *ConnectionManager) shouldMonitorProcesses(entities []api.ProcessInterface) []api.ProcessInterface {
	return c.monitorFilter.ShouldIncludeProcesses(entities)
}

func (c *ConnectionManager) checkConnectionIsExist(con *ConnectionInfo) bool {
	// skip the check if the check time is not reach
	if time.Since(con.LastCheckExistTime) < connectionCheckExistTime {
		return true
	}
	con.LastCheckExistTime = time.Now()
	var activateConn ActiveConnection
	if err := c.activeConnectionMap.Lookup(con.ConnectionID, &activateConn); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			con.MarkDeletable = true
			return false
		}
		log.Warnf("cannot found the active connection: %d-%d, err: %v", con.ConnectionID, con.RandomID, err)
		return false
	} else if activateConn.RandomID != 0 && activateConn.RandomID != con.RandomID {
		log.Debugf("detect the connection: %d-%d is already closed(by difference random ID), so remove from the connection manager",
			con.ConnectionID, con.RandomID)
		con.MarkDeletable = true
		return false
	}
	return true
}

func (c *ConnectionManager) RemoveProcess(pid int32, _ []api.ProcessInterface) {
	c.monitoringProcessLock.Lock()
	defer c.monitoringProcessLock.Unlock()
	// delete monitoring process and IP addresses
	c.disallowCgroupsOfProcesses(pid, c.monitoringProcesses[pid])
	delete(c.monitoringProcesses, pid)
	c.updateMonitorStatusForProcess(pid, false)
	// The process passed every filter while it lived, so its access logs are still worth sending
	// once it is gone - a short-lived process being gone is the normal case, not a reason to drop.
	c.recordProcessVerdict(pid, ProcessVerdictApproved)
	c.rebuildLocalIPWithPID()
	c.printTotalAddressesWithPid("remove monitoring process")
	for _, l := range c.processListeners {
		l.OnProcessRemoved(pid)
	}
}

func (c *ConnectionManager) RecheckAllProcesses(processes map[int32][]api.ProcessInterface) {
	shouldMonitoringProcesses := make(map[int32][]api.ProcessInterface)
	for pid, p := range processes {
		monitorProcesses := c.shouldMonitorProcesses(p)
		if len(monitorProcesses) == 0 {
			continue
		}
		shouldMonitoringProcesses[pid] = monitorProcesses
	}
	// checking the monitoring process
	c.monitoringProcesses = shouldMonitoringProcesses
	// for-each the existing monitored map, it should not be monitored, then remote it
	iterate := c.processMonitorMap.Iterate()
	processInBPF := make(map[int32]bool)
	var pid uint32
	var monitor uint32
	for iterate.Next(&pid, &monitor) {
		processInBPF[int32(pid)] = true
	}

	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	// make sure BPF and user space are consistent
	for pid := range processInBPF {
		if _, ok := c.monitoringProcesses[pid]; !ok {
			c.updateMonitorStatusForProcess(pid, false)
			for _, l := range c.processListeners {
				l.OnProcessRemoved(pid)
			}
		}
	}
	for pid := range c.monitoringProcesses {
		if _, ok := processInBPF[pid]; !ok {
			c.updateMonitorStatusForProcess(pid, true)
			for _, l := range c.processListeners {
				l.OnNewProcessMonitoring(pid)
			}
		}
	}

	// update all IP addresses
	c.rebuildLocalIPWithPID()
}

func (c *ConnectionManager) updateMonitorStatusForProcess(pid int32, monitor bool) {
	var err error
	if monitor {
		// the hint of the process goes first, its positive state last (bpf/accesslog/process/process.h)
		if err = bpf.MonitorProcessHint(c.processMonitorHint, uint32(pid)); err == nil {
			if err = c.processMonitorMap.Update(pid, uint32(1), ebpf.UpdateAny); err == nil {
				err = bpf.ConfirmMonitorProcessHint(c.processMonitorHint, uint32(pid))
			}
		}
	} else {
		// the positive state goes before the process leaves the map
		if err = bpf.UnconfirmMonitorProcessHint(c.processMonitorHint, uint32(pid)); err == nil {
			err = c.processMonitorMap.Delete(pid)
		}
	}
	if err != nil {
		if !monitor && errors.Is(err, ebpf.ErrKeyNotExist) {
			return
		}
		log.Warnf("failed to update the process %d monitor status to %t: %v", pid, monitor, err)
	} else {
		log.Debugf("update the process %d monitor status to %t", pid, monitor)
	}
}

// OnBuildConnectionLogFinished notify the connection log build finished
func (c *ConnectionManager) OnBuildConnectionLogFinished() {
	// delete all connections which marked as deletable
	// all deletable connection events been sent
	deletableConnections := make(map[ConnectionKey]*ConnectionInfo)
	now := time.Now()
	c.connections.IterCb(func(key ConnectionKey, con *ConnectionInfo) {
		if con == nil {
			return
		}
		// already mark as deletable or process not monitoring
		shouldDelete := con.MarkDeletable || !c.ProcessIsMonitor(con.PID)
		if !shouldDelete {
			shouldDelete = !c.checkConnectionIsExist(con)
		}

		if shouldDelete && con.DeleteAfter == nil {
			deleteAfterTime := now.Add(connectionDeleteDelayTime)
			con.DeleteAfter = &deleteAfterTime
			log.Debugf("detected the connection has mark as deletable, so add a delay timer, connection ID: %d, random ID: %d",
				con.ConnectionID, con.RandomID)
		}

		if shouldDelete && now.After(*con.DeleteAfter) {
			deletableConnections[key] = con
		}
	})

	for key, con := range deletableConnections {
		// the connection state is finalized, record the remote address resolve result
		c.recordConnectionResolveResult(con)
		log.Debugf("deleting the connection in manager: %s", key)
		c.connections.Remove(key)
	}
}

func (c *ConnectionManager) SkipAllDataAnalyzeAndDowngradeProtocol(conID, ranID uint64) {
	// setting connection protocol is break
	connectionKey := NewConnectionKey(conID, ranID)
	connection, exist := c.connections.Get(connectionKey)
	if exist {
		connection.ProtocolBreak = true
	} else {
		// setting to the protocol break map for encase the runner not starting building logs
		c.connectionProtocolBreakMap.Set(connectionKey, true, time.Minute)
	}

	// setting the connection skip data upload
	var activateConn ActiveConnection
	if err := c.activeConnectionMap.Lookup(conID, &activateConn); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return
		}
		log.Warnf("cannot found the active connection: %d-%d, err: %v", conID, ranID, err)
		return
	}
	if activateConn.RandomID != ranID {
		// make sure the connection is the same
		return
	}

	activateConn.SkipDataUpload = 1
	if err := c.activeConnectionMap.Update(conID, activateConn, ebpf.UpdateAny); err != nil {
		log.Warnf("failed to update the active connection: %d-%d", conID, ranID)
	}
}

func getSocketPairFromConnectEvent(event events.Event) (*events.SocketConnectEvent, *ip.SocketPair) {
	if e, ok := event.(*ConnectEventWithSocket); ok {
		return e.SocketConnectEvent, e.SocketPair
	}
	return nil, nil
}

type ActiveConnection struct {
	RandomID       uint64
	PID            uint32
	SocketFD       uint32
	Role           uint32
	SocketFamily   uint32
	Protocol       uint8
	SSL            uint8
	SkipDataUpload uint8
	// PAD for make sure it have same size when marshal data to the BPF
	PAD0 uint8
	PAD1 uint32
}

// DropH2CUnusedFrame tells whether the BPF side drops the h2c socket calls that carry only unused frames
// (access_log.protocol_analyze.drop_h2c_unused_frame, as it was applied)
func (c *ConnectionManager) DropH2CUnusedFrame() bool {
	return c != nil && c.dropH2CUnusedFrame
}

// SkipH2CDataPayload tells whether the BPF side uploads the h2c socket calls inside a DATA payload without
// their content (access_log.protocol_analyze.skip_h2c_data_payload, as it was applied)
func (c *ConnectionManager) SkipH2CDataPayload() bool {
	return c != nil && c.skipH2CDataPayload
}

// SetH2CSwitches sets the switches as SkipH2CDataPayload and DropH2CUnusedFrame report them, for a
// manager built without the BPF side (tests of the analyzers)
func (c *ConnectionManager) SetH2CSwitches(drop, skip bool) {
	c.dropH2CUnusedFrame, c.skipH2CDataPayload = drop, skip
}

// setupH2CFrames passes access_log.protocol_analyze.drop_h2c_unused_frame and skip_h2c_data_payload to
// the BPF side and returns the switches as it has them. It runs before any program is attached, so the
// BPF side never sees a switch change under a connection.
func setupH2CFrames(config *Config, bpfLoader *bpf.Loader) (drop, skip bool) {
	drop = setBPFSwitch(bpfLoader.DropH2cUnusedFrame, config != nil && config.ProtocolAnalyze.DropH2CUnusedFrame,
		"cannot enable dropping the unused h2c frames, every socket call is uploaded",
		"dropping the socket calls of cleartext HTTP/2 connections that carry only unused frames")
	skip = setBPFSwitch(bpfLoader.SkipH2cDataPayload, config != nil && config.ProtocolAnalyze.SkipH2CDataPayload,
		"cannot enable skipping the h2c DATA payloads, every socket call is uploaded with its content",
		"uploading the socket calls of cleartext HTTP/2 connections that lie inside a DATA payload without their content")
	setupH2CBatch(config, bpfLoader, skip)
	return drop, skip
}

// SummarizeH2CPayload tells whether the BPF side summarizes the h2c socket calls inside a DATA payload instead
// of sending them (access_log.protocol_analyze.summarize_h2c_payload, as it was applied)
func (c *ConnectionManager) SummarizeH2CPayload() bool {
	return c != nil && c.summarizeH2CPayload
}

// setupH2CSummary passes access_log.protocol_analyze.summarize_h2c_payload to the BPF side, with the boot
// time it splits the summaries at the wall clock minutes by. It only applies on top of the batching (whose
// records carry the summaries) with the kernel log merge on (a summary is the merged detail of its calls), and
// only with a BPF side that has it. It runs before any program is attached.
func setupH2CSummary(config *Config, bpfLoader *bpf.Loader, skip bool) bool {
	if bpfLoader.SummarizeH2cPayload == nil || bpfLoader.BatchH2cRecords == nil {
		return false
	}
	want := config != nil && config.ProtocolAnalyze.SummarizeH2CPayload && config.ProtocolAnalyze.BatchH2CRecords &&
		skip && config.Flush.MergeKernelLogs
	if want && config.KernelMetrics.L2L3 {
		// a summary is the merged detail of its calls, which has no L2 to L4 details: the calls are sent on their own
		log.Warnf("summarize_h2c_payload is off with access_log.kernel_metrics.l2_l3: a summary carries no L2 to L4 metrics")
		want = false
	}
	if want {
		var batching uint32
		if err := bpfLoader.BatchH2cRecords.Get(&batching); err != nil || batching == 0 {
			want = false
		}
	}
	if want {
		if err := bpfLoader.BootTimeUnixNs.Set(uint64(host.BootTime.UnixNano())); err != nil {
			log.Warnf("cannot pass the boot time to the BPF side, the h2c DATA payload is not summarized: %v", err)
			want = false
		}
	}
	return setBPFSwitch(bpfLoader.SummarizeH2cPayload, want,
		"cannot enable summarizing the h2c DATA payload, the skipped calls are sent on their own",
		"summarizing the socket calls of cleartext HTTP/2 connections that lie inside a DATA payload per stream")
}

// setupH2CBatch passes access_log.protocol_analyze.batch_h2c_records to the BPF side: the skipped and
// tail-cut h2c calls are then sent as compact records in per-CPU batches. It only applies with the DATA
// payload skipping (which produces those calls) and the kernel log merge on, and only with a BPF side that
// has the batching (the rover's has not: its loader has no such variable). With it on, the idle kick that
// flushes the batches once a second is started; a batching that cannot be kicked is not turned on, so a
// batch never waits for traffic that may not come.
func setupH2CBatch(config *Config, bpfLoader *bpf.Loader, skip bool) {
	want := config != nil && config.ProtocolAnalyze.BatchH2CRecords && skip && config.Flush.MergeKernelLogs
	if bpfLoader.BatchH2cRecords == nil {
		if want {
			log.Warnf("batch_h2c_records is on but the BPF side has no batching, every socket call is sent on its own")
		}
		return
	}
	if want {
		if err := startH2CBatchKick(bpfLoader); err != nil {
			log.Warnf("cannot start the idle kick of the h2c call batches, the batching stays off: %v", err)
			want = false
		}
	}
	setBPFSwitch(bpfLoader.BatchH2cRecords, want,
		"cannot enable batching the h2c call records, every socket call is sent on its own",
		"sending the skipped and tail-cut socket calls of cleartext HTTP/2 connections as per-CPU batches of records")
}

// SkipHTTP1BodyPayloadBPF tells whether the BPF side uploads the HTTP/1 socket calls inside a Content-Length
// body without their content (access_log.protocol_analyze.skip_http1_body_payload_bpf, as it was applied)
func (c *ConnectionManager) SkipHTTP1BodyPayloadBPF() bool {
	return c != nil && c.skipHTTP1BodyPayload
}

// setupHTTP1BodySkip passes access_log.protocol_analyze.skip_http1_body_payload_bpf to the BPF side, with
// the coalescing of the skipped calls of a body when the kernel logs are merged
// (access_log.flush.merge_kernel_logs) and the boot time the coalescing keeps the minutes of the kernel
// logs with, and returns the switch as the BPF side has it. It runs before any program is attached.
func setupHTTP1BodySkip(config *Config, bpfLoader *bpf.Loader) bool {
	want := config != nil && config.ProtocolAnalyze.SkipHTTP1BodyPayloadBPF
	if want {
		if err := bpfLoader.BootTimeUnixNs.Set(uint64(host.BootTime.UnixNano())); err != nil {
			log.Warnf("cannot pass the boot time to the BPF side, the HTTP/1 body calls are uploaded with their content: %v", err)
			want = false
		}
	}
	skip := setBPFSwitch(bpfLoader.SkipHttp1BodyPayload, want,
		"cannot enable skipping the HTTP/1 bodies, every socket call is uploaded with its content",
		"uploading the socket calls of cleartext HTTP/1 connections that lie inside a Content-Length body without their content")
	setBPFSwitch(bpfLoader.CoalesceHttp1BodyPayload, skip && config.Flush.MergeKernelLogs,
		"cannot enable coalescing the skipped HTTP/1 body calls, each is uploaded on its own",
		"uploading the consecutive skipped socket calls of an HTTP/1 body as one event (merge_kernel_logs)")
	return skip
}

// setBPFSwitch sets a BPF global switch and returns whether it is on: a switch that cannot be set is off
func setBPFSwitch(v *ebpf.Variable, want bool, failed, enabled string) bool {
	if err := v.Set(boolToUint32(want)); err != nil {
		if want {
			log.Warnf("%s: %v", failed, err)
		}
		return false
	}
	if want {
		log.Infof("%s", enabled)
	}
	return want
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// deleteH2CState removes the h2c frame state of a connection whose close the BPF side never sees, unless it is the
// state of a connection that reused the fd (h2c_stream_t starts with the random id of its connection)
func (c *ConnectionManager) deleteH2CState(conID, randomID uint64) {
	value := make([]byte, c.h2cStreamMap.ValueSize())
	if err := c.h2cStreamMap.Lookup(conID, value); err != nil {
		return
	}
	if len(value) >= 8 && binary.LittleEndian.Uint64(value) != randomID {
		return
	}
	if err := c.h2cStreamMap.Delete(conID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Warnf("failed to delete the h2c state of the connection, connection ID: %d, error: %v", conID, err)
	}
}

// setupEventReader passes access_log.event_reader to the event queues, which start after this
func setupEventReader(config *Config, bpfLoader *bpf.Loader) {
	if config == nil {
		return
	}
	r := config.EventReader
	options := btf.EventQueueReaderOptions{WakeupEvents: r.WakeupEvents, BatchSize: r.BatchSize}
	if r.FlushPeriod != "" {
		if d, err := time.ParseDuration(r.FlushPeriod); err == nil {
			options.FlushPeriod = d
		} else {
			log.Warnf("invalid access_log.event_reader.flush_period %q: %v", r.FlushPeriod, err)
		}
	}
	bpfLoader.SetEventQueueReaderOptions(options)
	flush := options.FlushPeriod
	if flush <= 0 {
		flush = time.Second // the reader's default
	}
	var readerDelay time.Duration
	if options.WakeupEvents > 0 {
		readerDelay += flush
	}
	if options.BatchSize > 1 {
		readerDelay += flush
	}
	deliveryDelayReader.Store(int64(readerDelay))
	if options.WakeupEvents > 0 || options.BatchSize > 1 {
		log.Infof("the event queues wake up for every %d events (flushed every %s) and hand over batches of up to %d",
			options.WakeupEvents, options.FlushPeriod, options.BatchSize)
	}
}
