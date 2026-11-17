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

package protocols

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/shardmap"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

var maxBufferExpireDuration = time.Minute

var log = logger.GetLogger("accesslog", "collector", "protocols")

type PartitionContext struct {
	// pendingDataEvents counts the data events appended since the last ProcessEvents, triggerEvents is
	// the count that starts an immediate ProcessEvents (0: only the periodic tick)
	pendingDataEvents int64
	triggerEvents     int64

	context      *common.AccessLogContext
	protocolMgr  *ProtocolManager
	connections  *shardmap.Map[common.ConnectionKey, *PartitionConnection]
	partitionNum int

	analyzeLocker sync.Mutex
	// triggerScheduled is held while an analysis pass started by the event counter is queued or
	// running: without it every event above the trigger count would start a goroutine that only finds
	// the lock taken, which is one goroutine per event under sustained load
	triggerScheduled atomic.Bool

	// self observability of the analysis: how much is waiting, how often it runs and how long it
	// takes. Without these the only way to tell that the analysis is behind is a heap profile.
	analyzePasses atomic.Int64
	analyzeNanos  atomic.Int64
	lastPassAt    atomic.Int64
	// rerun is set when a trigger could not run because another ProcessEvents was already running:
	// the running one repeats the pass instead of letting the triggering data wait for the next trigger
	rerun atomic.Bool
	// lastConnection is the connection GetConnectionContext returned last: the events of a connection come in
	// runs (the records of a per-CPU batch), so it is most often the next one too, without the shard map
	lastConnection atomic.Pointer[PartitionConnection]
	// removed are the connections the partition removed within removedMemory (UnixNano of the removal): what comes
	// for them later (a summary of skipped HTTP/2 payload) goes on its own at once, instead of in a new connection
	// that would hold it until the close detection finds the connection gone again
	removedLock sync.Mutex
	removed     map[common.ConnectionKey]int64
	// analyzeScratch holds the connections of an analysis pass (under analyzeLocker)
	analyzeScratch []*PartitionConnection
}

// removedMemory is how long a partition remembers a removed connection (PartitionContext.removed): the connection
// manager keeps a closed connection about as long (connectionDeleteDelayTime), after that nothing it sends is
// reported anyway
const removedMemory = 30 * time.Second

func newPartitionConnection(protocolMgr *ProtocolManager, conID, randomID uint64,
	protocol enums.ConnectionProtocol, currentDataID uint64) *PartitionConnection {
	connection := &PartitionConnection{
		connectionID:       conID,
		randomID:           randomID,
		dataBuffers:        make(map[enums.ConnectionProtocol]*buffer.Buffer),
		protocol:           make(map[enums.ConnectionProtocol]uint64),
		protocolAnalyzer:   make(map[enums.ConnectionProtocol]Protocol),
		protocolMetrics:    make(map[enums.ConnectionProtocol]ProtocolMetrics),
		lastCheckCloseTime: time.Now(),
	}
	connection.appendProtocolIfNeed(protocolMgr, conID, randomID, protocol, currentDataID)
	return connection
}

func (p *PartitionConnection) appendProtocolIfNeed(protocolMgr *ProtocolManager, conID, randomID uint64,
	protocol enums.ConnectionProtocol, currentDataID uint64) {
	// almost every event is of a protocol already recorded with a smaller data id: nothing to change. The
	// protocol and the smallest data id seen last answer that without the lock: the smallest data id of a
	// protocol only ever goes down, so one remembered is never below it
	if p.knownProtocol.Load() == uint32(protocol)+1 && currentDataID >= p.knownMinDataID.Load() {
		return
	}
	p.protocolLocker.RLock()
	minDataID, exist := p.protocol[protocol]
	p.protocolLocker.RUnlock()
	if exist && currentDataID >= minDataID {
		p.knownMinDataID.Store(minDataID)
		p.knownProtocol.Store(uint32(protocol) + 1)
		return
	}
	p.protocolLocker.Lock()
	defer p.protocolLocker.Unlock()
	if minDataID, exist := p.protocol[protocol]; !exist {
		analyzer := protocolMgr.GetProtocol(protocol)
		p.protocol[protocol] = currentDataID
		buf := buffer.NewBuffer()
		if protocol == enums.ConnectionProtocolHTTP2 {
			// the HTTP/2 analyzer only takes the events of the connection buffer over into its per direction
			// views (TakeDataEvents), which count the uploaded bytes for themselves
			buf.SetUploadAccounting(false)
		}
		p.dataBuffers[protocol] = buf
		p.protocolAnalyzer[protocol] = analyzer
		p.protocolMetrics[protocol] = analyzer.GenerateConnection(conID, randomID)
		p.setProtocolSlot(protocol, buf, analyzer, p.protocolMetrics[protocol])
	} else if currentDataID < minDataID {
		p.protocol[protocol] = currentDataID
	}
}

func NewPartitionContext(ctx *common.AccessLogContext, num int, protocols []Protocol) *PartitionContext {
	pc := &PartitionContext{
		context:      ctx,
		protocolMgr:  NewProtocolManager(protocols),
		connections:  shardmap.New[common.ConnectionKey, *PartitionConnection](),
		partitionNum: num,
	}
	pc.triggerEvents = int64(ctx.Config.ProtocolAnalyze.TriggerEvents)
	pc.lastPassAt.Store(time.Now().UnixNano())
	ctx.ConnectionMgr.RegisterProcessor(pc)
	registerPartitionMetrics(pc)
	return pc
}

func (p *PartitionContext) Start(ctx context.Context) {
	// process events with interval
	flushDuration, _ := time.ParseDuration(p.context.Config.Flush.Period)
	timeTicker := time.NewTicker(flushDuration)
	go func() {
		for {
			select {
			case <-timeTicker.C:
				// process event with interval
				p.ProcessEvents()
			case <-ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()

	// delete the expired events
	expireTicker := time.NewTicker(maxBufferExpireDuration)
	go func() {
		for {
			select {
			case <-expireTicker.C:
				p.ProcessExpireEvents()
			case <-ctx.Done():
				expireTicker.Stop()
				return
			}
		}
	}()
}

func (p *PartitionContext) Consume(data interface{}) {
	if event, ok := data.(*events.SocketDataUploadEvent); ok {
		if log.Enable(logrus.DebugLevel) {
			pid, _ := events.ParseConnectionID(event.ConnectionID)
			log.Debugf("receive the socket data event, connection ID: %d, random ID: %d, pid: %d, prev data id: %d, "+
				"data id: %d, sequence: %d, finished: %t, protocol: %d, size: %d",
				event.ConnectionID, event.RandomID, pid, event.PrevDataID0, event.DataID0, event.Sequence0, event.IsFinished(),
				event.Protocol0, event.BufferLen())
		}
		connection := p.GetConnectionContext(event.ConnectionID, event.RandomID, event.Protocol0, event.DataID0)
		p.AppendAndMaybeAnalyze(connection, event)
	}
}

// AppendAndMaybeAnalyze appends a socket data event to its connection and starts an analysis pass of
// the connections with new data once enough of them are pending. Consumers that receive the events
// themselves (instead of through Consume) call this, so the trigger policy stays in one place.
func (p *PartitionContext) AppendAndMaybeAnalyze(connection *PartitionConnection, data buffer.SocketDataBuffer) {
	if !p.filterGap(connection, data) {
		connection.AppendData(data)
	}
	if connection.releaseIfRemoved() {
		return
	}
	if !p.NoteDataEvent() {
		return
	}
	if !p.triggerScheduled.CompareAndSwap(false, true) {
		// a pass is already queued or running: tell it to repeat instead of queueing another one, so
		// the data that triggered this does not wait for the next trigger
		p.rerun.Store(true)
		return
	}
	go func() {
		defer p.triggerScheduled.Store(false)
		p.processEventsOfNewData()
	}()
}

// NoteDataEvent counts a pending data event and reports whether the trigger count has been reached.
// The counter is reset by the analysis pass itself, so a trigger that cannot run right away is not lost.
func (p *PartitionContext) NoteDataEvent() bool {
	if p.triggerEvents <= 0 {
		return false
	}
	return atomic.AddInt64(&p.pendingDataEvents, 1) >= p.triggerEvents
}

func (p *PartitionContext) GetConnectionContext(connectionID, randomID uint64,
	protocol enums.ConnectionProtocol, currentDataID uint64) *PartitionConnection {
	if last := p.lastConnection.Load(); last != nil && last.connectionID == connectionID && last.randomID == randomID &&
		!last.removed.Load() {
		last.appendProtocolIfNeed(p.protocolMgr, connectionID, randomID, protocol, currentDataID)
		return last
	}
	conKey := common.NewConnectionKey(connectionID, randomID)
	connection, exist := p.connections.Get(conKey)
	if exist {
		connection.appendProtocolIfNeed(p.protocolMgr, connectionID, randomID, protocol, currentDataID)
		p.lastConnection.Store(connection)
		return connection
	}
	result := newPartitionConnection(p.protocolMgr, connectionID, randomID, protocol, currentDataID)
	p.connections.Set(conKey, result)
	p.lastConnection.Store(result)
	return result
}

// FindConnectionContext is the context of the connection when the partition has one, nil otherwise
func (p *PartitionContext) FindConnectionContext(connectionID, randomID uint64) *PartitionConnection {
	connection, exist := p.connections.Get(common.NewConnectionKey(connectionID, randomID))
	if !exist {
		return nil
	}
	return connection
}

// ProcessEvents analyzes every connection of the partition and detects closed ones; it runs on the
// periodic flush tick.
func (p *PartitionContext) ProcessEvents() {
	p.processEvents(true)
}

// processEventsOfNewData analyzes only the connections that received data since the last pass; it runs
// when the pending event counter reaches trigger_events.
func (p *PartitionContext) processEventsOfNewData() {
	p.processEvents(false)
}

func (p *PartitionContext) processEvents(all bool) {
	// it could be triggered by interval or reach counter
	// if any trigger bean locked, the other one just ignore process
	if !p.analyzeLocker.TryLock() {
		// the data that triggered this run would otherwise wait for the next trigger (or tick): let the
		// run that holds the lock repeat the pass instead
		p.rerun.Store(true)
		return
	}
	defer p.analyzeLocker.Unlock()

	for {
		p.rerun.Store(false)
		atomic.StoreInt64(&p.pendingDataEvents, 0)
		start := time.Now()
		p.processEvents0(all)
		p.analyzeNanos.Add(int64(time.Since(start)))
		p.analyzePasses.Add(1)
		p.lastPassAt.Store(time.Now().UnixNano())
		if !p.rerun.Load() {
			return
		}
	}
}

// processEvents0 analyzes the connections that received data since the last pass. `all` also analyzes
// the idle ones and runs the close detection; it is set on the periodic tick, so a pass triggered by
// the event counter of one busy connection does not walk every connection of the partition.
func (p *PartitionContext) processEvents0(all bool) {
	closed := make([]*PartitionConnection, 0)
	// the connections are analyzed from a copy: a shard of the map stays locked only while it is copied, so the
	// partition goroutine adding a connection never waits for an analysis
	p.analyzeScratch = p.connections.AppendValues(p.analyzeScratch[:0])
	defer func() {
		clear(p.analyzeScratch)
	}()
	for _, info := range p.analyzeScratch {
		hasNewData := info.takeDataAppended()
		if !hasNewData && !all {
			continue
		}
		p.processConnectionEvents(info)
		if !all {
			continue
		}

		// if the connection already closed and not contains any buffer data, then delete the connection
		if info.PendingDataLength() > 0 {
			continue
		}
		if !info.closed {
			p.checkTheConnectionIsAlreadyClose(info)
		}
		if info.closed {
			closed = append(closed, info)
			log.Debugf("detect the connection is already closed, then notify to the callback, connection ID: %d, random ID: %d, partition number: %d",
				info.connectionID, info.randomID, p.partitionNum)
		}
	}

	if all {
		p.forgetRemoved(time.Now())
	}
	for _, con := range closed {
		// marked before it leaves the map: GetConnectionContext no longer hands it out from lastConnection
		con.removed.Store(true)
		p.lastConnection.CompareAndSwap(con, nil)
		key := common.NewConnectionKey(con.connectionID, con.randomID)
		p.noteRemoved(key)
		p.connections.Remove(key)
		con.ReleasePendingData()
	}
}

func (p *PartitionContext) noteRemoved(key common.ConnectionKey) {
	p.removedLock.Lock()
	defer p.removedLock.Unlock()
	if p.removed == nil {
		p.removed = make(map[common.ConnectionKey]int64)
	}
	p.removed[key] = time.Now().UnixNano()
}

// forgetRemoved forgets the connections removed removedMemory ago
func (p *PartitionContext) forgetRemoved(now time.Time) {
	p.removedLock.Lock()
	defer p.removedLock.Unlock()
	for key, at := range p.removed {
		if now.UnixNano()-at >= int64(removedMemory) {
			delete(p.removed, key)
		}
	}
}

// WasRemoved tells that the partition removed the connection (closed) within removedMemory, and does not have it
// again
func (p *PartitionContext) WasRemoved(connectionID, randomID uint64) bool {
	key := common.NewConnectionKey(connectionID, randomID)
	p.removedLock.Lock()
	_, removed := p.removed[key]
	p.removedLock.Unlock()
	if !removed {
		return false
	}
	_, exist := p.connections.Get(key)
	return !exist
}

func (p *PartitionContext) checkTheConnectionIsAlreadyClose(con *PartitionConnection) {
	if time.Since(con.lastCheckCloseTime) <= time.Second*30 {
		return
	}
	con.lastCheckCloseTime = time.Now()
	var activateConn common.ActiveConnection
	if err := p.context.BPF.ActiveConnectionMap.Lookup(con.connectionID, &activateConn); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			con.closed = true
			log.Debugf("detect the connection: %d-%d is already closed(by key not exist), so remove from the activate connection",
				con.connectionID, con.randomID)
			return
		}
		log.Warnf("cannot found the active connection: %d-%d, err: %v", con.connectionID, con.randomID, err)
		return
	} else if activateConn.RandomID != 0 && activateConn.RandomID != con.randomID {
		log.Debugf("detect the connection: %d-%d is already closed(by difference random ID), so remove from the activate connection",
			con.connectionID, con.randomID)
		con.closed = true
	}
}

func (p *PartitionContext) ProcessExpireEvents() {
	// the expiry must be mutual exclusion with events processor
	p.analyzeLocker.Lock()
	defer p.analyzeLocker.Unlock()

	p.analyzeScratch = p.connections.AppendValues(p.analyzeScratch[:0])
	for _, con := range p.analyzeScratch {
		p.processConnectionExpireEvents(con)
	}
	clear(p.analyzeScratch)
	purgeGapMarks(maxBufferExpireDuration)
}

func (p *PartitionContext) processConnectionExpireEvents(connection *PartitionConnection) {
	for _, buf := range connection.Buffers() {
		if c := buf.DeleteExpireEvents(maxBufferExpireDuration); c > 0 {
			log.Debugf("total removed %d expired socket data events from connection ID: %d, random ID: %d", c,
				connection.connectionID, connection.randomID)
		}
	}
}

func (p *PartitionContext) processConnectionEvents(connection *PartitionConnection) {
	if connection.skipAllDataAnalyze {
		if connection.gap.Load() != nil {
			connection.releaseGap()
		}
		return
	}
	helper := &AnalyzeHelper{}
	if connection.gap.Load() != nil {
		p.pruneAfterGap(connection)
	}
	p.analyzeConnection(connection, helper)
	if connection.gap.Load() != nil && p.resetAfterGap(connection) {
		// the events before the gap were analyzed above: resume with the resync request, pruned first
		// when it was cut again while resynchronising
		if connection.gap.Load() != nil {
			p.pruneAfterGap(connection)
		}
		p.analyzeConnection(connection, helper)
	}

	if helper.ProtocolBreak {
		// notify the connection manager to skip the analysis of all the data of the connection
		connection.skipAllDataAnalyze = true
		p.context.ConnectionMgr.SkipAllDataAnalyzeAndDowngradeProtocol(connection.connectionID, connection.randomID)
		// (the analyzer reported the kernel logs of the events in OnProtocolBreak)
		for _, buf := range connection.Buffers() {
			buf.Clean()
		}
	}
}

func (p *PartitionContext) analyzeConnection(connection *PartitionConnection, helper *AnalyzeHelper) {
	for _, protocol := range connection.sortedProtocols() {
		analyzer := connection.analyzer(protocol)
		if analyzer == nil {
			continue
		}
		if err := analyzer.Analyze(connection, helper); err != nil {
			log.Warnf("failed to analyze the %s protocol data: %v", enums.ConnectionProtocolString(protocol), err)
		}
	}
}

// the partitions register themselves so the metrics can report all of them without the queue having
// to hand them out; the series are registered once, on the first partition
var (
	partitionsLocker     sync.Mutex
	registeredPartitions []*PartitionContext
	partitionMetricsOnce sync.Once
)

func registerPartitionMetrics(p *PartitionContext) {
	partitionsLocker.Lock()
	registeredPartitions = append(registeredPartitions, p)
	partitionsLocker.Unlock()
	partitionMetricsOnce.Do(func() {
		series := func(read func(*PartitionContext) float64) func() []telemetry.Sample {
			return func() []telemetry.Sample {
				partitionsLocker.Lock()
				defer partitionsLocker.Unlock()
				samples := make([]telemetry.Sample, 0, len(registeredPartitions))
				for _, partition := range registeredPartitions {
					samples = append(samples, telemetry.Sample{
						Labels: map[string]string{"partition": strconv.Itoa(partition.partitionNum)},
						Value:  read(partition),
					})
				}
				return samples
			}
		}
		telemetry.RegisterSeries("rover_analyze_pending_events",
			"Socket data events appended to a partition since its last analysis pass",
			telemetry.Gauge, series(func(p *PartitionContext) float64 {
				return float64(atomic.LoadInt64(&p.pendingDataEvents))
			}))
		telemetry.RegisterSeries("rover_analyze_connections",
			"Connections a partition is tracking", telemetry.Gauge,
			series(func(p *PartitionContext) float64 { return float64(p.connections.Count()) }))
		telemetry.RegisterSeries("rover_analyze_passes_total",
			"Analysis passes a partition has run", telemetry.Counter,
			series(func(p *PartitionContext) float64 { return float64(p.analyzePasses.Load()) }))
		telemetry.RegisterSeries("rover_analyze_seconds_total",
			"Time a partition has spent analyzing, which against the wall clock is how busy it is",
			telemetry.Counter, series(func(p *PartitionContext) float64 {
				return time.Duration(p.analyzeNanos.Load()).Seconds()
			}))
		telemetry.RegisterSeries("rover_analyze_last_pass_age_seconds",
			"Time since a partition last finished an analysis pass", telemetry.Gauge,
			series(func(p *PartitionContext) float64 {
				return time.Since(time.Unix(0, p.lastPassAt.Load())).Seconds()
			}))
	})
}
