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
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"github.com/docker/go-units"

	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
	cmap "github.com/orcaman/concurrent-map"
)

var maxBufferExpireDuration = time.Minute

var log = logger.GetLogger("accesslog", "collector", "protocols")

type AnalyzeQueue struct {
	context      *common.AccessLogContext
	eventQueue   *btf.EventQueue
	perCPUBuffer int64

	detailSupplier   func() events.SocketDetail
	supportAnalyzers func(ctx *common.AccessLogContext) []Protocol
}

func NewAnalyzeQueue(ctx *common.AccessLogContext) (*AnalyzeQueue, error) {
	perCPUBufferSize, err := units.RAMInBytes(ctx.Config.ProtocolAnalyze.PerCPUBufferSize)
	if err != nil {
		return nil, err
	}
	if int(perCPUBufferSize) < os.Getpagesize() {
		return nil, fmt.Errorf("the cpu buffer must bigger than %dB", os.Getpagesize())
	}
	if ctx.Config.ProtocolAnalyze.AnalyzeParallels < 1 {
		return nil, fmt.Errorf("the analyze parallels cannot be small than 1")
	}
	if ctx.Config.ProtocolAnalyze.ParseParallels < 1 {
		return nil, fmt.Errorf("the parse parallels cannot be small than 1")
	}
	if ctx.Config.ProtocolAnalyze.QueueSize < 1 {
		return nil, fmt.Errorf("the queue size be small than 1")
	}

	return &AnalyzeQueue{
		context:      ctx,
		perCPUBuffer: perCPUBufferSize,
		detailSupplier: func() events.SocketDetail {
			return &events.SocketDetailEvent{}
		},
		supportAnalyzers: func(ctx *common.AccessLogContext) []Protocol {
			return []Protocol{
				NewHTTP1Analyzer(ctx, nil),
				NewHTTP2Analyzer(ctx, nil),
			}
		},
	}, nil
}

func (q *AnalyzeQueue) Start(ctx context.Context) {
	buffer.EnableMemoryProtectionFromConfig(q.context.Config.ProtocolAnalyze.MaxMemoryPercent, q.context.Config.ProtocolAnalyze.MaxMemory)
	q.eventQueue = btf.NewEventQueue("socket data analyzer",
		q.context.Config.ProtocolAnalyze.AnalyzeParallels, q.context.Config.ProtocolAnalyze.QueueSize,
		func(num int) btf.PartitionContext {
			return NewPartitionContext(q.context, num, q.supportAnalyzers(q.context))
		})
	q.eventQueue.RegisterReceiver(q.context.BPF.SocketDetailQueue, int(q.perCPUBuffer),
		q.context.Config.ProtocolAnalyze.ParseParallels, func() interface{} {
			return q.detailSupplier()
		}, func(data interface{}) int {
			return int(data.(events.SocketDetail).GetConnectionID())
		})
	q.eventQueue.RegisterReceiver(q.context.BPF.SocketDataUploadQueue, int(q.perCPUBuffer),
		q.context.Config.ProtocolAnalyze.ParseParallels, func() interface{} {
			if !buffer.AcquireEvent() {
				return nil // memory protection active: the event is dropped by the reader
			}
			return &events.SocketDataUploadEvent{}
		}, func(data interface{}) int {
			return int(data.(*events.SocketDataUploadEvent).ConnectionID)
		})

	q.eventQueue.Start(ctx, q.context.BPF.Linker)
}

func (q *AnalyzeQueue) ChangeDetailSupplier(supplier func() events.SocketDetail) {
	q.detailSupplier = supplier
}

func (q *AnalyzeQueue) ChangeSupportAnalyzers(protocols func(ctx *common.AccessLogContext) []Protocol) {
	q.supportAnalyzers = protocols
}

type PartitionContext struct {
	// pendingDataEvents counts the data events appended since the last ProcessEvents, triggerEvents is
	// the count that starts an immediate ProcessEvents (0: only the periodic tick)
	pendingDataEvents int64
	triggerEvents     int64

	context      *common.AccessLogContext
	protocolMgr  *ProtocolManager
	connections  cmap.ConcurrentMap
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
}

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
	p.protocolLocker.Lock()
	defer p.protocolLocker.Unlock()
	if minDataID, exist := p.protocol[protocol]; !exist {
		analyzer := protocolMgr.GetProtocol(protocol)
		p.protocol[protocol] = currentDataID
		p.dataBuffers[protocol] = buffer.NewBuffer()
		p.protocolAnalyzer[protocol] = analyzer
		p.protocolMetrics[protocol] = analyzer.GenerateConnection(conID, randomID)
	} else if currentDataID < minDataID {
		p.protocol[protocol] = currentDataID
	}
}

func NewPartitionContext(ctx *common.AccessLogContext, num int, protocols []Protocol) *PartitionContext {
	pc := &PartitionContext{
		context:      ctx,
		protocolMgr:  NewProtocolManager(protocols),
		connections:  cmap.New(),
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
	switch event := data.(type) {
	case events.SocketDetail:
		pid, _ := events.ParseConnectionID(event.GetConnectionID())
		log.Debugf("receive the socket detail event, connection ID: %d, random ID: %d, pid: %d, data id: %d, "+
			"function name: %s, package count: %d, package size: %d, ssl: %d, protocol: %d",
			event.GetConnectionID(), event.GetRandomID(), pid, event.DataID(), event.GetFunctionName(),
			event.GetL4PackageCount(), event.GetL4TotalPackageSize(), event.GetSSL(), event.GetProtocol())
		if event.GetProtocol() == enums.ConnectionProtocolUnknown {
			// if the connection protocol is unknown, we just needs to add this into the kernel log
			forwarder.SendTransferNoProtocolEvent(p.context, event)
			return
		}
		connection := p.GetConnectionContext(event.GetConnectionID(), event.GetRandomID(), event.GetProtocol(), event.DataID())
		connection.AppendDetail(p.context, event)
	case *events.SocketDataUploadEvent:
		pid, _ := events.ParseConnectionID(event.ConnectionID)
		log.Debugf("receive the socket data event, connection ID: %d, random ID: %d, pid: %d, prev data id: %d, "+
			"data id: %d, sequence: %d, finished: %t, protocol: %d, size: %d",
			event.ConnectionID, event.RandomID, pid, event.PrevDataID0, event.DataID0, event.Sequence0, event.IsFinished(),
			event.Protocol0, event.BufferLen())
		connection := p.GetConnectionContext(event.ConnectionID, event.RandomID, event.Protocol0, event.DataID0)
		p.AppendAndMaybeAnalyze(connection, event)
	}
}

// AppendAndMaybeAnalyze appends a socket data event to its connection and starts an analysis pass of
// the connections with new data once enough of them are pending. Consumers that receive the events
// themselves (instead of through Consume) call this, so the trigger policy stays in one place.
func (p *PartitionContext) AppendAndMaybeAnalyze(connection *PartitionConnection, data buffer.SocketDataBuffer) {
	connection.AppendData(data)
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
	conKey := p.buildConnectionKey(connectionID, randomID)
	conn, exist := p.connections.Get(conKey)
	if exist {
		connection := conn.(*PartitionConnection)
		connection.appendProtocolIfNeed(p.protocolMgr, connectionID, randomID, protocol, currentDataID)
		return connection
	}
	result := newPartitionConnection(p.protocolMgr, connectionID, randomID, protocol, currentDataID)
	p.connections.Set(conKey, result)
	return result
}

func (p *PartitionContext) buildConnectionKey(conID, ranID uint64) string {
	buf := make([]byte, 0, 42) // 21 + 1 + 21
	buf = strconv.AppendUint(buf, conID, 10)
	buf = append(buf, '_')
	buf = strconv.AppendUint(buf, ranID, 10)
	return string(buf)
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
	p.connections.IterCb(func(_ string, con interface{}) {
		info := con.(*PartitionConnection)
		hasNewData := info.takeDataAppended()
		if !hasNewData && !all {
			return
		}
		p.processConnectionEvents(info)
		if !all {
			return
		}

		// if the connection already closed and not contains any buffer data, then delete the connection
		if info.PendingDataLength() > 0 {
			return
		}
		if !info.closed {
			p.checkTheConnectionIsAlreadyClose(info)
		}
		if info.closed {
			closed = append(closed, info)
			log.Debugf("detect the connection is already closed, then notify to the callback, connection ID: %d, random ID: %d, partition number: %d",
				info.connectionID, info.randomID, p.partitionNum)
		}
	})

	for _, con := range closed {
		p.connections.Remove(p.buildConnectionKey(con.connectionID, con.randomID))
		con.ReleasePendingData()
	}
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

	p.connections.IterCb(func(_ string, con interface{}) {
		p.processConnectionExpireEvents(con.(*PartitionConnection))
	})
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
		return
	}
	helper := &AnalyzeHelper{}

	for _, protocol := range connection.sortedProtocols() {
		analyzer := connection.analyzer(protocol)
		if analyzer == nil {
			continue
		}
		if err := analyzer.Analyze(connection, helper); err != nil {
			log.Warnf("failed to analyze the %s protocol data: %v", enums.ConnectionProtocolString(protocol), err)
		}
	}

	if helper.ProtocolBreak {
		// notify the connection manager to skip analyze all data(just sending the detail)
		connection.skipAllDataAnalyze = true
		p.context.ConnectionMgr.SkipAllDataAnalyzeAndDowngradeProtocol(connection.connectionID, connection.randomID)
		for _, buf := range connection.Buffers() {
			for e := buf.BuildDetails().Front(); e != nil; e = e.Next() {
				forwarder.SendTransferNoProtocolEvent(p.context, e.Value.(events.SocketDetail))
			}
			buf.Clean()
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
