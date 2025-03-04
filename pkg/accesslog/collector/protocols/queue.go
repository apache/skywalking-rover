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
	"sort"
	"strconv"
	"sync"
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
			return &events.SocketDataUploadEvent{Buffer: *buffer.BorrowNewBuffer()}
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
	context      *common.AccessLogContext
	protocolMgr  *ProtocolManager
	connections  cmap.ConcurrentMap
	partitionNum int

	analyzeLocker sync.Mutex
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
	ctx.ConnectionMgr.RegisterProcessor(pc)
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
			"data id: %d, sequence: %d, protocol: %d",
			event.ConnectionID, event.RandomID, pid, event.PrevDataID0, event.DataID0, event.Sequence0, event.Protocol0)
		connection := p.GetConnectionContext(event.ConnectionID, event.RandomID, event.Protocol0, event.DataID0)
		connection.AppendData(event)
	}
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

func (p *PartitionContext) ProcessEvents() {
	// it could be triggered by interval or reach counter
	// if any trigger bean locked, the other one just ignore process
	if !p.analyzeLocker.TryLock() {
		return
	}
	defer p.analyzeLocker.Unlock()

	closedConnections := make([]string, 0)
	p.connections.IterCb(func(conKey string, con interface{}) {
		info := con.(*PartitionConnection)
		p.processConnectionEvents(info)

		// if the connection already closed and not contains any buffer data, then delete the connection
		var bufLen = 0
		for _, buf := range info.dataBuffers {
			bufLen += buf.DataLength()
		}
		if bufLen > 0 {
			return
		}
		if !info.closed {
			p.checkTheConnectionIsAlreadyClose(info)
		}
		if info.closed {
			closedConnections = append(closedConnections, conKey)
			log.Debugf("detect the connection is already closed, then notify to the callback, connection ID: %d, random ID: %d, partition number: %d",
				info.connectionID, info.randomID, p.partitionNum)
		}
	})

	for _, conKey := range closedConnections {
		p.connections.Remove(conKey)
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
	for _, buf := range connection.dataBuffers {
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

	// since the socket data/detail are getting unsorted, so rover need to using the minimal data id to analyze to ensure the order
	sortedProtocols := make([]enums.ConnectionProtocol, 0, len(connection.protocol))
	for protocol := range connection.protocol {
		sortedProtocols = append(sortedProtocols, protocol)
	}
	sort.Slice(sortedProtocols, func(i, j int) bool {
		return connection.protocol[sortedProtocols[i]] < connection.protocol[sortedProtocols[j]]
	})
	for _, protocol := range sortedProtocols {
		if err := connection.protocolAnalyzer[protocol].Analyze(connection, helper); err != nil {
			log.Warnf("failed to analyze the %s protocol data: %v", enums.ConnectionProtocolString(protocol), err)
		}
	}

	if helper.ProtocolBreak {
		// notify the connection manager to skip analyze all data(just sending the detail)
		connection.skipAllDataAnalyze = true
		p.context.ConnectionMgr.SkipAllDataAnalyzeAndDowngradeProtocol(connection.connectionID, connection.randomID)
		for _, buf := range connection.dataBuffers {
			for e := buf.BuildDetails().Front(); e != nil; e = e.Next() {
				forwarder.SendTransferNoProtocolEvent(p.context, e.Value.(events.SocketDetail))
			}
			buf.Clean()
		}
	}
}
