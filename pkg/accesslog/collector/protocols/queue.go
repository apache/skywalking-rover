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
}

func NewAnalyzeQueue(ctx *common.AccessLogContext) (*AnalyzeQueue, error) {
	perCPUBufferSize, err := units.RAMInBytes(ctx.Config.ProtocolAnalyze.PerCPUBufferSize)
	if err != nil {
		return nil, err
	}
	if int(perCPUBufferSize) < os.Getpagesize() {
		return nil, fmt.Errorf("the cpu buffer must bigger than %dB", os.Getpagesize())
	}
	if ctx.Config.ProtocolAnalyze.Parallels < 1 {
		return nil, fmt.Errorf("the parallels cannot be small than 1")
	}
	if ctx.Config.ProtocolAnalyze.QueueSize < 1 {
		return nil, fmt.Errorf("the queue size be small than 1")
	}

	return &AnalyzeQueue{
		context:      ctx,
		perCPUBuffer: perCPUBufferSize,
		eventQueue: btf.NewEventQueue(ctx.Config.ProtocolAnalyze.Parallels, ctx.Config.ProtocolAnalyze.QueueSize, func() btf.PartitionContext {
			return NewPartitionContext(ctx)
		}),
	}, nil
}

func (q *AnalyzeQueue) Start(ctx context.Context) {
	q.eventQueue.RegisterReceiver(q.context.BPF.SocketDetailDataQueue, int(q.perCPUBuffer), func() interface{} {
		return &events.SocketDetailEvent{}
	}, func(data interface{}) string {
		return fmt.Sprintf("%d", data.(*events.SocketDetailEvent).GetConnectionID())
	})
	q.eventQueue.RegisterReceiver(q.context.BPF.SocketDataUploadEventQueue, int(q.perCPUBuffer), func() interface{} {
		return &events.SocketDataUploadEvent{}
	}, func(data interface{}) string {
		return fmt.Sprintf("%d", data.(*events.SocketDataUploadEvent).ConnectionID)
	})

	q.eventQueue.Start(ctx, q.context.BPF.Linker)
}

type PartitionContext struct {
	context     *common.AccessLogContext
	protocolMgr *ProtocolManager
	connections cmap.ConcurrentMap

	analyzeLocker sync.Mutex
}

func newPartitionConnection(protocolMgr *ProtocolManager, conID, randomID uint64, protocol enums.ConnectionProtocol) *PartitionConnection {
	analyzer := protocolMgr.GetProtocol(protocol)
	return &PartitionConnection{
		connectionID:     conID,
		randomID:         randomID,
		dataBuffer:       buffer.NewBuffer(),
		protocol:         protocol,
		protocolAnalyzer: analyzer,
		protocolMetrics:  analyzer.GenerateConnection(conID, randomID),
	}
}

func NewPartitionContext(ctx *common.AccessLogContext) *PartitionContext {
	pc := &PartitionContext{
		context:     ctx,
		protocolMgr: NewProtocolManager(ctx),
		connections: cmap.New(),
	}
	ctx.ConnectionMgr.RegisterProcessor(pc)
	return pc
}

func (p *PartitionContext) OnConnectionClose(event *events.SocketCloseEvent, closeCallback common.ConnectionProcessFinishCallback) {
	conn, exist := p.connections.Get(p.buildConnectionKey(event.GetConnectionID(), event.GetRandomID()))
	if !exist {
		closeCallback()
		return
	}
	connection := conn.(*PartitionConnection)
	connection.closeCallback = closeCallback
	connection.closed = true
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
				p.processEvents()
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
				p.processExpireEvents()
			case <-ctx.Done():
				expireTicker.Stop()
				return
			}
		}
	}()
}

func (p *PartitionContext) Consume(data interface{}) {
	switch event := data.(type) {
	case *events.SocketDetailEvent:
		pid, _ := events.ParseConnectionID(event.ConnectionID)
		log.Debugf("receive the socket detail event, connection ID: %d, random ID: %d, pid: %d, data id: %d, "+
			"function name: %s, package count: %d, package size: %d, l4 duration: %d",
			event.ConnectionID, event.RandomID, pid, event.DataID0, event.FunctionName,
			event.L4PackageCount, event.L4TotalPackageSize, event.L4Duration)
		if event.Protocol == enums.ConnectionProtocolUnknown {
			// if the connection protocol is unknown, we just needs to add this into the kernel log
			forwarder.SendTransferNoProtocolEvent(p.context, event)
			return
		}
		connection := p.getConnectionContext(event.GetConnectionID(), event.GetRandomID(), event.Protocol)
		connection.appendDetail(p.context, event)
	case *events.SocketDataUploadEvent:
		pid, _ := events.ParseConnectionID(event.ConnectionID)
		log.Debugf("receive the socket data event, connection ID: %d, random ID: %d, pid: %d, data id: %d, sequence: %d, protocol: %d",
			event.ConnectionID, event.RandomID, pid, event.DataID0, event.Sequence0, event.Protocol)
		connection := p.getConnectionContext(event.ConnectionID, event.RandomID, event.Protocol)
		connection.appendData(event)
	}
}

func (p *PartitionContext) getConnectionContext(connectionID, randomID uint64, protocol enums.ConnectionProtocol) *PartitionConnection {
	conKey := p.buildConnectionKey(connectionID, randomID)
	conn, exist := p.connections.Get(conKey)
	if exist {
		return conn.(*PartitionConnection)
	}
	result := newPartitionConnection(p.protocolMgr, connectionID, randomID, protocol)
	p.connections.Set(conKey, result)
	return result
}

func (p *PartitionContext) buildConnectionKey(conID, ranID uint64) string {
	return fmt.Sprintf("%d_%d", conID, ranID)
}

func (p *PartitionContext) processEvents() {
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
		bufLen := info.dataBuffer.DataLength()
		if bufLen > 0 {
			return
		}
		if !info.closed {
			p.checkTheConnectionIsAlreadyClose(info)
		}
		if info.closed {
			if info.closeCallback != nil {
				info.closeCallback()
			}
			closedConnections = append(closedConnections, conKey)
		}
	})

	for _, conKey := range closedConnections {
		p.connections.Remove(conKey)
	}
}

func (p *PartitionContext) checkTheConnectionIsAlreadyClose(con *PartitionConnection) {
	if time.Now().Sub(con.lastCheckCloseTime) <= time.Second*30 {
		return
	}
	con.lastCheckCloseTime = time.Now()
	var activateConn common.ActiveConnection
	if err := p.context.BPF.ActiveConnectionMap.Lookup(con.connectionID, &activateConn); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			con.closed = true
			return
		}
		log.Warnf("cannot found the active connection: %d-%d, err: %v", con.connectionID, con.randomID, err)
		return
	} else if activateConn.RandomID != 0 && activateConn.RandomID != con.randomID {
		log.Debugf("detect the connection: %d-%d is already closed, so remove from the activate connection",
			con.connectionID, con.randomID)
		con.closed = true
	}
}

func (p *PartitionContext) processExpireEvents() {
	// the expiry must be mutual exclusion with events processor
	p.analyzeLocker.Lock()
	defer p.analyzeLocker.Unlock()

	p.connections.IterCb(func(_ string, con interface{}) {
		p.processConnectionExpireEvents(con.(*PartitionConnection))
	})
}

func (p *PartitionContext) processConnectionExpireEvents(connection *PartitionConnection) {
	if c := connection.dataBuffer.DeleteExpireEvents(maxBufferExpireDuration); c > 0 {
		log.Debugf("total removed %d expired socket data events", c)
	}
}

func (p *PartitionContext) processConnectionEvents(connection *PartitionConnection) {
	if connection.skipAllDataAnalyze {
		return
	}
	helper := &AnalyzeHelper{}
	if err := connection.protocolAnalyzer.Analyze(connection.protocolMetrics, connection.dataBuffer, helper); err != nil {
		log.Warnf("failed to analyze the %s protocol data: %v", connection.protocol.String(), err)
	}

	if helper.ProtocolBreak {
		// notify the connection manager to skip analyze all data(just sending the detail)
		connection.skipAllDataAnalyze = true
		p.context.ConnectionMgr.SkipAllDataAnalyze(connection.connectionID, connection.randomID)
		connection.dataBuffer.Clean()
	}
}

type PartitionConnection struct {
	connectionID, randomID uint64
	dataBuffer             *buffer.Buffer
	protocol               enums.ConnectionProtocol
	protocolAnalyzer       Protocol
	protocolMetrics        ProtocolMetrics
	closed                 bool
	closeCallback          common.ConnectionProcessFinishCallback
	skipAllDataAnalyze     bool
	lastCheckCloseTime     time.Time
}

func (p *PartitionConnection) appendDetail(ctx *common.AccessLogContext, detail *events.SocketDetailEvent) {
	if p.skipAllDataAnalyze {
		// if the connection is already skip all data analyze, then just send the detail event
		forwarder.SendTransferNoProtocolEvent(ctx, detail)
		return
	}
	p.dataBuffer.AppendDetailEvent(detail)
}

func (p *PartitionConnection) appendData(data buffer.SocketDataBuffer) {
	if p.skipAllDataAnalyze {
		return
	}
	p.dataBuffer.AppendDataEvent(data)
}
