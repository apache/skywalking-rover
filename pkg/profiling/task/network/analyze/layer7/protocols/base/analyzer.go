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

package base

import (
	"context"
	"fmt"
	"sync"
	"time"

	cmap "github.com/orcaman/concurrent-map"

	"github.com/apache/skywalking-rover/pkg/logger"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/buffer"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/enums"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
)

const (
	batchReadMinCount = 1000
)

var log = logger.GetLogger("profiling", "task", "network", "layer7", "protocols", "base")

// ProtocolAnalyzer handler all socket data for each protocol
type ProtocolAnalyzer struct {
	protocolContext Context
	protocol        Protocol
	config          *profiling.TaskConfig

	connections       cmap.ConcurrentMap // connections with concurrent key: connection id+random id, value: *connectionInfo
	analyzeLocker     sync.Mutex
	receiveEventCount int
}

func NewProtocolAnalyzer(protocolContext Context, p Protocol, config *profiling.TaskConfig) *ProtocolAnalyzer {
	return &ProtocolAnalyzer{
		protocolContext: protocolContext,
		protocol:        p,
		config:          config,
		connections:     cmap.New(),
	}
}

func (a *ProtocolAnalyzer) Start(ctx context.Context) {
	duration, _ := time.ParseDuration(a.config.Network.ReportInterval)
	timeTicker := time.NewTicker(duration)
	go func() {
		for {
			select {
			case <-timeTicker.C:
				// process event with interval
				a.processEvents()
			case <-ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()

	// if the protocol defined the events expire time, then check events interval
	expireDuration := a.protocol.PackageMaxExpireDuration()
	if expireDuration.Milliseconds() > 0 {
		expireTicker := time.NewTicker(expireDuration)
		go func() {
			for {
				select {
				case <-expireTicker.C:
					a.processExpireEvents(expireDuration)
				case <-ctx.Done():
					expireTicker.Stop()
					return
				}
			}
		}()
	}
}

func (a *ProtocolAnalyzer) ReceiveSocketDetail(ctx Context, event *events.SocketDetailEvent) {
	connectionID := event.GenerateConnectionID()
	connection := a.getConnection(ctx, event.ConnectionID, event.RandomID)

	log.Debugf("receive detail from connection: %s, dataid: %d", connectionID, event.DataID)
	connection.buffer.AppendDetailEvent(event)
}

func (a *ProtocolAnalyzer) ReceiveSocketData(ctx Context, event *events.SocketDataUploadEvent) {
	connectionID := event.GenerateConnectionID()
	connection := a.getConnection(ctx, event.ConnectionID, event.RandomID)

	log.Debugf("receive data from connection: %s, dataid: %d, sequence: %d, finished: %d, have reduce after chunk: %t, "+
		"direction: %s, size: %d, total size: %d",
		connectionID, event.DataID(), event.DataSequence(), event.Finished, event.HaveReduceDataAfterChunk(),
		event.Direction().String(), event.DataLen, event.TotalSize0)

	// insert to the event list
	connection.buffer.AppendDataEvent(event)

	// process the events if reach the receiver counter
	a.receiveEventCount++
	if a.receiveEventCount >= batchReadMinCount {
		a.processEvents()
	}
	a.receiveEventCount = 0
}

func (a *ProtocolAnalyzer) getConnection(ctx Context, connectionID, randomID uint64) *connectionInfo {
	conKey := a.generateConnectionInfoKey(connectionID, randomID)
	connection, _ := a.connections.Get(conKey)
	if connection == nil {
		connection = newConnectionInfo(a.protocol, ctx, connectionID, randomID)
		a.connections.Set(conKey, connection)
	}
	info := connection.(*connectionInfo)
	info.checkConnectionMetrics(ctx)
	return info
}

// processEvents means analyze the protocol in each connection
func (a *ProtocolAnalyzer) processEvents() {
	// it could be triggered by interval or reach counter
	// if any trigger bean locked, the other one just ignore process
	if !a.analyzeLocker.TryLock() {
		return
	}
	defer a.analyzeLocker.Unlock()

	closedConnections := make([]string, 0)
	a.connections.IterCb(func(conKey string, con interface{}) {
		info := con.(*connectionInfo)
		a.processConnectionEvents(info)

		// if the connection already closed and not contains any buffer data, then delete the connection
		if info.closed && info.buffer.DataLength() == 0 {
			closedConnections = append(closedConnections, conKey)
		}
	})

	for _, conKey := range closedConnections {
		a.connections.Remove(conKey)
	}
}

// processExpireEvents delete the expired events
func (a *ProtocolAnalyzer) processExpireEvents(expireDuration time.Duration) {
	// the expiry must be mutual exclusion with events processor
	a.analyzeLocker.Lock()
	defer a.analyzeLocker.Unlock()

	a.connections.IterCb(func(_ string, con interface{}) {
		a.processConnectionExpireEvents(con.(*connectionInfo), expireDuration)
	})
}

func (a *ProtocolAnalyzer) processConnectionEvents(connection *connectionInfo) {
	// reset the status for prepare reading
	metrics := connection.metrics
	connectionID := connection.connectionID
	connection.buffer.ResetForLoopReading()
	// loop to read the protocol data
	for {
		// reset the status of reading
		if !connection.buffer.PrepareForReading() {
			log.Debugf("prepare finsihed: reduce data event size: %d", connection.buffer.DataLength())
			return
		}

		result := a.protocol.ParseProtocol(connectionID, metrics, connection.buffer)
		finishReading := false
		switch result {
		case enums.ParseResultSuccess:
			finishReading = connection.buffer.RemoveReadElements()
		case enums.ParseResultSkipPackage:
			finishReading = connection.buffer.SkipCurrentElement()
		}

		if finishReading {
			log.Debugf("reading finsihed: reduce data event size: %d", connection.buffer.DataLength())
			break
		}
	}
}

func (a *ProtocolAnalyzer) processConnectionExpireEvents(connection *connectionInfo, expireDuration time.Duration) {
	if c := connection.buffer.DeleteExpireEvents(expireDuration); c > 0 {
		log.Debugf("total removed %d expired events for %s protocol", c, a.protocol.Protocol().String())
	}
}

func (a *ProtocolAnalyzer) UpdateExtensionConfig(config *profiling.ExtensionConfig) {
	a.protocol.UpdateExtensionConfig(config)
}

func (a *ProtocolAnalyzer) ReceiveSocketCloseEvent(event *events.SocketCloseEvent) {
	con, _ := a.connections.Get(a.generateConnectionInfoKey(event.ConID, event.RandomID))
	if con == nil {
		return
	}
	con.(*connectionInfo).closed = true
}

func (a *ProtocolAnalyzer) generateConnectionInfoKey(connectionID, randomID uint64) string {
	return fmt.Sprintf("%d_%d", connectionID, randomID)
}

type connectionInfo struct {
	connectionID, randomID uint64
	connectionProtocol     events.ConnectionProtocol
	buffer                 *buffer.Buffer
	metrics                Metrics
	metricsFromConnection  bool
	closed                 bool
}

func newConnectionInfo(p Protocol, connectionContext Context, connectionID, randomID uint64) *connectionInfo {
	fromConnection := false
	var connectionMetrics Metrics
	con := connectionContext.QueryConnection(connectionID, randomID)
	// if connection not exists, then cached it into the analyzer context
	if con == nil {
		connectionMetrics = p.GenerateMetrics()
	} else {
		connectionMetrics = connectionContext.QueryProtocolMetrics(con.Metrics, p.Protocol())
		fromConnection = true
	}

	return &connectionInfo{
		connectionID:          connectionID,
		randomID:              randomID,
		connectionProtocol:    p.Protocol(),
		buffer:                buffer.NewBuffer(),
		metrics:               connectionMetrics,
		metricsFromConnection: fromConnection,
	}
}

func (c *connectionInfo) checkConnectionMetrics(protocolContext Context) {
	if c.metricsFromConnection {
		return
	}
	connection := protocolContext.QueryConnection(c.connectionID, c.randomID)
	if connection == nil {
		return
	}

	// merge the temporary metrics into the connection metrics
	connectionMetrics := protocolContext.QueryProtocolMetrics(connection.Metrics, c.connectionProtocol)
	connectionMetrics.MergeMetricsFromConnection(connection, c.metrics)
	c.metrics = connectionMetrics
	c.metricsFromConnection = true
}
