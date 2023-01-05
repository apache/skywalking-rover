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
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/logger"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
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

	connections       map[connectionKey]*connectionInfo
	analyzeLocker     sync.Mutex
	receiveEventCount int
}

func NewProtocolAnalyzer(protocolContext Context, p Protocol, config *profiling.TaskConfig) *ProtocolAnalyzer {
	return &ProtocolAnalyzer{
		protocolContext: protocolContext,
		protocol:        p,
		config:          config,
		connections:     make(map[connectionKey]*connectionInfo),
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

func (a *ProtocolAnalyzer) ReceiveSocketData(ctx Context, event *SocketDataUploadEvent) {
	connectionID := event.GenerateConnectionID()
	key := connectionKey{connectionID: event.ConnectionID, randomID: event.RandomID}
	connection := a.connections[key]
	if connection == nil {
		connection = newConnectionInfo(a.protocol, ctx, key.connectionID, key.randomID)
		a.connections[key] = connection
	}
	connection.checkConnectionMetrics(ctx)

	log.Debugf("receive connection: %s, dataid: %d, sequence: %d, finished: %d, have reduce after chunk: %t, direction: %s, size: %d, total size: %d",
		connectionID, event.DataID(), event.DataSequence(), event.Finished, event.HaveReduceDataAfterChunk(),
		event.Direction().String(), event.DataLen, event.TotalSize0)

	// insert to the event list
	connection.buffer.appendEvent(event)

	// process the events if reach the receiver counter
	a.receiveEventCount++
	if a.receiveEventCount >= batchReadMinCount {
		a.processEvents()
	}
	a.receiveEventCount = 0
}

// processEvents means analyze the protocol in each connection
func (a *ProtocolAnalyzer) processEvents() {
	// it could be triggered by interval or reach counter
	// if any trigger bean locked, the other one just ignore process
	if !a.analyzeLocker.TryLock() {
		return
	}
	defer a.analyzeLocker.Unlock()

	for _, connection := range a.connections {
		a.processConnectionEvents(connection)
	}
}

// processExpireEvents delete the expired events
func (a *ProtocolAnalyzer) processExpireEvents(expireDuration time.Duration) {
	// the expiry must be mutual exclusion with events processor
	a.analyzeLocker.Lock()
	defer a.analyzeLocker.Unlock()

	for _, connection := range a.connections {
		a.processConnectionExpireEvents(connection, expireDuration)
	}
}

func (a *ProtocolAnalyzer) processConnectionEvents(connection *connectionInfo) {
	// reset the status for prepare reading
	buffer := connection.buffer
	metrics := connection.metrics
	connectionID := connection.connectionID
	buffer.resetForLoopReading()
	// loop to read the protocol data
	for {
		// reset the status of reading
		if !buffer.prepareForReading() {
			log.Debugf("prepare finsihed: event size: %d", buffer.events.Len())
			return
		}

		result := a.protocol.ParseProtocol(connectionID, metrics, buffer)
		finishReading := false
		switch result {
		case ParseResultSuccess:
			finishReading = buffer.removeReadElements()
		case ParseResultSkipPackage:
			finishReading = buffer.skipCurrentElement()
		}

		if finishReading {
			log.Debugf("reading finsihed: event size: %d", buffer.events.Len())
			break
		}
	}
}

func (a *ProtocolAnalyzer) processConnectionExpireEvents(connection *connectionInfo, expireDuration time.Duration) {
	if c := connection.buffer.deleteExpireEvents(expireDuration); c > 0 {
		log.Debugf("total removed %d expired events for %s protocol", c, a.protocol.Protocol().String())
	}
}

func (a *ProtocolAnalyzer) UpdateExtensionConfig(config *profiling.ExtensionConfig) {
	a.protocol.UpdateExtensionConfig(config)
}

type connectionKey struct {
	connectionID uint64
	randomID     uint64
}

type connectionInfo struct {
	connectionID, randomID uint64
	connectionProtocol     base.ConnectionProtocol
	buffer                 *Buffer
	metrics                Metrics
	metricsFromConnection  bool
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
		buffer:                newBuffer(),
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
