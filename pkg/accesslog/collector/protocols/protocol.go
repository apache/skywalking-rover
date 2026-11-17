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
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

type ProtocolManager struct {
	protocols map[enums.ConnectionProtocol]Protocol
}

func NewProtocolManager(protocols []Protocol) *ProtocolManager {
	m := make(map[enums.ConnectionProtocol]Protocol)
	for _, protocol := range protocols {
		m[protocol.ForProtocol()] = protocol
	}
	return &ProtocolManager{protocols: m}
}

func (a *ProtocolManager) GetProtocol(protocol enums.ConnectionProtocol) Protocol {
	return a.protocols[protocol]
}

type ProtocolMetrics interface {
}

// PendingDataMetrics is implemented by the metrics of a protocol that keeps socket data events
// outside the connection buffer (the HTTP/2 analyzer re-partitions them per direction), so the queue
// can still see that the connection has unparsed data and release it when the connection is removed
type PendingDataMetrics interface {
	// PendingDataLength is the count of socket data events the metrics still hold
	PendingDataLength() int
	// ReleasePendingData gives the held socket data events back to the pool
	ReleasePendingData()
}

// DataAppendObserver is implemented by the metrics of a protocol that follow the events appended to the
// connection buffer; DataAppended runs after the event was appended
type DataAppendObserver interface {
	DataAppended(data buffer.SocketDataBuffer)
}

// ReleasableMetrics is implemented by the metrics of a protocol that hold something outside the
// connection, released when the connection is removed
type ReleasableMetrics interface {
	Release()
}

type AnalyzeHelper struct {
	ProtocolBreak bool
}

type Protocol interface {
	ForProtocol() enums.ConnectionProtocol
	GenerateConnection(connectionID, randomID uint64) ProtocolMetrics
	Analyze(connection *PartitionConnection, helper *AnalyzeHelper) error
}
