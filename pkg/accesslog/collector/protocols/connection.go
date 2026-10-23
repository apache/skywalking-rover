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
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

type PartitionConnection struct {
	// protocolLocker guards the four protocol maps below: they are written by the partition goroutine
	// (a new protocol on an existing connection, a smaller data id) while the analyzer goroutine reads
	// and iterates them, which the Go runtime aborts the process for ("concurrent map iteration and
	// map write")
	protocolLocker         sync.RWMutex
	connectionID, randomID uint64
	dataBuffers            map[enums.ConnectionProtocol]*buffer.Buffer
	protocol               map[enums.ConnectionProtocol]uint64 // protocol with minimal data id
	protocolAnalyzer       map[enums.ConnectionProtocol]Protocol
	protocolMetrics        map[enums.ConnectionProtocol]ProtocolMetrics
	closed                 bool
	skipAllDataAnalyze     bool
	lastCheckCloseTime     time.Time
	// dataAppended records that the connection received data since the last analysis pass, so a pass
	// triggered by the event counter of a busy connection does not re-analyze every idle connection
	dataAppended atomic.Bool
}

func (p *PartitionConnection) Metrics(protocol enums.ConnectionProtocol) ProtocolMetrics {
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	return p.protocolMetrics[protocol]
}

func (p *PartitionConnection) IsExistProtocol(protocol enums.ConnectionProtocol) bool {
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	_, exist := p.protocol[protocol]
	return exist
}

func (p *PartitionConnection) Buffer(protocol enums.ConnectionProtocol) *buffer.Buffer {
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	return p.dataBuffers[protocol]
}

// Buffers returns a snapshot of the data buffers of every protocol of the connection, so the caller
// can iterate them without holding the lock while analyzing
func (p *PartitionConnection) Buffers() []*buffer.Buffer {
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	result := make([]*buffer.Buffer, 0, len(p.dataBuffers))
	for _, buf := range p.dataBuffers {
		result = append(result, buf)
	}
	return result
}

// sortedProtocols returns the protocols of the connection ordered by their minimal data id, together
// with their analyzer and metrics; a snapshot, so the maps are not iterated outside the lock
func (p *PartitionConnection) sortedProtocols() []enums.ConnectionProtocol {
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	// since the socket data/detail are getting unsorted, so rover need to using the minimal data id to analyze to ensure the order
	result := make([]enums.ConnectionProtocol, 0, len(p.protocol))
	for protocol := range p.protocol {
		result = append(result, protocol)
	}
	if len(result) > 1 {
		sort.Slice(result, func(i, j int) bool {
			return p.protocol[result[i]] < p.protocol[result[j]]
		})
	}
	return result
}

func (p *PartitionConnection) analyzer(protocol enums.ConnectionProtocol) Protocol {
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	return p.protocolAnalyzer[protocol]
}

func (p *PartitionConnection) AppendDetail(ctx *common.AccessLogContext, detail events.SocketDetail) {
	if p.skipAllDataAnalyze {
		// if the connection is already skip all data analyze, then just send the detail event
		forwarder.SendTransferNoProtocolEvent(ctx, detail)
		return
	}
	buf := p.Buffer(detail.GetProtocol())
	if buf == nil {
		// no analyzer owns this protocol: the detail is dropped here, so anything it holds has to be
		// given back rather than left to the garbage collector
		releaseDroppedEvent(detail)
		return
	}
	buf.AppendDetailEvent(detail)
	p.markDataAppended()
}

func (p *PartitionConnection) AppendData(data buffer.SocketDataBuffer) {
	if p.skipAllDataAnalyze || p.Buffer(data.Protocol()) == nil {
		// the connection is no longer analyzed, or no analyzer owns this protocol: either way the
		// event is dropped here and its buffer must go back to the pool
		buffer.ReleaseEvent(data.ReleaseBuffer())
		return
	}
	p.Buffer(data.Protocol()).AppendDataEvent(data)
	p.markDataAppended()
}

// releaseDroppedEvent gives back the buffer of an event that is dropped before it reaches a buffer.
// A detail that carries no buffer (the kernel detail events of the rover itself) releases nothing.
func releaseDroppedEvent(event interface{}) {
	if holder, ok := event.(buffer.SocketDataBuffer); ok {
		buffer.ReleaseEvent(holder.ReleaseBuffer())
	}
}

// markDataAppended records that the connection received data since the last analysis pass
func (p *PartitionConnection) markDataAppended() {
	p.dataAppended.Store(true)
}

// takeDataAppended reports whether the connection received data since the last analysis pass and
// clears the flag
func (p *PartitionConnection) takeDataAppended() bool {
	return p.dataAppended.Swap(false)
}

// PendingDataLength is the count of data events the connection still holds: the events in the
// protocol buffers plus the events an analyzer moved into its own buffers (the HTTP/2 analyzer
// re-partitions them per direction), so a connection with unparsed data is never treated as empty
func (p *PartitionConnection) PendingDataLength() int {
	var result int
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	for protocol, buf := range p.dataBuffers {
		result += buf.DataLength()
		if m, ok := p.protocolMetrics[protocol].(PendingDataMetrics); ok {
			result += m.PendingDataLength()
		}
	}
	return result
}

// ReleasePendingData gives every socket data event the connection still holds back to the pool, so
// removing a connection with unparsed data does not leak the in-use accounting
func (p *PartitionConnection) ReleasePendingData() {
	p.protocolLocker.RLock()
	defer p.protocolLocker.RUnlock()
	for protocol, buf := range p.dataBuffers {
		buf.ReleaseAll()
		if m, ok := p.protocolMetrics[protocol].(PendingDataMetrics); ok {
			m.ReleasePendingData()
		}
	}
}
