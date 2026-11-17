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

package analyze

import (
	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

var partitionLog = logger.GetLogger("accesslog", "collector", "protocols", "partition")

type PartitionContext struct {
	// origin partition context
	*protocols.PartitionContext
	alc *common.AccessLogContext
}

func NewPartitionContext(alc *common.AccessLogContext, ctx *protocols.PartitionContext) *PartitionContext {
	return &PartitionContext{PartitionContext: ctx, alc: alc}
}

func (p *PartitionContext) Consume(data interface{}) {
	if record, ok := data.(*events.H2CRecord); ok {
		p.consumeRecord(record)
		return
	}
	if summary, ok := data.(*events.H2CSummary); ok {
		p.consumeSummary(summary)
		return
	}
	event := data.(*events.SocketDataUploadEvent)
	if partitionLog.Enable(logrus.DebugLevel) {
		pid, _ := events.ParseConnectionID(event.ConnectionID)
		partitionLog.Debugf("receive the socket data event, connection ID: %d, random ID: %d, pid: %d, prev data id: %d, "+
			"data id: %d, sequence: %d, protocol: %d, package count: %d, package size: %d, func name: %s",
			event.ConnectionID, event.RandomID, pid, event.PrevDataID0, event.DataID0, event.Sequence0, event.Protocol0,
			event.L4PackageCount, event.L4TotalPackageSize, event.GetFunctionName())
	}
	// if the protocol is unknown, then just sending to the kernel metrics
	if event.Protocol() == enums.ConnectionProtocolUnknown {
		// only the metadata is needed from here on: release the buffer instead of pinning it in the flush
		// queue until the next flush
		// nothing else holds the event: it goes to the queue itself once its buffer is given back
		buffer.ReleaseEvent(event.ReleaseBuffer())
		// the flush owns the event from here on and recycles it once its kernel log is in the batch
		forwarder.SendTransferNoProtocolEventOwned(p.alc, event)
		return
	}
	connection := p.GetConnectionContext(event.ConnectionID, event.RandomID, event.Protocol0, event.DataID0)
	p.AppendAndMaybeAnalyze(connection, event)
}

// consumeRecord appends a record of a batch of HTTP/2 calls (events.SplitH2CBatch) to its connection: what
// Consume does with the event the record stands for, which always has the HTTP/2 protocol
func (p *PartitionContext) consumeRecord(record *events.H2CRecord) {
	if partitionLog.Enable(logrus.DebugLevel) {
		pid, _ := events.ParseConnectionID(record.ConnectionID)
		partitionLog.Debugf("receive the socket data event, connection ID: %d, random ID: %d, pid: %d, prev data id: %d, "+
			"data id: %d, sequence: %d, protocol: %d, package count: %d, package size: %d, func name: %s",
			record.ConnectionID, record.RandomID, pid, record.PrevDataID0, record.DataID0, 0, record.Protocol(),
			record.L4PackageCount, record.L4TotalPackageSize, record.GetFunctionName())
	}
	connection := p.GetConnectionContext(record.ConnectionID, record.RandomID, record.Protocol(), record.DataID0)
	p.AppendAndMaybeAnalyze(connection, record)
}

// consumeSummary hands a summary of skipped DATA payload calls to the HTTP/2 parser of its connection
// (summarize_h2c_payload); a summary of a connection the partition does not have anymore goes as a kernel log
// of its own
func (p *PartitionContext) consumeSummary(summary *events.H2CSummary) {
	connection := p.FindConnectionContext(summary.ConnectionID, summary.RandomID)
	if connection == nil {
		if p.WasRemoved(summary.ConnectionID, summary.RandomID) {
			// the connection is closed and gone: no stream takes the summary anymore, and the connection manager
			// still knows the connection for a while, so the summary goes now
			sendOrphanSummary(p.alc, summary)
			return
		}
		// the summary may come before the first event of its connection (another per-CPU batch): a stream of the
		// connection takes it, or it goes on its own after http2SummaryOrphanAge
		connection = p.GetConnectionContext(summary.ConnectionID, summary.RandomID, enums.ConnectionProtocolHTTP2, summary.FirstDataID0)
	}
	if !protocols.AppendHTTP2Summary(connection, summary) {
		sendOrphanSummary(p.alc, summary)
	}
}
