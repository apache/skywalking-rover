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
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

type PartitionConnection struct {
	connectionID, randomID uint64
	dataBuffer             *buffer.Buffer
	protocol               map[enums.ConnectionProtocol]bool
	protocolAnalyzer       map[enums.ConnectionProtocol]Protocol
	protocolMetrics        map[enums.ConnectionProtocol]ProtocolMetrics
	closed                 bool
	closeCallback          common.ConnectionProcessFinishCallback
	skipAllDataAnalyze     bool
	lastCheckCloseTime     time.Time
}

func (p *PartitionConnection) Metrics(protocol enums.ConnectionProtocol) ProtocolMetrics {
	return p.protocolMetrics[protocol]
}

func (p *PartitionConnection) IsExistProtocol(protocol enums.ConnectionProtocol) bool {
	_, exist := p.protocol[protocol]
	return exist
}

func (p *PartitionConnection) Buffer() *buffer.Buffer {
	return p.dataBuffer
}

func (p *PartitionConnection) AppendDetail(ctx *common.AccessLogContext, detail events.SocketDetail) {
	if p.skipAllDataAnalyze {
		// if the connection is already skip all data analyze, then just send the detail event
		forwarder.SendTransferNoProtocolEvent(ctx, detail)
		return
	}
	p.dataBuffer.AppendDetailEvent(detail)
}

func (p *PartitionConnection) AppendData(data buffer.SocketDataBuffer) {
	if p.skipAllDataAnalyze {
		return
	}
	p.dataBuffer.AppendDataEvent(data)
}
