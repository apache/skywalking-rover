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

package network

import (
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
)

type BufferDirection uint8

var protocolAnalyzers map[base.ConnectionProtocol]ProtocolAnalyzer

var (
	BufferDirectionRequest  BufferDirection = 1
	BufferDirectionResponse                 = 2
)

func init() {
	protocolAnalyzers = make(map[base.ConnectionProtocol]ProtocolAnalyzer)
	protocolAnalyzers[base.ConnectionProtocolHTTP] = NewHTTP1Analyzer()
}

type networkBufferInBPF struct {
	Timestamp  uint64
	ChannelRef uint64
	Protocol   base.ConnectionProtocol
	Direction  BufferDirection
	Size       uint16
	Pid        uint32
	Buffer     [159]byte
}

type networkBufferReader struct {
	notifyFunc func(event BufferEvent)
}

func newNetworkBufferReader(notify func(event BufferEvent)) *networkBufferReader {
	return &networkBufferReader{
		notifyFunc: notify,
	}
}

func (n *networkBufferReader) Read(data interface{}) {
	buffer := data.(*networkBufferInBPF)
	analyzer := protocolAnalyzers[buffer.Protocol]
	if analyzer == nil {
		return
	}

	event := analyzer.HandleBufferEvent(buffer)
	if event != nil {
		n.notifyFunc(event)
	}
}

func (n *networkBufferReader) BufferDataBPFSupplier() interface{} {
	return &networkBufferInBPF{}
}

type ProtocolAnalyzer interface {
	HandleBufferEvent(buffer *networkBufferInBPF) BufferEvent
}
