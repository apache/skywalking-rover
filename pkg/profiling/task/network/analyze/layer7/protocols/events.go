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
	"fmt"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
)

type SocketDataBuffer interface {
	// Combine from other buffer
	Combine(buffered SocketDataBuffer) SocketDataBuffer
	// BufferData of the buffer
	BufferData() []byte
	// TotalSize of socket data, the data may exceed the size of the BufferData()
	TotalSize() uint64
	// Time of socket data send
	Time() uint64
	// Direction of the data, send or receive
	Direction() base.SocketDataDirection
	FirstEvent() *SocketDataUploadEvent

	MinDataID() int
	MaxDataID() int
}

type SocketDataUploadEvent struct {
	Protocol     base.ConnectionProtocol
	MsgType      base.SocketMessageType
	Direction0   base.SocketDataDirection
	Finished     uint8
	Sequence     uint16
	DataLen      uint16
	Timestamp    uint64
	ConnectionID uint64
	RandomID     uint64
	DataID       uint64
	TotalSize0   uint64
	Buffer       [2048]byte
}

func (s *SocketDataUploadEvent) GenerateConnectionID() string {
	return fmt.Sprintf("%d_%d", s.ConnectionID, s.RandomID)
}

func (s *SocketDataUploadEvent) BufferData() []byte {
	return s.Buffer[:s.DataLen]
}

func (s *SocketDataUploadEvent) Time() uint64 {
	return s.Timestamp
}

func (s *SocketDataUploadEvent) Direction() base.SocketDataDirection {
	return s.Direction0
}

func (s *SocketDataUploadEvent) FirstEvent() *SocketDataUploadEvent {
	return s
}

func (s *SocketDataUploadEvent) MinDataID() int {
	return int(s.DataID)
}

func (s *SocketDataUploadEvent) MaxDataID() int {
	return int(s.DataID)
}

func (s *SocketDataUploadEvent) IsStart() bool {
	return s.Sequence == 0
}

func (s *SocketDataUploadEvent) IsFinished() bool {
	return s.Finished == 1
}

func (s *SocketDataUploadEvent) Combine(other SocketDataBuffer) SocketDataBuffer {
	combined := &SocketDataUploadCombinedEvent{first: s}
	combined.realBuffer = append(s.Buffer[:s.DataLen], other.BufferData()...)
	combined.minDataID = int(s.DataID)
	if other.MinDataID() < combined.minDataID {
		combined.minDataID = other.MinDataID()
	}
	combined.maxDataID = int(s.DataID)
	if other.MaxDataID() > combined.maxDataID {
		combined.maxDataID = other.MaxDataID()
	}
	return combined
}

func (s *SocketDataUploadEvent) TotalSize() uint64 {
	return s.TotalSize0
}

type SocketDataUploadCombinedEvent struct {
	first      *SocketDataUploadEvent
	realBuffer []byte
	minDataID  int
	maxDataID  int
}

func (s *SocketDataUploadCombinedEvent) BufferData() []byte {
	return s.realBuffer
}

func (s *SocketDataUploadCombinedEvent) TotalSize() uint64 {
	return s.first.TotalSize0
}

func (s *SocketDataUploadCombinedEvent) Time() uint64 {
	return s.first.Timestamp
}

func (s *SocketDataUploadCombinedEvent) MinDataID() int {
	return s.minDataID
}

func (s *SocketDataUploadCombinedEvent) MaxDataID() int {
	return s.maxDataID
}

func (s *SocketDataUploadCombinedEvent) Direction() base.SocketDataDirection {
	return s.first.Direction0
}

func (s *SocketDataUploadCombinedEvent) FirstEvent() *SocketDataUploadEvent {
	return s.first
}

func (s *SocketDataUploadCombinedEvent) Combine(other SocketDataBuffer) SocketDataBuffer {
	s.realBuffer = append(s.realBuffer, other.BufferData()...)
	if other.MinDataID() < s.minDataID {
		s.minDataID = other.MinDataID()
	}
	if other.MaxDataID() > s.maxDataID {
		s.maxDataID = other.MaxDataID()
	}
	return s
}
