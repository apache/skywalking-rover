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
	"fmt"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
)

type SocketDataBuffer interface {
	// BufferData of the buffer
	BufferData() []byte
	// TotalSize of socket data, the data may exceed the size of the BufferData()
	TotalSize() uint64
	// Direction of the data, send or receive
	Direction() base.SocketDataDirection
	// BufferStartPosition the buffer start index
	BufferStartPosition() int
	// BufferLen the buffer data length
	BufferLen() int
	// DataID data id of the buffer
	DataID() uint64
	// DataSequence the data sequence under same data id
	DataSequence() int
	// IsStart this buffer is start of the same data id
	IsStart() bool
	// IsFinished this buffer is finish of the same data id
	IsFinished() bool
	// HaveReduceDataAfterChunk check have reduced data after current buffer
	HaveReduceDataAfterChunk() bool

	// StartTime the data start timestamp
	StartTime() uint64
	// EndTime the data end timestamp
	EndTime() uint64
}

type SocketDataUploadEvent struct {
	Protocol     base.ConnectionProtocol
	HaveReduce   uint8
	Direction0   base.SocketDataDirection
	Finished     uint8
	Sequence0    uint16
	DataLen      uint16
	StartTime0   uint64
	EndTime0     uint64
	ConnectionID uint64
	RandomID     uint64
	DataID0      uint64
	TotalSize0   uint64
	Buffer       [2048]byte
}

func (s *SocketDataUploadEvent) GenerateConnectionID() string {
	return fmt.Sprintf("%d_%d", s.ConnectionID, s.RandomID)
}

func (s *SocketDataUploadEvent) BufferData() []byte {
	return s.Buffer[:s.DataLen]
}

func (s *SocketDataUploadEvent) BufferLen() int {
	return int(s.DataLen)
}

func (s *SocketDataUploadEvent) StartTime() uint64 {
	return s.StartTime0
}

func (s *SocketDataUploadEvent) EndTime() uint64 {
	return s.EndTime0
}

func (s *SocketDataUploadEvent) Direction() base.SocketDataDirection {
	return s.Direction0
}

func (s *SocketDataUploadEvent) IsStart() bool {
	return s.Sequence0 == 0
}

func (s *SocketDataUploadEvent) IsFinished() bool {
	return s.Finished == 1
}

func (s *SocketDataUploadEvent) DataID() uint64 {
	return s.DataID0
}

func (s *SocketDataUploadEvent) DataSequence() int {
	return int(s.Sequence0)
}

func (s *SocketDataUploadEvent) BufferStartPosition() int {
	return 0
}

func (s *SocketDataUploadEvent) TotalSize() uint64 {
	return s.TotalSize0
}

func (s *SocketDataUploadEvent) HaveReduceDataAfterChunk() bool {
	return s.HaveReduce == 1
}

type SocketDataEventLimited struct {
	SocketDataBuffer
	from int
	size int
}

func (s *SocketDataEventLimited) BufferData() []byte {
	return s.SocketDataBuffer.BufferData()[s.from:s.size]
}

func (s *SocketDataEventLimited) BufferLen() int {
	return s.size - s.from
}

func (s *SocketDataEventLimited) BufferStartPosition() int {
	return s.from
}

type SocketDetailEvent struct {
	ConnectionID     uint64
	RandomID         uint64
	DataID           uint64
	TotalPackageSize uint64
	IfIndex          uint32
	PackageCount     uint8
	FuncName         base.SocketFunctionName
	RTTCount         uint8
	Protocol         base.ConnectionProtocol
	RTTTime          uint64
}

func (s *SocketDetailEvent) GenerateConnectionID() string {
	return fmt.Sprintf("%d_%d", s.ConnectionID, s.RandomID)
}
