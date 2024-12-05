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

package events

import (
	"fmt"

	"github.com/apache/skywalking-rover/pkg/tools/btf/reader"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

type SocketDataUploadEvent struct {
	Protocol0    enums.ConnectionProtocol
	HaveReduce   uint8
	Direction0   enums.SocketDataDirection
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

func (s *SocketDataUploadEvent) ReadFrom(r *reader.Reader) {
	s.Protocol0 = enums.ConnectionProtocol(r.ReadUint8())
	s.HaveReduce = r.ReadUint8()
	s.Direction0 = enums.SocketDataDirection(r.ReadUint8())
	s.Finished = r.ReadUint8()
	s.Sequence0 = r.ReadUint16()
	s.DataLen = r.ReadUint16()
	s.StartTime0 = r.ReadUint64()
	s.EndTime0 = r.ReadUint64()
	s.ConnectionID = r.ReadUint64()
	s.RandomID = r.ReadUint64()
	s.DataID0 = r.ReadUint64()
	s.TotalSize0 = r.ReadUint64()
	r.ReadUint8Array(s.Buffer[:], 2048)
}

func (s *SocketDataUploadEvent) Protocol() enums.ConnectionProtocol {
	return s.Protocol0
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

func (s *SocketDataUploadEvent) Direction() enums.SocketDataDirection {
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
