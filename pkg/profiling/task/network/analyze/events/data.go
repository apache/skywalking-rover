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
	"unsafe"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
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
	PrevDataID0  uint64
	TotalSize0   uint64
	// PayloadSkipped is set by the shared upload code (bpf/include/socket_data_event.h), never by the
	// network profiling, which does not follow h2c frames
	PayloadSkipped0 uint8
	Buffer          [20480]byte

	// what the memory protection charged the event for its embedded array (buffer.ChargeEmbeddedEvent), given
	// back on its release
	embeddedCharge int
}

// socketDataUploadEventSize is the size class of the event (the 20KB array embedded), which the memory protection
// charges an event in use
const socketDataUploadEventSize = 21760

var _ = [socketDataUploadEventSize - unsafe.Sizeof(SocketDataUploadEvent{})]struct{}{}

// ReadFrom decodes the event as the network profiling submits it (bpf/include/socket_data_event.h): the BPF side
// sends the header and only the data_len bytes of the buffer that are used (offsetof(buffer) + data_len), so a
// fixed-size decode of the whole struct (binary.Read) fails for every event shorter than the buffer. The fields are
// read in the order of the struct, packed as binary.Read reads them; the buffer bytes behind DataLen keep whatever
// they held.
func (s *SocketDataUploadEvent) ReadFrom(r btf.Reader) {
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
	s.PrevDataID0 = r.ReadUint64()
	s.TotalSize0 = r.ReadUint64()
	s.PayloadSkipped0 = r.ReadUint8()
	if _, sample := r.(*btf.BytesReader); !sample {
		// the reader measures the event once (no sample) to size the records it reads the samples into: the whole
		// array, so a record holds any sample without growing
		r.ReadUint8Array(s.Buffer[:], len(s.Buffer))
		return
	}
	// a real event (admitted by buffer.AcquireEvent): charged its embedded array, once
	if s.embeddedCharge == 0 {
		s.embeddedCharge = buffer.ChargeEmbeddedEvent(socketDataUploadEventSize)
	}
	if int(s.DataLen) > len(s.Buffer) {
		s.DataLen = uint16(len(s.Buffer))
	}
	// a sample shorter than its data_len sets the error of the reader: the event is dropped as a broken one
	r.ReadUint8Array(s.Buffer[:s.DataLen], int(s.DataLen))
}

// Discard gives back what an event the reader does not deliver holds (a broken sample, the sizing event): its
// admission and the charge of its array
func (s *SocketDataUploadEvent) Discard() {
	buffer.ReleaseEvent(s.ReleaseBuffer())
}

// ReleaseBuffer: the array is embedded in the event, there is no separately pooled buffer to give back
// (handing out an interior pointer would put memory of a live event into the pool)
func (s *SocketDataUploadEvent) ReleaseBuffer() []byte {
	// (called once, by the release of the event: the charge of the embedded array goes with it)
	buffer.RefundEmbeddedEvent(s.embeddedCharge)
	s.embeddedCharge = 0
	return nil
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

func (s *SocketDataUploadEvent) PrevDataID() uint64 {
	return s.PrevDataID0
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

type SocketDetailEvent struct {
	ConnectionID     uint64
	RandomID         uint64
	DataID0          uint64
	TotalPackageSize uint64
	IfIndex          uint32
	PackageCount     uint8
	FuncName         enums.SocketFunctionName
	RTTCount         uint8
	Protocol         enums.ConnectionProtocol
	RTTTime          uint32
}

func (s *SocketDetailEvent) Time() uint64 {
	return 0
}

func (s *SocketDetailEvent) DataID() uint64 {
	return s.DataID0
}

func (s *SocketDetailEvent) GenerateConnectionID() string {
	return fmt.Sprintf("%d_%d", s.ConnectionID, s.RandomID)
}
