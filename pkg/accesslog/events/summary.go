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
	"encoding/binary"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// H2CSummary is a summary of the socket calls BPF did not upload because they lie wholly inside the payload of
// a DATA frame (summarize_h2c_payload, skywalking-rover/bpf/accesslog/common/h2c_sum.h): the calls of one
// stream and direction, of one wall clock minute and one function. It comes as a record of a per-CPU batch
// (BPF sent it, Reason one of the SummaryReason* below up to SummaryReasonRekey) or from the map, drained by
// the user space (the other reasons). The bytes it counts the parser already counted, in the gaps in front of
// the positional events (buffer.SummaryGap); the summary gives the kernel log details of its calls to the
// stream's protocol log, as the one detail the merge of the details of its calls gives (DetailTo).
type H2CSummary struct {
	ConnectionID       uint64
	RandomID           uint64
	StreamID           uint32
	Direction0         enums.SocketDataDirection
	Reason             uint8
	Epoch              uint8
	StartTime0         uint64
	EndTime0           uint64
	FirstDataID0       uint64
	LastDataID0        uint64
	Bytes              uint64
	L4TotalPackageSize uint64
	L4PackageCount     uint32
	Calls              uint32
	Minute             uint32
	LocalPort          uint16
	RemotePort         uint16
	FunctionName       uint8
	SSL                uint8
	Gen                uint8
}

// the reasons a summary left the map: BPF sent it (h2c_sum.h H2C_SUM_REASON_*), or the user space drained it
const (
	SummaryReasonEndStream = 1
	SummaryReasonRST       = 2
	SummaryReasonClose     = 3
	SummaryReasonRekey     = 4
	// the epoch flush of the user space
	SummaryReasonFlush = 5
	// drained for a closed connection by the user space
	SummaryReasonCloseDrain = 6
	// drained for a connection the agent does not know
	SummaryReasonStale = 7
	// drained by the parser for a stream that ended (END_STREAM or RST_STREAM it saw)
	SummaryReasonStreamDrain = 8
	SummaryReasons           = 9
)

// the layout of the map key and value and of a summary record (h2c_sum.h)
const (
	SummaryKeySize   = 24
	SummaryValueSize = 72
	batchKindSummary = 3
	// offsets in a summary record of a batch
	sumRecDirection = 1
	sumRecReason    = 2
	sumRecEpoch     = 3
	sumRecStream    = 4
	sumRecConID     = 8
	sumRecRandomID  = 16
	sumRecValue     = 24
)

// DecodeSummaryKey fills the fields of the map key (struct h2c_sum_key_t)
func DecodeSummaryKey(s *H2CSummary, key []byte) {
	s.ConnectionID = binary.LittleEndian.Uint64(key[0:])
	s.RandomID = binary.LittleEndian.Uint64(key[8:])
	s.StreamID = binary.LittleEndian.Uint32(key[16:])
	s.Direction0 = enums.SocketDataDirection(key[20])
	s.Epoch = key[21]
}

// EncodeSummaryKey writes the map key of the summary (struct h2c_sum_key_t) into key, SummaryKeySize bytes
func EncodeSummaryKey(key []byte, connectionID, randomID uint64, stream uint32, direction enums.SocketDataDirection, epoch uint8) {
	clear(key[:SummaryKeySize])
	binary.LittleEndian.PutUint64(key[0:], connectionID)
	binary.LittleEndian.PutUint64(key[8:], randomID)
	binary.LittleEndian.PutUint32(key[16:], stream)
	key[20] = uint8(direction)
	key[21] = epoch
}

// DecodeSummaryValue fills the fields of the map value (struct h2c_sum_value_t)
func DecodeSummaryValue(s *H2CSummary, v []byte) {
	s.StartTime0 = binary.LittleEndian.Uint64(v[0:])
	s.EndTime0 = binary.LittleEndian.Uint64(v[8:])
	s.FirstDataID0 = binary.LittleEndian.Uint64(v[16:])
	s.LastDataID0 = binary.LittleEndian.Uint64(v[24:])
	s.Bytes = binary.LittleEndian.Uint64(v[32:])
	s.L4TotalPackageSize = binary.LittleEndian.Uint64(v[40:])
	s.L4PackageCount = binary.LittleEndian.Uint32(v[48:])
	s.Calls = binary.LittleEndian.Uint32(v[52:])
	s.Minute = binary.LittleEndian.Uint32(v[56:])
	s.LocalPort = binary.LittleEndian.Uint16(v[60:])
	s.RemotePort = binary.LittleEndian.Uint16(v[62:])
	s.FunctionName = v[64]
	s.SSL = v[65]
	s.Gen = v[66]
}

// EncodeSummaryValue writes the map value of the summary (struct h2c_sum_value_t), SummaryValueSize bytes
func EncodeSummaryValue(v []byte, s *H2CSummary) {
	clear(v[:SummaryValueSize])
	binary.LittleEndian.PutUint64(v[0:], s.StartTime0)
	binary.LittleEndian.PutUint64(v[8:], s.EndTime0)
	binary.LittleEndian.PutUint64(v[16:], s.FirstDataID0)
	binary.LittleEndian.PutUint64(v[24:], s.LastDataID0)
	binary.LittleEndian.PutUint64(v[32:], s.Bytes)
	binary.LittleEndian.PutUint64(v[40:], s.L4TotalPackageSize)
	binary.LittleEndian.PutUint32(v[48:], s.L4PackageCount)
	binary.LittleEndian.PutUint32(v[52:], s.Calls)
	binary.LittleEndian.PutUint32(v[56:], s.Minute)
	binary.LittleEndian.PutUint16(v[60:], s.LocalPort)
	binary.LittleEndian.PutUint16(v[62:], s.RemotePort)
	v[64], v[65], v[66] = s.FunctionName, s.SSL, s.Gen
}

// decodeSummaryRecord is the summary of record number i of the batch sample, which must be one
func decodeSummaryRecord(sample []byte, i int) *H2CSummary {
	b := sample[batchHeaderSize+i*batchRecordSize:]
	s := &H2CSummary{
		ConnectionID: binary.LittleEndian.Uint64(b[sumRecConID:]),
		RandomID:     binary.LittleEndian.Uint64(b[sumRecRandomID:]),
		StreamID:     binary.LittleEndian.Uint32(b[sumRecStream:]),
		Direction0:   enums.SocketDataDirection(b[sumRecDirection]),
		Reason:       b[sumRecReason],
		Epoch:        b[sumRecEpoch],
	}
	DecodeSummaryValue(s, b[sumRecValue:sumRecValue+SummaryValueSize])
	return s
}

// SummaryStreamID, SummaryDirection, SummaryBytes and SummaryFirstDataID give the HTTP/2 parser what it
// matches a summary with (protocols.HTTP2Summary)
func (s *H2CSummary) SummaryStreamID() uint32 { return s.StreamID }

func (s *H2CSummary) SummaryDirection() enums.SocketDataDirection { return s.Direction0 }

func (s *H2CSummary) SummaryBytes() uint64 { return s.Bytes }

func (s *H2CSummary) SummaryFirstDataID() uint64 { return s.FirstDataID0 }

// DetailTo fills c with the kernel log detail of the calls of the summary: what merging the details of the
// calls one by one (SocketDataUploadEvent.MergeDetail into the copy of the first, CanMergeDetail holding for
// every one of them: one function, one minute) gives in every field a kernel log is built of: the function,
// the start of the first call, the end of the last, the L4 counters summed, and the data id of the first.
// The rest is what the first call's event carries but its size, which is the bytes of every call.
func (s *H2CSummary) DetailTo(c *SocketDataUploadEvent) {
	*c = SocketDataUploadEvent{
		Protocol0:          enums.ConnectionProtocolHTTP2,
		L4PackageCount:     s.L4PackageCount,
		Finished:           1,
		FunctionName:       uint32(s.FunctionName),
		SSL:                uint32(s.SSL),
		StartTime0:         s.StartTime0,
		EndTime0:           s.EndTime0,
		ConnectionID:       s.ConnectionID,
		RandomID:           s.RandomID,
		DataID0:            s.FirstDataID0,
		TotalSize0:         s.Bytes,
		L4TotalPackageSize: s.L4TotalPackageSize,
		Direction0:         s.Direction0,
		PayloadSkipped0:    1,
		LocalPort:          s.LocalPort,
		RemotePort:         s.RemotePort,
	}
}

// Detail is DetailTo into a new event
func (s *H2CSummary) Detail() *SocketDataUploadEvent {
	c := &SocketDataUploadEvent{}
	s.DetailTo(c)
	return c
}

// DecodeBatchSummary is the summary of record number i of the batch sample, false when the record is not one
func DecodeBatchSummary(sample []byte, i int) (*H2CSummary, bool) {
	if i < 0 || i >= BatchRecordCount(sample) || sample[batchHeaderSize+i*batchRecordSize+recKind] != batchKindSummary {
		return nil, false
	}
	return decodeSummaryRecord(sample, i), true
}
