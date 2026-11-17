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
	"sync/atomic"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

// Per-CPU batch of compact HTTP/2 DATA call records (bpf/accesslog/common/h2c_batch.h). When BPF batches
// the skipped and tail-cut calls of followed HTTP/2 connections, it sends one perf event that holds several
// records instead of one event per call. Each record carries exactly the fields the event it replaces would
// carry. The splitter keeps every record as a compact H2CRecord (record.go, buffer.CompactRecord), which answers every question
// the parser, the buffers and the kernel logs ask as that event would, so the existing kernel-log merge does
// all the merging and the output is byte-identical to the per-call events, without a full event per call.
// The wire layout below mirrors the C structs; the kernel tests check its size against the loaded object's map.

// BatchMarker is the first byte of a batch perf event, where a socket data upload event has its protocol.
// A real event's protocol is an enums.ConnectionProtocol, never this value.
const BatchMarker = 0xBA

// BatchRecordSize and BatchMaxRecords mirror the BPF structs (bpf/accesslog/common/h2c_batch.h); the
// kernel tests check them against the loaded object's map so a layout drift is caught.
const BatchRecordSize = 112
const BatchMaxRecords = 64

const (
	batchHeaderSize = 8 // marker(1) + pad(3) + count(4)
	batchCountOff   = 4

	batchRecordSize = BatchRecordSize
	// offsets inside one record
	recKind       = 0
	recDirection  = 1
	recCutLen     = 2
	recStartTime  = 8
	recEndTime    = 16
	recConID      = 24
	recRandomID   = 32
	recDataID     = 40
	recPrevDataID = 48
	recTotalSize  = 56
	recExt        = 64
	recCutBuf     = 96
	batchCutMax   = 16
	batchKindSkip = 1
	batchKindCut  = 2
	// offsets inside the upload_data_args_ext at recExt
	extL4Size     = 0
	extLocalPort  = 8
	extRemotePt   = 10
	extL4Count    = 12
	extFuncName   = 13
	extSSL        = 14
	extInFlight   = 16
	extSumBefore  = 20
	extH2CFrames  = 15
	extSumStream  = 24
	extSumFrames  = 28
	extFirstFrame = 30
)

// IsBatchRecord tells whether a raw perf sample is a batch of compact records rather than a socket data
// upload event, by the marker byte.
func IsBatchRecord(sample []byte) bool {
	return len(sample) >= batchHeaderSize && sample[0] == BatchMarker
}

// BatchRecordCount is the number of records a batch sample claims to hold (bounded by what fits the sample).
func BatchRecordCount(sample []byte) int {
	if !IsBatchRecord(sample) {
		return 0
	}
	count := int(binary.LittleEndian.Uint32(sample[batchCountOff:]))
	fit := (len(sample) - batchHeaderSize) / batchRecordSize
	if count > fit {
		count = fit
	}
	if count < 0 {
		count = 0
	}
	return count
}

// DecodeBatchRecordInto fills event from record number i of the batch sample, reconstructing the socket data
// upload event that BPF would have sent for that call without batching. It returns false when i is out of
// range. The buffer (for a tail-cut record) is taken from cutBuf, which the caller owns; pass nil to let the
// event keep no buffer (cut records then report their length with no bytes, which a reader fills itself).
func DecodeBatchRecordInto(event *SocketDataUploadEvent, sample []byte, i int, cutBuf []byte) bool {
	if i < 0 || i >= BatchRecordCount(sample) {
		return false
	}
	r := sample[batchHeaderSize+i*batchRecordSize:]
	*event = SocketDataUploadEvent{}
	event.Protocol0 = enums.ConnectionProtocolHTTP2
	event.Direction0 = enums.SocketDataDirection(r[recDirection])
	event.StartTime0 = binary.LittleEndian.Uint64(r[recStartTime:])
	event.EndTime0 = binary.LittleEndian.Uint64(r[recEndTime:])
	event.ConnectionID = binary.LittleEndian.Uint64(r[recConID:])
	event.RandomID = binary.LittleEndian.Uint64(r[recRandomID:])
	event.DataID0 = binary.LittleEndian.Uint64(r[recDataID:])
	event.PrevDataID0 = binary.LittleEndian.Uint64(r[recPrevDataID:])
	event.TotalSize0 = binary.LittleEndian.Uint64(r[recTotalSize:])
	event.Finished = 1
	event.Sequence0 = 0

	ext := r[recExt:]
	event.L4TotalPackageSize = binary.LittleEndian.Uint64(ext[extL4Size:])
	event.LocalPort = binary.LittleEndian.Uint16(ext[extLocalPort:])
	event.RemotePort = binary.LittleEndian.Uint16(ext[extRemotePt:])
	event.L4PackageCount = uint32(ext[extL4Count])
	event.FunctionName = uint32(ext[extFuncName])
	event.SSL = uint32(ext[extSSL])
	event.InFlight = binary.LittleEndian.Uint16(ext[extInFlight:])
	event.SumBefore = binary.LittleEndian.Uint32(ext[extSumBefore:])
	event.SumStream = binary.LittleEndian.Uint32(ext[extSumStream:])
	event.SumFrames = binary.LittleEndian.Uint16(ext[extSumFrames:])
	event.H2CFrames0 = ext[extH2CFrames]
	event.FirstFrameOff = binary.LittleEndian.Uint16(ext[extFirstFrame:])
	if event.H2CFrames0&buffer.H2CFramesKnown == 0 {
		// (nothing known: no offset, as the compact record gives it)
		event.FirstFrameOff = 0xffff
	}

	switch r[recKind] {
	case batchKindSkip:
		// a call wholly inside a DATA payload: an event without content that counts its size
		event.PayloadSkipped0 = 1
		event.HaveReduce = 0
		event.DataLen = 0
	case batchKindCut:
		// a tail-cut call: the bytes before the DATA payload are its content, cut there
		cutLen := int(r[recCutLen])
		if cutLen > batchCutMax {
			cutLen = batchCutMax
		}
		event.PayloadSkipped0 = 0
		event.HaveReduce = 1
		event.DataLen = uint16(cutLen)
		if cutBuf != nil && cap(cutBuf) >= cutLen {
			cutBuf = cutBuf[:cutLen]
			copy(cutBuf, r[recCutBuf:recCutBuf+cutLen])
			event.Buffer = cutBuf
		} else {
			b := make([]byte, cutLen)
			copy(b, r[recCutBuf:recCutBuf+cutLen])
			event.Buffer = b
		}
	default:
		return false
	}
	return true
}

// DecodeBatchRecord fills the event from record i of the batch sample, as DecodeBatchRecordInto does, with the
// bytes of a tail-cut record kept in the event itself (at most 16, which the inline array holds), so the
// record takes no buffer from the pool. It counts the event in the socket data event size metric like
// ReadFrom does.
func (s *SocketDataUploadEvent) DecodeBatchRecord(sample []byte, i int) bool {
	if !DecodeBatchRecordInto(s, sample, i, s.inline[:]) {
		return false
	}
	recordEventSize(s.Protocol0, s.Direction0, int(s.DataLen))
	return true
}

// UploadSampleSize is the size BatchRecordAsUploadSample needs: the header of a socket data upload event
// (the offset of its buffer) and the bytes of a tail-cut record behind it
const UploadSampleSize = uploadDataOffset + batchCutMax

// uploadDataOffset is where the data of a raw socket data upload event starts (the buffer of
// socket_data_upload_event, bpf/accesslog/include/socket_data_event.h)
const uploadDataOffset = 100

// BatchRecordAsUploadSample writes record i of the batch sample into dst in the layout of a raw socket data
// upload event (the one ReadFrom reads), so the observers of the samples the memory protection refused,
// which read a raw event by its offsets, see a refused batch record as the event it stands for. dst must
// hold UploadSampleSize bytes; the result is a slice of it, nil when i is out of range.
func BatchRecordAsUploadSample(sample []byte, i int, dst []byte) []byte {
	var e SocketDataUploadEvent
	if len(dst) < UploadSampleSize || !DecodeBatchRecordInto(&e, sample, i, e.inline[:]) {
		return nil
	}
	out := dst[:uploadDataOffset+int(e.DataLen)]
	clear(out)
	out[0] = uint8(e.Protocol0)
	out[1] = e.HaveReduce
	out[2] = uint8(e.L4PackageCount)
	out[3] = e.Finished
	binary.LittleEndian.PutUint16(out[4:], e.Sequence0)
	binary.LittleEndian.PutUint16(out[6:], e.DataLen)
	binary.LittleEndian.PutUint32(out[8:], e.FunctionName)
	out[12] = uint8(e.SSL)
	out[13] = e.H2CFrames0
	binary.LittleEndian.PutUint16(out[14:], e.InFlight)
	binary.LittleEndian.PutUint64(out[16:], e.StartTime0)
	binary.LittleEndian.PutUint64(out[24:], e.EndTime0)
	binary.LittleEndian.PutUint64(out[32:], e.ConnectionID)
	binary.LittleEndian.PutUint64(out[40:], e.RandomID)
	binary.LittleEndian.PutUint64(out[48:], e.DataID0)
	binary.LittleEndian.PutUint64(out[56:], e.PrevDataID0)
	binary.LittleEndian.PutUint64(out[64:], e.TotalSize0)
	binary.LittleEndian.PutUint64(out[72:], e.L4TotalPackageSize)
	out[80] = uint8(e.Direction0)
	out[81] = e.PayloadSkipped0
	binary.LittleEndian.PutUint16(out[82:], e.LocalPort)
	binary.LittleEndian.PutUint16(out[84:], e.RemotePort)
	binary.LittleEndian.PutUint32(out[88:], e.SumBefore)
	binary.LittleEndian.PutUint32(out[92:], e.SumStream)
	binary.LittleEndian.PutUint16(out[96:], e.SumFrames)
	binary.LittleEndian.PutUint16(out[98:], e.FirstFrameOff)
	copy(out[uploadDataOffset:], e.BufferData())
	return out
}

// The batching metrics: the perf events the socket data queue delivers (a batch counts once, so the rate
// shows what batching saves on the ring), the batches, and the records each carries.
var (
	socketDataPerfEvents atomic.Int64
	h2cBatches           atomic.Int64
	// h2cUnknownRecords are the records of a kind this agent does not know (a BPF side newer than the agent): lost
	h2cUnknownRecords atomic.Int64
	h2cBatchRecords   = telemetry.NewHistogram("rover_h2c_batch_records",
		"Socket call records carried by each per-CPU batch of skipped and tail-cut HTTP/2 calls",
		[]int64{1, 2, 4, 8, 16, 32, 48, 64})
)

func init() {
	telemetry.Register("rover_socket_data_perf_events_total",
		"Perf events read from the socket data queue (a batch of HTTP/2 call records counts once)",
		telemetry.Counter, func() float64 { return float64(socketDataPerfEvents.Load()) })
	telemetry.Register("rover_h2c_batches_total",
		"Per-CPU batches of skipped and tail-cut HTTP/2 call records read from the socket data queue",
		telemetry.Counter, func() float64 { return float64(h2cBatches.Load()) })
	telemetry.Register("rover_h2c_batch_unknown_records_total",
		"Records of an unknown kind in the per-CPU batches of HTTP/2 call records, which are lost",
		telemetry.Counter, func() float64 { return float64(h2cUnknownRecords.Load()) })
}

// CountPerfEvent counts one perf event of the socket data queue
func CountPerfEvent() {
	socketDataPerfEvents.Add(1)
}

// CountBatch counts one batch perf event and the records it carries
func CountBatch(records int) {
	socketDataPerfEvents.Add(1)
	h2cBatches.Add(1)
	h2cBatchRecords.Observe(int64(records))
}

// SplitH2CBatch is the reader's batch splitter for the socket data queue (btf.SetBatchSampleSplitter). A
// per-CPU batch of skipped and tail-cut HTTP/2 call records is turned into the socket data events the records
// stand for, as H2CRecords: each one is admitted by the memory protection on its own, as a perf event of its
// own would be, decoded into a record of its own (buffer.NewCompactRecord, one small allocation that nothing
// else shares), charged its own size (buffer.ChargeRecord) and routed to its connection like any decoded
// event. A record the
// memory protection refuses is reported as the raw event it stands for (BatchRecordAsUploadSample), so the gap
// handling and the drop counters see exactly what they would see for that event. It returns false for any
// other sample.
func SplitH2CBatch(sample []byte, deliver func(data interface{}), drop func(sample []byte)) bool {
	if !IsBatchRecord(sample) {
		return false
	}
	n := BatchRecordCount(sample)
	CountBatch(n)
	for i := 0; i < n; i++ {
		if sample[batchHeaderSize+i*batchRecordSize+recKind] == batchKindSummary {
			// a summary of skipped payload calls (summary.go): no event of a socket call, and small; it is
			// delivered whatever the budget, the protocol logs of its stream wait for it
			summary := decodeSummaryRecord(sample, i)
			deliver(summary)
			continue
		}
		if !knownRecordKind(sample, i) {
			// an unknown record kind: nothing can be made of it, and it is not refused by the memory protection
			h2cUnknownRecords.Add(1)
			continue
		}
		if !buffer.AcquireEvent() {
			dropRefusedRecord(sample, i, drop)
			continue
		}
		record := buffer.NewCompactRecord()
		if !decodeRecord(record, sample, i) {
			// a record whose run the compact record has no room for (BPF sends none): the event it stands for
			event := &SocketDataUploadEvent{}
			event.DecodeBatchRecord(sample, i)
			deliver(event)
			continue
		}
		// the record is charged its own size, given back by its release
		buffer.ChargeRecord(record)
		recordEventSize(enums.ConnectionProtocolHTTP2, record.Direction0, record.BufferLen())
		deliver(record)
	}
	return true
}

// knownRecordKind tells whether record number i of the batch sample is of a kind decodeRecord knows; i must be
// in range
func knownRecordKind(sample []byte, i int) bool {
	kind := sample[batchHeaderSize+i*batchRecordSize+recKind]
	return kind == batchKindSkip || kind == batchKindCut
}

// decodeRecord fills the record from record number i of the batch sample, the fields DecodeBatchRecordInto
// reads, false for a record of an unknown kind; i must be in range
func decodeRecord(r *H2CRecord, sample []byte, i int) bool {
	b := sample[batchHeaderSize+i*batchRecordSize:]
	kind := b[recKind]
	if kind != batchKindSkip && kind != batchKindCut {
		return false
	}
	ext := b[recExt:]
	*r = H2CRecord{
		StartTime0:         binary.LittleEndian.Uint64(b[recStartTime:]),
		EndTime0:           binary.LittleEndian.Uint64(b[recEndTime:]),
		ConnectionID:       binary.LittleEndian.Uint64(b[recConID:]),
		RandomID:           binary.LittleEndian.Uint64(b[recRandomID:]),
		DataID0:            binary.LittleEndian.Uint64(b[recDataID:]),
		PrevDataID0:        binary.LittleEndian.Uint64(b[recPrevDataID:]),
		TotalSize0:         binary.LittleEndian.Uint64(b[recTotalSize:]),
		L4TotalPackageSize: binary.LittleEndian.Uint64(ext[extL4Size:]),
		LocalPort:          binary.LittleEndian.Uint16(ext[extLocalPort:]),
		RemotePort:         binary.LittleEndian.Uint16(ext[extRemotePt:]),
		InFlight:           binary.LittleEndian.Uint16(ext[extInFlight:]),
		L4PackageCount:     ext[extL4Count],
		FunctionName:       ext[extFuncName],
		SSL:                ext[extSSL],
		Direction0:         enums.SocketDataDirection(b[recDirection]),
	}
	r.SetH2CFrames(ext[extH2CFrames], binary.LittleEndian.Uint16(ext[extFirstFrame:]))
	r.SetSumBefore(binary.LittleEndian.Uint32(ext[extSumBefore:]))
	if kind == batchKindCut {
		r.SetCut()
		r.CutLen = min(b[recCutLen], batchCutMax)
		copy(r.CutData[:], b[recCutBuf:recCutBuf+int(r.CutLen)])
	}
	// BPF sends no record cut behind more bytes than leave room for its run: should one come, the event keeps it
	return r.SetSumRun(binary.LittleEndian.Uint32(ext[extSumStream:]), binary.LittleEndian.Uint16(ext[extSumFrames:]))
}

// dropRefusedRecord reports record i of the batch, which the memory protection refused, as the raw event it
// stands for. The sample it writes escapes to drop, so it is only taken for a refused record.
func dropRefusedRecord(sample []byte, i int, drop func(sample []byte)) {
	var refused [UploadSampleSize]byte
	if raw := BatchRecordAsUploadSample(sample, i, refused[:]); raw != nil {
		drop(raw)
	}
}

// H2CBatchesSeen is the number of batch perf events the reader split so far (rover_h2c_batches_total)
func H2CBatchesSeen() int64 {
	return h2cBatches.Load()
}
