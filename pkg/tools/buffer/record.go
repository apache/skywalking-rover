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

package buffer

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// CompactRecord is a socket data event of one whole socket call that carries at most CompactCutMax bytes:
// a call uploaded without its content (PayloadSkipped, the bytes counted by TotalSize) or one cut behind
// its first bytes (HaveReduceDataAfterChunk, the rest counted by TotalSize). The per-CPU batches of HTTP/2
// call records (bpf/accesslog/common/h2c_batch.h) are read into them, so such a call never becomes a full
// socket data event: the record answers every question the parser, the buffers, the ordering, the gap
// handling and the accounting ask (SocketDataBuffer, PayloadSkippedBuffer) as the event of the call would,
// and the kernel log questions (the events.SocketDetail getters) with the fields of the call.
//
// Every record is an allocation of its own (NewCompactRecord, one size class of 96 bytes), made when the
// reader splits the batch, and the buffers hold a pointer to it like to any event: nothing is shared between
// records, so a record that something still refers to (a kernel log in the flush queue, a position, a slice)
// keeps only itself alive, never a slab of its neighbours. Nothing changes a record once it is routed but
// ReleaseBuffer, which only marks its cut bytes as given back, what releasing an event does to its buffer.
type CompactRecord struct {
	StartTime0         uint64
	EndTime0           uint64
	ConnectionID       uint64
	RandomID           uint64
	DataID0            uint64
	PrevDataID0        uint64
	TotalSize0         uint64
	L4TotalPackageSize uint64
	LocalPort          uint16
	RemotePort         uint16
	InFlight           uint16
	L4PackageCount     uint8
	FunctionName       uint8
	SSL                uint8
	Direction0         enums.SocketDataDirection
	// h2cFrames is what the h2c follower knew of the frames of the call (H2CFramesBuffer): the flags in the low 3
	// bits, the offset of the first frame header + 1 above (0: none; a record's is within its cut bytes). In the place of the protocol, which is
	// HTTP/2 for every record.
	h2cFrames uint8
	// CutLen is the bytes a call cut behind its first bytes carries (IsCut)
	CutLen uint8
	// state holds recordReleased, recordCharged and recordCut
	state uint8
	// sumBefore is the h2c DATA payload bytes BPF summarised in front of the call (SummarisedBeforeBuffer), 24
	// bits little endian: they lie in the payload of one frame, whose length is 24 bits. The record keeps its
	// size class with it.
	sumBefore [3]uint8
	CutData   [CompactCutMax]byte
}

const (
	// recordReleased is set by ReleaseBuffer: the cut bytes are not readable anymore, as a released event's
	// buffer
	recordReleased = 1 << iota
	// recordCharged tells the record's memory is counted in bytesInUse (ChargeRecord) until its release
	recordCharged
	// recordCut tells a call cut behind CutLen bytes from one uploaded without its content
	recordCut
	// recordRun tells the summarised bytes in front of the call are a run of whole DATA frames (SummaryRun),
	// whose stream and frames are kept in the last bytes of CutData (from recordRunAt)
	recordRun
)

// recordRunAt is where the run of a record is kept in CutData: BPF batches no call cut behind more bytes that
// carries one (H2C_BATCH_CUT_RUN_MAX in syscalls/h2c.h), so the record keeps its size class
const recordRunAt = CompactCutMax - 6

// IsCut tells a call cut behind CutLen bytes from one uploaded without its content
func (r *CompactRecord) IsCut() bool {
	return r.state&recordCut != 0
}

// SetCut marks the record as a call cut behind CutLen bytes
func (r *CompactRecord) SetCut() {
	r.state |= recordCut
}

// SetSumBefore sets the summarised bytes in front of the call (24 bits, see sumBefore)
func (r *CompactRecord) SetSumBefore(n uint32) {
	r.sumBefore = [3]uint8{uint8(n), uint8(n >> 8), uint8(n >> 16)}
}

// SetSumRun sets the run the summarised bytes in front of the call are: frames whole DATA frames of the stream
// (stream 0: none, they are payload of one frame). Set after the cut bytes; false when they leave no room for
// it (more than recordRunAt of them), which BPF never sends.
func (r *CompactRecord) SetSumRun(stream uint32, frames uint16) bool {
	if stream == 0 {
		r.state &^= recordRun
		return true
	}
	if int(r.CutLen) > recordRunAt {
		return false
	}
	run := r.CutData[recordRunAt:]
	run[0], run[1], run[2], run[3] = uint8(stream), uint8(stream>>8), uint8(stream>>16), uint8(stream>>24)
	run[4], run[5] = uint8(frames), uint8(frames>>8)
	r.state |= recordRun
	return true
}

// SetH2CFrames sets what the h2c follower knew of the frames of the call (H2CFramesBuffer). The offset of the
// first frame header of a record is within its cut bytes, or there is none (0xffff).
func (r *CompactRecord) SetH2CFrames(flags uint8, firstFrameOff uint16) {
	off := uint8(0)
	if flags&H2CFramesKnown != 0 && firstFrameOff < 0x1f {
		off = uint8(firstFrameOff) + 1
	}
	r.h2cFrames = flags&h2cFramesFlags | off<<3
}

// H2CFrames implements H2CFramesBuffer
func (r *CompactRecord) H2CFrames() (flags uint8, firstFrameOff uint16) {
	flags, firstFrameOff = r.h2cFrames&h2cFramesFlags, 0xffff
	if off := r.h2cFrames >> 3; off != 0 {
		firstFrameOff = uint16(off - 1)
	}
	return flags, firstFrameOff
}

// SummaryRunOpenRest implements SummaryRunOpenBuffer: BPF gives the rest of the open frame of a run as the first frame
// offset of the call, which a record keeps within its cut bytes (a record that carries an open run is a cut one whose
// first frame header lies in its cut bytes)
func (r *CompactRecord) SummaryRunOpenRest() uint32 {
	if stream, _ := r.SummaryRun(); !SummaryRunIsOpen(stream) {
		return 0
	}
	if flags, first := r.H2CFrames(); flags&H2CFramesKnown != 0 && first != 0xffff {
		return uint32(first)
	}
	return 0
}

// SummaryRun implements SummaryRunBuffer
func (r *CompactRecord) SummaryRun() (stream uint32, frames uint16) {
	if r.state&recordRun == 0 {
		return 0, 0
	}
	run := r.CutData[recordRunAt:]
	return uint32(run[0]) | uint32(run[1])<<8 | uint32(run[2])<<16 | uint32(run[3])<<24, uint16(run[4]) | uint16(run[5])<<8
}

// CompactCutMax is the most bytes a CompactRecord carries
const CompactCutMax = 16

// CompactRecordSize is the memory one record takes: its Go size class
const CompactRecordSize = 96

// NewCompactRecord allocates a record for the reader to fill
func NewCompactRecord() *CompactRecord {
	r := new(CompactRecord)
	return r
}

// recordsInUse counts the records charged (ChargeRecord) and not released yet: each one is CompactRecordSize
// of bytesInUse, and InflightBytes charges it the bookkeeping of an event instead of the event overhead
var recordsInUse atomic.Int64

// ChargeRecord counts the memory of an admitted record (AcquireEvent) in the memory protection: the record
// itself, CompactRecordSize in bytesInUse, instead of the event struct the admission charges by default. The
// charge is given back once, by the first ReleaseBuffer of the record. The record must be filled already:
// filling it as a whole afterwards would clear the charge.
func ChargeRecord(r *CompactRecord) {
	if r.state&recordCharged != 0 {
		return
	}
	r.state |= recordCharged
	recordsInUse.Add(1)
	bytesInUse.Add(CompactRecordSize)
}

// ReleaseBuffer implements SocketDataBuffer: the record holds no pooled buffer. Like a released event it has
// no readable bytes afterwards, and the first release gives its charge back (ChargeRecord).
func (r *CompactRecord) ReleaseBuffer() []byte {
	r.state |= recordReleased
	if r.state&recordCharged != 0 {
		r.state &^= recordCharged
		recordsInUse.Add(-1)
		bytesInUse.Add(-CompactRecordSize)
	}
	return nil
}

// Discard gives the admission of a record the reader drops back (btf.EventDiscarder)
func (r *CompactRecord) Discard() {
	ReleaseEvent(r.ReleaseBuffer())
}

// CopyMetadata implements MetadataCopier: a copy without the bytes
func (r *CompactRecord) CopyMetadata() SocketDataBuffer {
	c := &CompactRecord{}
	*c = *r
	c.state = recordReleased | (r.state & recordCut)
	return c
}

func (r *CompactRecord) Protocol() enums.ConnectionProtocol {
	return enums.ConnectionProtocolHTTP2
}

func (r *CompactRecord) GenerateConnectionID() string {
	return fmt.Sprintf("%d_%d", r.ConnectionID, r.RandomID)
}

// BufferData is the cut bytes of a cut record until it is released, nil otherwise
func (r *CompactRecord) BufferData() []byte {
	if !r.IsCut() || r.state&recordReleased != 0 {
		return nil
	}
	return r.CutData[:r.CutLen]
}

// TotalSize is the size of the call
func (r *CompactRecord) TotalSize() uint64 {
	return r.TotalSize0
}

func (r *CompactRecord) Direction() enums.SocketDataDirection {
	return r.Direction0
}

func (r *CompactRecord) BufferStartPosition() int {
	return 0
}

func (r *CompactRecord) BufferLen() int {
	return int(r.CutLen)
}

func (r *CompactRecord) DataID() uint64 {
	return r.DataID0
}

func (r *CompactRecord) PrevDataID() uint64 {
	return r.PrevDataID0
}

// DataSequence is 0, IsStart and IsFinished true: a record is a whole call
func (r *CompactRecord) DataSequence() int {
	return 0
}

func (r *CompactRecord) IsStart() bool {
	return true
}

func (r *CompactRecord) IsFinished() bool {
	return true
}

func (r *CompactRecord) HaveReduceDataAfterChunk() bool {
	return r.IsCut()
}

func (r *CompactRecord) StartTime() uint64 {
	return r.StartTime0
}

func (r *CompactRecord) EndTime() uint64 {
	return r.EndTime0
}

// SummarisedBefore implements SummarisedBeforeBuffer
func (r *CompactRecord) SummarisedBefore() uint32 {
	return uint32(r.sumBefore[0]) | uint32(r.sumBefore[1])<<8 | uint32(r.sumBefore[2])<<16
}

// PayloadSkipped implements PayloadSkippedBuffer
func (r *CompactRecord) PayloadSkipped() bool {
	return !r.IsCut()
}

// BodyPayloadSkipped implements BodyPayloadSkippedBuffer: never, that is an HTTP/1 body call
func (r *CompactRecord) BodyPayloadSkipped() bool {
	return false
}

// DecodeSequence is 0: the HTTP/1 body skipping does not decode records
func (r *CompactRecord) DecodeSequence() uint64 {
	return 0
}

// the getters of a kernel log detail (events.SocketDetail)

func (r *CompactRecord) GetConnectionID() uint64 {
	return r.ConnectionID
}

func (r *CompactRecord) GetRandomID() uint64 {
	return r.RandomID
}

func (r *CompactRecord) Timestamp() time.Time {
	return host.Time(r.StartTime0)
}

func (r *CompactRecord) Time() uint64 {
	return r.StartTime0
}

func (r *CompactRecord) GetStartTime() uint64 {
	return r.StartTime0
}

func (r *CompactRecord) GetEndTime() uint64 {
	return r.EndTime0
}

func (r *CompactRecord) GetL4PackageCount() uint32 {
	return uint32(r.L4PackageCount)
}

func (r *CompactRecord) GetL4TotalPackageSize() uint64 {
	return r.L4TotalPackageSize
}

func (r *CompactRecord) GetFunctionName() enums.SocketFunctionName {
	return enums.SocketFunctionName(uint32(r.FunctionName))
}

func (r *CompactRecord) GetProtocol() enums.ConnectionProtocol {
	return enums.ConnectionProtocolHTTP2
}

func (r *CompactRecord) GetSSL() uint8 {
	return r.SSL
}
