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
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols/http1skip"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

type SocketDataUploadEvent struct {
	Protocol0  enums.ConnectionProtocol
	HaveReduce uint8
	// FirstFrameOff and H2CFrames0: what the h2c follower of BPF knew of the frames of the call
	// (buffer.H2CFramesBuffer): where the first frame header that starts in it starts (0xffff: none, or not known)
	// and the buffer.H2CFrames* flags (0: nothing known). In the padding of the event, which keeps its size class.
	FirstFrameOff  uint16
	L4PackageCount uint32
	Finished       uint8
	H2CFrames0     uint8
	Sequence0      uint16
	DataLen        uint16
	FunctionName   uint32
	SSL            uint32 // a __u8 in the event
	// InFlight is the count of the socket calls of the fd in flight when the call returned, itself included,
	// 0 when BPF does not know it (see socket_data_call_observe in bpf/accesslog/common/data_args.h)
	InFlight uint16
	// SumFrames and SumStream: the SumBefore bytes are a run of SumFrames whole DATA frames of the stream
	// SumStream, headers included (buffer.SummaryRunBuffer); SumStream 0 when they are payload of one frame.
	// Here, in the padding behind InFlight, so the event keeps its size class.
	SumFrames          uint16
	SumStream          uint32
	StartTime0         uint64
	EndTime0           uint64
	ConnectionID       uint64
	RandomID           uint64
	DataID0            uint64
	PrevDataID0        uint64
	TotalSize0         uint64
	L4TotalPackageSize uint64
	Direction0         enums.SocketDataDirection
	// PayloadSkipped0 is 1 when BPF uploaded the call without its content because it lies wholly inside
	// the payload of an h2c DATA frame (skip_h2c_data_payload): DataLen is 0 and TotalSize0 the call's size.
	// It is PayloadSkippedHTTP1Body when the reader decoded the call without its bytes because it lies
	// wholly inside an HTTP/1 body (skip_http1_body_payload): DataLen keeps the length, Buffer is nil.
	PayloadSkipped0 uint8
	// shed is set when BPF sent the call without its data because the memory protection was under
	// pressure (PayloadShed): the event is decoded as one without a protocol, which only gives the kernel
	// log of its call, see ReadFrom
	shed bool
	// peek: the event of a receive made with MSG_PEEK (PayloadPeek)
	peek       bool
	LocalPort  uint16
	RemotePort uint16
	// DataIDSpan: the event stands for the skipped calls of an HTTP/1 body with the data ids DataID0 -
	// DataIDSpan to DataID0, which BPF coalesced into one event (skip_http1_body_payload_bpf with
	// merge_kernel_logs): their sizes and L4 counters summed, the start of the first, the end of the last.
	// 0 for the event of one call.
	DataIDSpan uint16
	// SumBefore is the h2c DATA payload bytes BPF summarised in front of the call (summarize_h2c_payload,
	// bpf/accesslog/common/h2c_sum.h): the parser counts them as skipped payload in front of it
	// (buffer.SummaryGap). 0 without the summaries.
	SumBefore uint32
	Buffer    []byte
	// DecodeSeq0 is the order the reader decoded the event in, with skip_http1_body_payload (0 without)
	DecodeSeq0 uint64
	// inline holds the data of a small event (most socket calls of a busy HTTP/2 connection are a few
	// control frames), which then takes no pooled buffer: Buffer points into it
	inline [inlineDataSize]byte
}

// PayloadSkippedHTTP1Body is PayloadSkipped0 of an HTTP/1 body call decoded without its bytes
const PayloadSkippedHTTP1Body = 2

// PayloadShed is the payload_skipped mark of an event BPF sent without the data of its call because the
// memory protection was under pressure (SOCKET_DATA_PAYLOAD_SHED, socket_data_pressure_map in
// skywalking-rover/bpf/accesslog/syscalls/transfer.h). It carries the details of its call, and at most
// the first 8 bytes of it, which only tell the gap handling whether it started an HTTP/1 request.
const PayloadShed = 3

// PayloadPeek is the payload_skipped mark of the event of a receive made with MSG_PEEK (SOCKET_DATA_PAYLOAD_PEEK in
// skywalking-rover/bpf/accesslog/syscalls/transfer.h): the call left its bytes in the socket for the call that
// receives them, so they are no part of the stream. The event carries the details of the call and takes no place in
// the chain of the uploads; it is decoded into the kernel log of its call alone, without a protocol (see ReadFrom).
const PayloadPeek = 4

// Peek tells whether the event is the one of a receive made with MSG_PEEK (PayloadPeek)
func (s *SocketDataUploadEvent) Peek() bool { return s.peek }

// Shed tells whether BPF sent the call without its data because of the memory pressure (PayloadShed)
func (s *SocketDataUploadEvent) Shed() bool { return s.shed }

// http1BodySkipper decides which HTTP/1 body calls are decoded without their bytes, nil when
// skip_http1_body_payload is off. Only the reader goroutine decodes events.
var http1BodySkipper atomic.Pointer[http1skip.Tracker]

// SetHTTP1BodySkipper turns skip_http1_body_payload on with the tracker, or off with nil
func SetHTTP1BodySkipper(t *http1skip.Tracker) {
	http1BodySkipper.Store(t)
}

// DroppedSampleObserver tells the tracker about the socket data events the reader drops before decoding
// them (btf.SetDroppedSampleObserver), by the connection in their raw record
func DroppedSampleObserver(t *http1skip.Tracker) func(sample []byte) {
	return func(sample []byte) {
		// the connection and random id follow the 32 bytes of the flags, sizes, function, ssl and times
		if len(sample) >= 48 {
			t.NoteDropped(binary.LittleEndian.Uint64(sample[32:40]), binary.LittleEndian.Uint64(sample[40:48]))
		}
	}
}

// inlineDataSize is the largest data kept in the event itself, see inline. 32 bytes take the control
// frames (SETTINGS ACK 9, WINDOW_UPDATE 13, PING 17) and keep the event in the 160 byte size class.
const inlineDataSize = 32

// InlineDataSize is inlineDataSize for the configuration of the agent
const InlineDataSize = inlineDataSize

// EventSize is the size of the event struct, what the memory protection charges an event in use
// besides its pooled buffer
const EventSize = int(unsafe.Sizeof(SocketDataUploadEvent{}))

// ReleaseBuffer hands the pooled buffer back and detaches it from the event: a released buffer is
// about to be handed to another event, so a reference left behind here would read someone else's data
func (s *SocketDataUploadEvent) ReleaseBuffer() []byte {
	released := s.Buffer
	s.Buffer = nil
	if unsafe.SliceData(released) == &s.inline[0] {
		return nil // the event's own array, nothing to give back
	}
	return released
}

// Discard gives the event back when the reader drops it instead of delivering it (btf.EventDiscarder),
// so its buffer returns to the pool instead of waiting for the garbage collector
func (s *SocketDataUploadEvent) Discard() {
	buffer.ReleaseEvent(s.ReleaseBuffer())
}

// CopyMetadata implements buffer.MetadataCopier: the body consumer keeps such copies as kernel log
// details after releasing the original event's buffer
func (s *SocketDataUploadEvent) CopyMetadata() buffer.SocketDataBuffer {
	return s.Detach()
}

// Detach returns a copy of the event without the data buffer. The kernel log details that travel
// with a protocol log through the flush queue only need the metadata; keeping the original event
// there would pin its 20KB buffer (and the pool cannot reuse it) until the next flush.
func (s *SocketDataUploadEvent) Detach() *SocketDataUploadEvent {
	c := &SocketDataUploadEvent{}
	s.DetachTo(c)
	return c
}

// DetachTo is Detach into c, for the copies that are allocated together
func (s *SocketDataUploadEvent) DetachTo(c *SocketDataUploadEvent) {
	*c = *s
	c.Buffer = nil
}

func (s *SocketDataUploadEvent) ReadFrom(r btf.Reader) {
	// a real sample comes in a BytesReader; the reader measures the event once with another one (no sample)
	_, sample := r.(*btf.BytesReader)
	if sample {
		CountPerfEvent()
	}
	s.Protocol0 = enums.ConnectionProtocol(r.ReadUint8())
	s.HaveReduce = r.ReadUint8()
	s.L4PackageCount = uint32(r.ReadUint8())
	s.Finished = r.ReadUint8()
	s.Sequence0 = r.ReadUint16()
	s.DataLen = r.ReadUint16()
	s.FunctionName = r.ReadUint32()
	s.SSL = uint32(r.ReadUint8())
	s.H2CFrames0 = r.ReadUint8()
	s.InFlight = r.ReadUint16()
	s.StartTime0 = r.ReadUint64()
	s.EndTime0 = r.ReadUint64()
	s.ConnectionID = r.ReadUint64()
	s.RandomID = r.ReadUint64()
	s.DataID0 = r.ReadUint64()
	s.PrevDataID0 = r.ReadUint64()
	s.TotalSize0 = r.ReadUint64()
	s.L4TotalPackageSize = r.ReadUint64()
	s.Direction0 = enums.SocketDataDirection(r.ReadUint8())
	s.PayloadSkipped0 = r.ReadUint8()
	s.LocalPort = r.ReadUint16()
	s.RemotePort = r.ReadUint16()
	s.DataIDSpan = r.ReadUint16()
	s.SumBefore = r.ReadUint32()
	s.SumStream = r.ReadUint32()
	s.SumFrames = r.ReadUint16()
	s.FirstFrameOff = r.ReadUint16()
	s.shed, s.peek = false, false
	if s.PayloadSkipped0 == PayloadPeek {
		// a peek is no read: its bytes (BPF sends none) never reach a protocol analyzer, which would parse them twice
		// (once more when they are received), and it names no previous upload. What is left is its kernel log.
		dataLen := min(int(s.DataLen), len(s.inline))
		r.ReadUint8Array(s.inline[:dataLen], dataLen)
		if rest := int(s.DataLen) - dataLen; rest > 0 {
			if b, ok := r.(*btf.BytesReader); ok {
				b.Skip(rest)
			}
		}
		s.peek = true
		s.Protocol0 = enums.ConnectionProtocolUnknown
		s.PayloadSkipped0, s.DataLen, s.Buffer, s.PrevDataID0 = 0, 0, nil, 0
		return
	}
	if s.PayloadSkipped0 == PayloadShed {
		// the reader handled the call as dropped by the memory protection (the gap handling and the drop
		// counters) before it decoded it: what is left of it is its kernel log, without a protocol, so no
		// protocol analyzer ever sees a call it cannot read. The bytes it carries are read past.
		dataLen := min(int(s.DataLen), len(s.inline))
		r.ReadUint8Array(s.inline[:dataLen], dataLen)
		s.shed = true
		s.Protocol0 = enums.ConnectionProtocolUnknown
		s.PayloadSkipped0, s.DataLen, s.Buffer = 0, 0, nil
		return
	}
	// the BPF side only sends the bytes it read, so the record ends after data_len bytes of buffer,
	// and the buffer itself is taken now that its size is known rather than at a fixed chunk size
	dataLen := int(s.DataLen)
	if dataLen > buffer.MaxEventBufferSize {
		// BPF never sends more than a chunk; the length is the bytes the event holds (BufferLen)
		dataLen = buffer.MaxEventBufferSize
		s.DataLen = uint16(dataLen)
	}
	if s.skipHTTP1Body(r, dataLen) {
		recordEventSize(s.Protocol0, s.Direction0, dataLen)
		return
	}
	if dataLen > 0 {
		if dataLen <= len(s.inline) {
			s.Buffer = s.inline[:dataLen]
		} else {
			s.Buffer = buffer.TakeBuffer(dataLen)
		}
		r.ReadUint8Array(s.Buffer, dataLen)
	}
	if sample {
		recordEventSize(s.Protocol0, s.Direction0, dataLen)
	}
}

// skipHTTP1Body asks the tracker of skip_http1_body_payload about the event before its bytes are copied,
// and skips them when the call lies wholly inside an HTTP/1 body: the event keeps its length (BufferLen)
// and takes no buffer
func (s *SocketDataUploadEvent) skipHTTP1Body(r btf.Reader, dataLen int) bool {
	tracker := http1BodySkipper.Load()
	if tracker == nil {
		return false
	}
	sample, ok := r.(*btf.BytesReader)
	if !ok || sample.HasError() != nil {
		return false
	}
	payload := sample.Peek(dataLen)
	if len(payload) < dataLen {
		// a short sample: the read of the bytes below fails it, the tracker is not told of a call it never sees
		return false
	}
	call := http1skip.Call{
		ConnectionID: s.ConnectionID, RandomID: s.RandomID, Protocol: s.Protocol0, SSL: s.SSL != 0,
		Direction: s.Direction0, DataID: s.DataID0, PrevDataID: s.PrevDataID0, Sequence: s.Sequence0,
		Finished: s.Finished == 1, Reduced: s.HaveReduce == 1, DataLen: int(s.DataLen), TotalSize: s.TotalSize0,
		StartTime: s.StartTime0, InFlight: s.InFlight, FirstDataID: s.FirstDataID(),
	}
	seq, skip := tracker.Decide(&call, payload)
	s.DecodeSeq0 = seq
	if !skip {
		return false
	}
	sample.Skip(dataLen)
	s.PayloadSkipped0 = PayloadSkippedHTTP1Body
	return true
}

// eventSizeBounds are the upper bounds of the event size histogram. The low end is fine grained on
// purpose: an HTTP/2 SETTINGS ACK is 9 bytes, a WINDOW_UPDATE 13 and a PING 17, so the two lowest
// buckets of the h2c series count the socket calls that carry nothing but control frames - the
// events the analyzer discards without reading. The high end shows how many events a byte capped
// batch could merge: the upload chunk, and with it any batch, is 20480 bytes.
var eventSizeBounds = [...]int{16, 32, 64, 256, 1024, 2048, 4096, 8192, 16384, buffer.MaxEventBufferSize}

// eventSizes is indexed by protocol (unknown, http, http2), direction (unused, ingress, egress) and
// bucket. One atomic add per event on the read path: a few nanoseconds against the ~30-50
// microseconds the rest of an event costs.
var eventSizes [3][3][len(eventSizeBounds)]atomic.Int64

func recordEventSize(p enums.ConnectionProtocol, d enums.SocketDataDirection, size int) {
	if int(p) >= len(eventSizes) || int(d) >= len(eventSizes[0]) {
		return
	}
	for i, bound := range eventSizeBounds {
		if size <= bound || i == len(eventSizeBounds)-1 {
			eventSizes[p][d][i].Add(1)
			return
		}
	}
}

func init() {
	protocols := [...]string{"unknown", "http1", "http2"}
	directions := [...]string{"", "ingress", "egress"}
	telemetry.RegisterSeries("rover_socket_data_event_size_total",
		"Socket data events by protocol, direction and payload size bucket. Buckets are not "+
			"cumulative: each event is counted in exactly one, labelled by its inclusive byte range",
		telemetry.Counter, func() []telemetry.Sample {
			samples := make([]telemetry.Sample, 0, len(protocols)*2*len(eventSizeBounds))
			for p := range protocols {
				for d := 1; d < len(directions); d++ {
					low := 0
					for i, bound := range eventSizeBounds {
						samples = append(samples, telemetry.Sample{
							Labels: map[string]string{"protocol": protocols[p], "direction": directions[d],
								"bytes": fmt.Sprintf("%d-%d", low, bound)},
							Value: float64(eventSizes[p][d][i].Load()),
						})
						low = bound + 1
					}
				}
			}
			return samples
		})
}

func (s *SocketDataUploadEvent) GetConnectionID() uint64 {
	return s.ConnectionID
}

func (s *SocketDataUploadEvent) GetRandomID() uint64 {
	return s.RandomID
}

func (s *SocketDataUploadEvent) Timestamp() time.Time {
	return host.Time(s.StartTime0)
}

func (s *SocketDataUploadEvent) Protocol() enums.ConnectionProtocol {
	return s.Protocol0
}

func (s *SocketDataUploadEvent) GenerateConnectionID() string {
	return fmt.Sprintf("%d_%d", s.ConnectionID, s.RandomID)
}

func (s *SocketDataUploadEvent) BufferData() []byte {
	if s.Buffer == nil {
		return nil
	}
	// the buffer is taken for the length the event reported, so they normally match; a length that
	// does not fit what was allocated is bounded here rather than panicking in the data path
	if int(s.DataLen) > len(s.Buffer) {
		return s.Buffer
	}
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

func (s *SocketDataUploadEvent) Time() uint64 {
	return s.StartTime0
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

// SummarisedBefore implements buffer.SummarisedBeforeBuffer: the lower 24 bits of SumBefore (the upper 8 are a part of
// the rest of an open run, SummaryRunOpenRest)
func (s *SocketDataUploadEvent) SummarisedBefore() uint32 {
	return s.SumBefore & 0xffffff
}

// SummaryRunOpenRest implements buffer.SummaryRunOpenBuffer: with a run whose last frame is open (H2C_SUM_RUN_OPEN), BPF
// sends the rest of that frame's payload from the start of the call in FirstFrameOff (the lower 16 bits) and the upper
// byte of SumBefore (the upper 8 bits)
func (s *SocketDataUploadEvent) SummaryRunOpenRest() uint32 {
	if !buffer.SummaryRunIsOpen(s.SumStream) {
		return 0
	}
	return uint32(s.FirstFrameOff) | s.SumBefore>>24<<16
}

// H2CFrames implements buffer.H2CFramesBuffer. Behind an open run the first frame offset BPF sent is the rest of the
// open frame (SummaryRunOpenRest), which is where the first frame header starts when it lies in the call: none when
// the call ends first, not known when it does not fit the offset.
func (s *SocketDataUploadEvent) H2CFrames() (flags uint8, firstFrameOff uint16) {
	if rest := s.SummaryRunOpenRest(); rest > 0 {
		switch {
		case uint64(rest) >= s.TotalSize0:
			return s.H2CFrames0, 0xffff
		case rest >= 0xffff:
			return 0, 0xffff
		}
		return s.H2CFrames0, uint16(rest)
	}
	return s.H2CFrames0, s.FirstFrameOff
}

// SummaryRun implements buffer.SummaryRunBuffer
func (s *SocketDataUploadEvent) SummaryRun() (stream uint32, frames uint16) {
	return s.SumStream, s.SumFrames
}

// FirstDataID is the first data id of the socket calls the event stands for: DataID0 but for an event of
// coalesced calls (DataIDSpan)
func (s *SocketDataUploadEvent) FirstDataID() uint64 {
	if uint64(s.DataIDSpan) >= s.DataID0 {
		return s.DataID0
	}
	return s.DataID0 - uint64(s.DataIDSpan)
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

// PayloadSkipped implements buffer.PayloadSkippedBuffer
func (s *SocketDataUploadEvent) PayloadSkipped() bool {
	return s.PayloadSkipped0 != 0
}

// BodyPayloadSkipped implements buffer.BodyPayloadSkippedBuffer
func (s *SocketDataUploadEvent) BodyPayloadSkipped() bool {
	return s.PayloadSkipped0 == PayloadSkippedHTTP1Body
}

// DecodeSequence is the order the reader decoded the event in (skip_http1_body_payload)
func (s *SocketDataUploadEvent) DecodeSequence() uint64 {
	return s.DecodeSeq0
}

func (s *SocketDataUploadEvent) GetStartTime() uint64 {
	return s.StartTime0
}

func (s *SocketDataUploadEvent) GetEndTime() uint64 {
	return s.EndTime0
}

func (s *SocketDataUploadEvent) GetL4PackageCount() uint32 {
	return s.L4PackageCount
}

func (s *SocketDataUploadEvent) GetL4TotalPackageSize() uint64 {
	return s.L4TotalPackageSize
}

func (s *SocketDataUploadEvent) GetFunctionName() enums.SocketFunctionName {
	return enums.SocketFunctionName(s.FunctionName)
}

func (s *SocketDataUploadEvent) GetProtocol() enums.ConnectionProtocol {
	return s.Protocol0
}

func (s *SocketDataUploadEvent) GetSSL() uint8 {
	return uint8(s.SSL)
}

// CanMergeDetail, CopyForMerge and MergeDetail let the access log report one record per operation of
// a message instead of one per socket syscall, see events.MergeDetails in the rover. The copy is not
// optional: one socket call can carry the end of a message and the start of the next, so the same
// detail belongs to two protocol logs.
func (s *SocketDataUploadEvent) CanMergeDetail(other SocketDetail) bool {
	// a batch record (H2CRecord) is the event it stands for
	fn, start, ok := mergeKey(other)
	// the backend buckets a record by its own start time, so a merge may not cross a minute
	return ok && fn == s.FunctionName && sameMinute(s.StartTime0, start)
}

func (s *SocketDataUploadEvent) CopyForMerge() MergeableDetail {
	copied := *s
	copied.Buffer = nil
	return &copied
}

func (s *SocketDataUploadEvent) MergeDetail(other SocketDetail) {
	var end, size uint64
	var count uint32
	switch next := other.(type) {
	case *SocketDataUploadEvent:
		end, count, size = next.EndTime0, next.L4PackageCount, next.L4TotalPackageSize
	case *H2CRecord:
		// the event the record stands for
		end, count, size = next.EndTime0, uint32(next.L4PackageCount), next.L4TotalPackageSize
	default:
		return
	}
	if end > s.EndTime0 {
		s.EndTime0 = end
	}
	s.L4PackageCount += count
	s.L4TotalPackageSize += size
}

// sameMinute is host.SameMinute, the merge rule of CanMergeDetail
func sameMinute(a, b uint64) bool {
	return host.SameMinute(a, b)
}
