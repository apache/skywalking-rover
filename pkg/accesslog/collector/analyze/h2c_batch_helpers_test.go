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

package analyze

import (
	"encoding/binary"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The layout of a per-CPU batch of HTTP/2 call records (bpf/accesslog/common/h2c_batch.h, events/batch.go),
// for the tests that build batches the way BPF does. The events tests check the decoder against the same
// offsets, and the kernel tests the record size against the loaded object.
const (
	tbHeader     = 8
	tbCountOff   = 4
	tbKind       = 0
	tbDirection  = 1
	tbCutLen     = 2
	tbStart      = 8
	tbEnd        = 16
	tbConID      = 24
	tbRandomID   = 32
	tbDataID     = 40
	tbPrevDataID = 48
	tbTotal      = 56
	tbExt        = 64
	tbCutBuf     = 96
	tbCutMax     = 16
	tbKindSkip   = 1
	tbKindCut    = 2
	// inside the upload_data_args_ext at tbExt
	tbL4Size    = 0
	tbLocal     = 8
	tbRemote    = 10
	tbL4Count   = 12
	tbFuncName  = 13
	tbSSL       = 14
	tbInFlight  = 16
	tbSumBefore = 20
	tbSumStream = 24
	tbSumFrames = 28
	tbH2CFrames = 15
	tbFirstOff  = 30
)

// h2cBatchable tells whether BPF sends the event as a batch record: a call skipped inside a DATA payload,
// or one cut in front of a DATA payload behind at most 16 bytes
func h2cBatchable(e *events.SocketDataUploadEvent) bool {
	if e.Protocol0 != enums.ConnectionProtocolHTTP2 || e.Sequence0 != 0 || e.Finished != 1 {
		return false
	}
	if e.PayloadSkipped0 == 1 {
		return e.DataLen == 0
	}
	return e.HaveReduce == 1 && int(e.DataLen) <= tbCutMax
}

// encodeH2CBatch lays the events out as one batch perf sample; every event must be h2cBatchable
func encodeH2CBatch(evs []*events.SocketDataUploadEvent) []byte {
	b := make([]byte, tbHeader+len(evs)*events.BatchRecordSize)
	b[0] = events.BatchMarker
	binary.LittleEndian.PutUint32(b[tbCountOff:], uint32(len(evs)))
	for i, e := range evs {
		o := b[tbHeader+i*events.BatchRecordSize:]
		if e.PayloadSkipped0 == 1 {
			o[tbKind] = tbKindSkip
		} else {
			o[tbKind] = tbKindCut
			o[tbCutLen] = uint8(e.DataLen)
			copy(o[tbCutBuf:tbCutBuf+tbCutMax], e.BufferData())
		}
		o[tbDirection] = uint8(e.Direction0)
		binary.LittleEndian.PutUint64(o[tbStart:], e.StartTime0)
		binary.LittleEndian.PutUint64(o[tbEnd:], e.EndTime0)
		binary.LittleEndian.PutUint64(o[tbConID:], e.ConnectionID)
		binary.LittleEndian.PutUint64(o[tbRandomID:], e.RandomID)
		binary.LittleEndian.PutUint64(o[tbDataID:], e.DataID0)
		binary.LittleEndian.PutUint64(o[tbPrevDataID:], e.PrevDataID0)
		binary.LittleEndian.PutUint64(o[tbTotal:], e.TotalSize0)
		ext := o[tbExt:]
		binary.LittleEndian.PutUint64(ext[tbL4Size:], e.L4TotalPackageSize)
		binary.LittleEndian.PutUint16(ext[tbLocal:], e.LocalPort)
		binary.LittleEndian.PutUint16(ext[tbRemote:], e.RemotePort)
		ext[tbL4Count], ext[tbFuncName], ext[tbSSL] = uint8(e.L4PackageCount), uint8(e.FunctionName), uint8(e.SSL)
		binary.LittleEndian.PutUint16(ext[tbInFlight:], e.InFlight)
		binary.LittleEndian.PutUint32(ext[tbSumBefore:], e.SumBefore)
		binary.LittleEndian.PutUint32(ext[tbSumStream:], e.SumStream)
		binary.LittleEndian.PutUint16(ext[tbSumFrames:], e.SumFrames)
		ext[tbH2CFrames] = e.H2CFrames0
		binary.LittleEndian.PutUint16(ext[tbFirstOff:], e.FirstFrameOff)
	}
	return b
}

// h2cDelivery is what the reader hands over at one point: a full event, or a batch sample to split
type h2cDelivery struct {
	call   int
	event  *events.SocketDataUploadEvent
	sample []byte
}

// h2cCutUploads is skipUploads with the tail cut as well: a call whose end lies in a DATA payload is uploaded
// up to the payload, with the size of the call and the reduce mark, as BPF cuts it
func (s *h2cScript) h2cCutUploads(base uint64, drop bool) []h2cEvent {
	evs, _ := s.skipUploads(base, drop, true)
	cuts := h2cTailSkippable(s)
	for _, e := range evs {
		if cut := cuts[e.call]; cut > 0 && e.event.PayloadSkipped0 == 0 {
			e.event.Buffer = e.event.Buffer[:cut]
			e.event.DataLen, e.event.HaveReduce = uint16(cut), 1
		}
	}
	return evs
}

// h2cBatchDeliveries models the per-CPU batching: the batchable events go into the open batch, which is
// handed over when it holds batchSize records, when inOrder and a full event follows (so the order of the
// calls is kept), or every flushEvery events; the full events go at once. Without inOrder, a batch arrives
// behind the full events read after its records, as a batch of another CPU or one kicked late does.
func h2cBatchDeliveries(evs []h2cEvent, batchSize, flushEvery int, inOrder bool) []h2cDelivery {
	var result []h2cDelivery
	var pending []*events.SocketDataUploadEvent
	lastCall := 0
	flush := func() {
		if len(pending) > 0 {
			result = append(result, h2cDelivery{call: lastCall, sample: encodeH2CBatch(pending)})
			pending = nil
		}
	}
	for i, e := range evs {
		lastCall = e.call
		if h2cBatchable(e.event) {
			pending = append(pending, e.event)
			if len(pending) >= batchSize {
				flush()
			}
		} else {
			if inOrder {
				flush()
			}
			result = append(result, h2cDelivery{call: e.call, event: e.event})
		}
		if flushEvery > 0 && i%flushEvery == flushEvery-1 {
			flush()
		}
	}
	flush()
	return result
}

// h2cBenchRecords is a batch of 64 records of one connection: three skipped calls for every cut one
func h2cBenchRecords(firstDataID uint64) []byte {
	evs := make([]*events.SocketDataUploadEvent, 0, 64)
	for i := 0; i < 64; i++ {
		id := firstDataID + uint64(i)
		e := &events.SocketDataUploadEvent{Protocol0: enums.ConnectionProtocolHTTP2, Finished: 1,
			FunctionName: uint32(enums.SocketFunctionNameRead), StartTime0: id * 1000, EndTime0: id*1000 + 300,
			ConnectionID: 1, RandomID: 1, DataID0: id, PrevDataID0: id - 1, TotalSize0: 16384,
			L4PackageCount: 12, L4TotalPackageSize: 16384 + 12*66, Direction0: enums.SocketDataDirectionIngress,
			LocalPort: 8080, RemotePort: 50000}
		if i%4 == 3 {
			e.HaveReduce, e.DataLen, e.Buffer = 1, 9, []byte{0, 0x40, 0, 0, 0, 0, 0, 0, 1}
		} else {
			e.PayloadSkipped0 = 1
		}
		evs = append(evs, e)
	}
	return encodeH2CBatch(evs)
}
