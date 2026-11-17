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

package collector

import (
	"encoding/binary"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// the fields of a raw socket data upload record (events.SocketDataUploadEvent.ReadFrom) the gap handling
// needs from an event the memory protection refused before decoding it
const (
	recordProtocolOffset     = 0
	recordSequenceOffset     = 4
	recordDataLenOffset      = 6
	recordSSLOffset          = 12
	recordConnectionIDOffset = 32
	recordRandomIDOffset     = 40
	recordDataIDOffset       = 48
	recordTotalSizeOffset    = 64
	recordPayloadSkipped     = 81
	recordDataOffset         = 100
)

// recordPayloadShed is the payload_skipped mark of an event BPF sent without the data of its socket call
// because the memory protection was under pressure (events.PayloadShed). It carries the details of the
// call and at most its first bytes, enough for decodeDroppedRecord to tell an HTTP/1 request start.
const recordPayloadShed = events.PayloadShed

// isShedRecord tells whether a raw record is an event BPF sent without its data under memory pressure:
// the reader handles it exactly like an event the memory protection refused (the dropped sample
// observers, counted as dropped), then decodes it into the kernel log of its call (selfEvents ReadFrom)
func isShedRecord(sample []byte) bool {
	if len(sample) < recordDataOffset || sample[recordPayloadSkipped] != recordPayloadShed {
		return false
	}
	buffer.CountShedEvent()
	return true
}

// supplyShedEvent is the event a shed record decodes into: admitted whatever the budget, it only carries
// the details of its call, and is released as soon as its kernel log is queued
func supplyShedEvent() interface{} {
	buffer.AdmitShedEvent()
	return events.AcquireUploadEvent()
}

// countDroppedRecord counts the socket call of a record the memory protection dropped, by who dropped it:
// a shed record is a whole call of its total size; a refused record is a part of its call, the call
// counted with its first part (sequence 0) and the bytes it carried
func countDroppedRecord(sample []byte) {
	if len(sample) < recordDataOffset {
		return
	}
	if sample[recordPayloadSkipped] == recordPayloadShed {
		buffer.CountDroppedCall(buffer.DropReasonKernelShed, 1,
			int64(binary.LittleEndian.Uint64(sample[recordTotalSizeOffset:])))
		return
	}
	calls := int64(0)
	if binary.LittleEndian.Uint16(sample[recordSequenceOffset:]) == 0 {
		calls = 1
	}
	buffer.CountDroppedCall(buffer.DropReasonMemory, calls, int64(binary.LittleEndian.Uint16(sample[recordDataLenOffset:])))
}

// droppedRecord is what the gap handling reads of a refused record
type droppedRecord struct {
	connectionID, randomID, dataID uint64
	protocol                       enums.ConnectionProtocol
	ssl, startsRequest             bool
	sequence                       uint16
}

func decodeDroppedRecord(sample []byte) (droppedRecord, bool) {
	if len(sample) < recordDataOffset {
		return droppedRecord{}, false
	}
	r := droppedRecord{
		connectionID: binary.LittleEndian.Uint64(sample[recordConnectionIDOffset:]),
		randomID:     binary.LittleEndian.Uint64(sample[recordRandomIDOffset:]),
		dataID:       binary.LittleEndian.Uint64(sample[recordDataIDOffset:]),
		protocol:     enums.ConnectionProtocol(sample[recordProtocolOffset]),
		ssl:          sample[recordSSLOffset] != 0,
		sequence:     binary.LittleEndian.Uint16(sample[recordSequenceOffset:]),
	}
	r.startsRequest = r.sequence == 0 && protocols.IsHTTP1RequestLine(sample[recordDataOffset:])
	return r, true
}

// noteDroppedForGaps tells the protocols queue which connection lost a socket data event to the memory
// protection, so it drops the rest of the cut message and resynchronises at the next request
func noteDroppedForGaps(sample []byte) {
	if r, ok := decodeDroppedRecord(sample); ok {
		protocols.NoteProtectionDrop(r.connectionID, r.randomID, r.protocol, r.ssl, r.dataID, r.sequence, r.startsRequest)
	}
}

// droppedSampleObserver chains the observers of the samples the memory protection refused
func droppedSampleObserver(observers ...func(sample []byte)) func(sample []byte) {
	return func(sample []byte) {
		for _, observe := range observers {
			observe(sample)
		}
	}
}
