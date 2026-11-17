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
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
)

// H2CRecord is one record of a per-CPU batch of skipped and tail-cut HTTP/2 calls (batch.go), kept as the
// compact record of the buffers (buffer.CompactRecord) instead of the SocketDataUploadEvent it stands for.
// The reader allocates and fills it (buffer.NewCompactRecord, 96 bytes that nothing else shares) and the
// buffers of its connection hold it like any event (see buffer.CompactRecord). Every question the
// parser, the buffers and the kernel logs ask it is answered as the event DecodeBatchRecordInto builds of the
// same record answers it; a kernel log detail a protocol log keeps is made of it with DetachRecordTo, the
// copy the event's DetachTo gives, and a kernel log without a protocol refers to the record itself, which keeps
// nothing but itself alive.
type H2CRecord = buffer.CompactRecord

// DetachRecordTo fills c with the event DecodeBatchRecordInto builds of the record, without its buffer: what
// that event's DetachTo gives (the event keeps the cut bytes in its inline array, so does the copy)
func DetachRecordTo(r *H2CRecord, c *SocketDataUploadEvent) {
	*c = SocketDataUploadEvent{
		Protocol0:          r.Protocol(),
		L4PackageCount:     uint32(r.L4PackageCount),
		Finished:           1,
		FunctionName:       uint32(r.FunctionName),
		SSL:                uint32(r.SSL),
		InFlight:           r.InFlight,
		StartTime0:         r.StartTime0,
		EndTime0:           r.EndTime0,
		ConnectionID:       r.ConnectionID,
		RandomID:           r.RandomID,
		DataID0:            r.DataID0,
		PrevDataID0:        r.PrevDataID0,
		TotalSize0:         r.TotalSize0,
		L4TotalPackageSize: r.L4TotalPackageSize,
		Direction0:         r.Direction0,
		LocalPort:          r.LocalPort,
		RemotePort:         r.RemotePort,
		SumBefore:          r.SummarisedBefore(),
	}
	c.SumStream, c.SumFrames = r.SummaryRun()
	c.H2CFrames0, c.FirstFrameOff = r.H2CFrames()
	if !r.IsCut() {
		c.PayloadSkipped0 = 1
		return
	}
	c.HaveReduce = 1
	c.DataLen = uint16(r.CutLen)
	copy(c.inline[:], r.CutData[:r.CutLen])
}

// DetachRecord is DetachRecordTo into a new event
func DetachRecord(r *H2CRecord) *SocketDataUploadEvent {
	c := &SocketDataUploadEvent{}
	DetachRecordTo(r, c)
	return c
}

// DetachTo fills c with the socket data event of the agent b stands for, without its data buffer: b is a
// SocketDataUploadEvent or an H2CRecord (DetachRecordTo); false for anything else
func DetachTo(b buffer.SocketDataBuffer, c *SocketDataUploadEvent) bool {
	switch e := b.(type) {
	case *SocketDataUploadEvent:
		e.DetachTo(c)
	case *H2CRecord:
		DetachRecordTo(e, c)
	default:
		return false
	}
	return true
}

// CanMergeCalls is first.CanMergeDetail(next) for the socket data events of the agent, either of them an
// H2CRecord standing for its event
func CanMergeCalls(first, next SocketDetail) bool {
	fn, start, ok := mergeKey(first)
	if !ok {
		return false
	}
	nextFn, nextStart, ok := mergeKey(next)
	return ok && fn == nextFn && sameMinute(start, nextStart)
}

// mergeKey is what CanMergeDetail compares of the detail: its syscall and its start time; false when the
// detail is not a socket data event of the agent
func mergeKey(other SocketDetail) (functionName uint32, startTime uint64, ok bool) {
	switch next := other.(type) {
	case *SocketDataUploadEvent:
		return next.FunctionName, next.StartTime0, true
	case *H2CRecord:
		return uint32(next.FunctionName), next.StartTime0, true
	}
	return 0, 0, false
}
