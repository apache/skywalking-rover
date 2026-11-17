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

package forwarder

import (
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

type KernelLogBuilder func(data events.Event) *v3.AccessLogKernelLog

var kernelLogBuilders = make([]KernelLogBuilder, 10)

func RegisterKernelLogBuilder(tp common.LogType, builder KernelLogBuilder) {
	kernelLogBuilders[tp] = builder
	if tp == common.LogTypeKernelTransfer {
		// the filler of the previous builder does not fill the logs of this one, see RegisterKernelTransferLog
		transferLogFiller = nil
	}
}

func BuildKernelLogFromEvent(tp common.LogType, event events.Event) *v3.AccessLogKernelLog {
	builder := kernelLogBuilders[tp]
	if builder == nil {
		return nil
	}
	return builder(event)
}

// TransferLog is a kernel transfer log (a read or a write) as plain values. The kernel logs of a protocol
// log are encoded as soon as they are built and never merged, so the sender writes them from this (see
// sender.BatchLogs.AppendTransferProtocolLog) instead of building the messages; the filler of a
// KernelLogBuilder must give the bytes of the messages the builder gives.
type TransferLog struct {
	// Write is a write operation (AccessLogKernelLog.write), a read (AccessLogKernelLog.read) otherwise
	Write bool
	// Syscall is the AccessLogKernelWriteSyscall or AccessLogKernelReadSyscall
	Syscall            int32
	StartTime, EndTime uint64
	// Metrics are the metrics messages of the operation, its fields 4 to 6: L4, L3, L2 of a write and L2,
	// L3, L4 of a read. A message is written when its HasMetrics is set, with its varint fields by number
	// (an int64 as its two's complement); a number the message does not have, and the loss package
	// metrics (field 4 of the write L4), stay zero.
	HasMetrics [3]bool
	Metrics    [3][9]uint64
}

// TransferLogFiller gives the TransferLog of a kernel transfer event, false when it has no log. The log is
// returned, not filled through a pointer, which would move it to the heap behind the call of a func value.
type TransferLogFiller func(event events.Event) (TransferLog, bool)

var transferLogFiller TransferLogFiller

// RegisterKernelTransferLog registers the KernelLogBuilder of LogTypeKernelTransfer with its filler, which
// must give the bytes of the logs the builder gives
func RegisterKernelTransferLog(builder KernelLogBuilder, filler TransferLogFiller) {
	RegisterKernelLogBuilder(common.LogTypeKernelTransfer, builder)
	transferLogFiller = filler
}

// BuildTransferLog gives the TransferLog of the event: ok is false when the event has no log, and filled
// is false when no filler is registered, the log is then built with BuildKernelLogFromEvent
func BuildTransferLog(event events.Event) (log TransferLog, filled, ok bool) {
	if transferLogFiller == nil {
		return log, false, false
	}
	log, ok = transferLogFiller(event)
	return log, true, ok
}

func BuildOffsetTimestamp(t uint64) *v3.EBPFTimestamp {
	return new(OffsetTimestamp).Build(t)
}

// BuildOffsetTimestamps builds the start and the end timestamp of a log from one allocation
func BuildOffsetTimestamps(start, end uint64) (startTime, endTime *v3.EBPFTimestamp) {
	timestamps := new([2]OffsetTimestamp)
	return timestamps[0].Build(start), timestamps[1].Build(end)
}

// OffsetTimestamp holds the three messages of an offset timestamp, so building one is a single
// allocation (or none, when it is a field of a larger allocation, see kernelTransferLogBuilder)
type OffsetTimestamp struct {
	timestamp v3.EBPFTimestamp
	oneof     v3.EBPFTimestamp_Offset
	offset    v3.EBPFOffsetTimestamp
}

// Build fills the timestamp with the offset and returns it, the same message as
// &v3.EBPFTimestamp{Timestamp: &v3.EBPFTimestamp_Offset{Offset: &v3.EBPFOffsetTimestamp{Offset: t}}}
func (o *OffsetTimestamp) Build(t uint64) *v3.EBPFTimestamp {
	o.offset.Offset = t
	o.oneof.Offset = &o.offset
	o.timestamp.Timestamp = &o.oneof
	return &o.timestamp
}
