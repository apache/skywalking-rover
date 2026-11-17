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
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

func init() {
	RegisterKernelTransferLog(kernelTransferLogBuilder, fillTransferLog)
}

func SendTransferNoProtocolEvent(context *common.AccessLogContext, event events.SocketDetail) {
	context.Queue.AppendKernelLog(common.NewKernelLogEvent(common.LogTypeKernelTransfer, event))
}

// SendTransferNoProtocolEventOwned is SendTransferNoProtocolEvent for an event nothing else refers to: the
// flush takes it over and may recycle it once its kernel log is built (common.KernelLog.Owned)
func SendTransferNoProtocolEventOwned(context *common.AccessLogContext, event events.SocketDetail) {
	context.Queue.AppendKernelLog(common.NewOwnedKernelLogEvent(common.LogTypeKernelTransfer, event))
}

// kernelWriteLog and kernelReadLog hold every message of one kernel transfer log, so building one is
// a single allocation instead of one per message
type kernelWriteLog struct {
	log        v3.AccessLogKernelLog
	operation  v3.AccessLogKernelLog_Write
	write      v3.AccessLogKernelWriteOperation
	start, end OffsetTimestamp
	l4         v3.AccessLogKernelWriteL4Metrics
}

type kernelReadLog struct {
	log        v3.AccessLogKernelLog
	operation  v3.AccessLogKernelLog_Read
	read       v3.AccessLogKernelReadOperation
	start, end OffsetTimestamp
	l2         v3.AccessLogKernelReadL2Metrics
}

// transferFields are the fields a kernel transfer log is built of: the details of the socket call the socket data
// event carries (or the event a batch record or a summary stands for), the only details the access log has
func transferFields(event events.Event) (funcName enums.SocketFunctionName, packages uint32, size, start, end uint64) {
	detail, ok := event.(events.SocketDetail)
	if !ok {
		// no transfer detail: function 0 is neither a read nor a write, so no log is built
		return 0, 0, 0, 0, 0
	}
	return detail.GetFunctionName(), detail.GetL4PackageCount(), detail.GetL4TotalPackageSize(), detail.GetStartTime(),
		detail.GetEndTime()
}

// kernelL2L3WriteLog and kernelL2L3ReadLog are kernelWriteLog and kernelReadLog with the messages of the L2 to L4
// details of the call (access_log.kernel_metrics.l2_l3, events.LookupL24)
type kernelL2L3WriteLog struct {
	kernelWriteLog
	l3 v3.AccessLogKernelWriteL3Metrics
	l2 v3.AccessLogKernelWriteL2Metrics
}

type kernelL2L3ReadLog struct {
	kernelReadLog
	l3 v3.AccessLogKernelReadL3Metrics
	l4 v3.AccessLogKernelReadL4Metrics
}

// l24Fields are the L2 to L4 details of the call of the detail event, false without any (the switch is off, or the
// call sent none): the log is then built as without them
func l24Fields(event events.Event) (events.L24Metrics, bool) {
	if !events.L24Enabled() {
		return events.L24Metrics{}, false
	}
	detail, ok := event.(events.SocketDetail)
	if !ok {
		return events.L24Metrics{}, false
	}
	return events.LookupL24(detail)
}

// l24WritePackages are the L4 package count and size of a write with its L2 to L4 details: the sk_buffs
// __tcp_transmit_skb sent while the call was in progress when there were any, those of the event otherwise
func l24WritePackages(m *events.L24Metrics, packages uint32, size uint64) (uint32, uint64) {
	if m.L4TransmitPackageCount > 0 {
		return m.L4TransmitPackageCount, m.L4TransmitPackageSize
	}
	return packages, size
}

func kernelTransferLogBuilder(event events.Event) *v3.AccessLogKernelLog {
	funcName, packages, size, start, end := transferFields(event)
	// process the read or write
	switch funcName.GetSocketOperationType() {
	case enums.SocketOperationTypeWrite:
		if m, ok := l24Fields(event); ok {
			return buildL2L3WriteLog(funcName, packages, size, start, end, &m)
		}
		w := &kernelWriteLog{
			write: v3.AccessLogKernelWriteOperation{
				Syscall: parseWriteSyscall(funcName),
			},
			l4: v3.AccessLogKernelWriteL4Metrics{
				TotalTransmitPackageCount: int64(packages),
				TotalPackageSize:          int64(size),
			},
		}
		w.write.StartTime = w.start.Build(start)
		w.write.EndTime = w.end.Build(end)
		w.write.L4Metrics = &w.l4
		w.operation.Write = &w.write
		w.log.Operation = &w.operation
		return &w.log
	case enums.SocketOperationTypeRead:
		if m, ok := l24Fields(event); ok {
			return buildL2L3ReadLog(funcName, packages, size, start, end, &m)
		}
		r := &kernelReadLog{
			read: v3.AccessLogKernelReadOperation{
				Syscall: parseReadSyscall(funcName),
			},
			l2: v3.AccessLogKernelReadL2Metrics{
				TotalPackageCount: packages,
				TotalPackageSize:  size,
			},
		}
		r.read.StartTime = r.start.Build(start)
		r.read.EndTime = r.end.Build(end)
		r.read.L2Metrics = &r.l2
		r.operation.Read = &r.read
		r.log.Operation = &r.operation
		return &r.log
	}
	return nil
}

// buildL2L3WriteLog is the write log with the L2 to L4 details of its call
func buildL2L3WriteLog(funcName enums.SocketFunctionName, packages uint32, size, start, end uint64,
	m *events.L24Metrics) *v3.AccessLogKernelLog {
	packages, size = l24WritePackages(m, packages, size)
	w := &kernelL2L3WriteLog{}
	w.write.Syscall = parseWriteSyscall(funcName)
	w.l4 = v3.AccessLogKernelWriteL4Metrics{
		TotalDuration:               m.L4Duration,
		TotalTransmitPackageCount:   int64(packages),
		TotalRetransmitPackageCount: int64(m.L4RetransmitPackageCount),
		TotalPackageSize:            int64(size),
	}
	w.l3 = v3.AccessLogKernelWriteL3Metrics{
		TotalDuration:           m.L3Duration,
		TotalLocalDuration:      m.L3LocalDuration,
		TotalOutputDuration:     m.L3OutputDuration,
		TotalResolveMACCount:    uint64(m.L3ResolveMacCount),
		TotalResolveMACDuration: m.L3ResolveMacDuration,
		TotalNetFilterCount:     uint64(m.L3NetFilterCount),
		TotalNetFilterDuration:  m.L3NetFilterDuration,
	}
	w.l2 = v3.AccessLogKernelWriteL2Metrics{
		TotalDuration:              m.L2Duration,
		Ifindex:                    m.IfIndex,
		TotalEnterQueueBufferCount: uint64(m.L2EnterQueueCount),
		TotalReadySendDuration:     m.L2ReadySendDuration,
		TotalNetDeviceSendDuration: m.L2SendDuration,
	}
	w.write.StartTime = w.start.Build(start)
	w.write.EndTime = w.end.Build(end)
	w.write.L4Metrics = &w.l4
	w.write.L3Metrics = &w.l3
	w.write.L2Metrics = &w.l2
	w.operation.Write = &w.write
	w.log.Operation = &w.operation
	return &w.log
}

// buildL2L3ReadLog is the read log with the L2 to L4 details of its call
func buildL2L3ReadLog(funcName enums.SocketFunctionName, packages uint32, size, start, end uint64,
	m *events.L24Metrics) *v3.AccessLogKernelLog {
	r := &kernelL2L3ReadLog{}
	r.read.Syscall = parseReadSyscall(funcName)
	r.l2 = v3.AccessLogKernelReadL2Metrics{
		Ifindex:                          m.IfIndex,
		TotalPackageCount:                packages,
		TotalPackageSize:                 size,
		TotalPackageToQueueDuration:      m.L2PackageToQueueDuration,
		TotalRcvPackageFromQueueDuration: m.L2RcvPackageFromQueueDuration,
	}
	r.l3 = v3.AccessLogKernelReadL3Metrics{
		TotalDuration:          m.L3Duration,
		TotalRecvDuration:      m.L3RcvDuration,
		TotalLocalDuration:     m.L3LocalDuration,
		TotalNetFilterCount:    uint64(m.L3NetFilterCount),
		TotalNetFilterDuration: m.L3NetFilterDuration,
	}
	r.l4 = v3.AccessLogKernelReadL4Metrics{TotalDuration: m.L4Duration}
	r.read.StartTime = r.start.Build(start)
	r.read.EndTime = r.end.Build(end)
	r.read.L2Metrics = &r.l2
	r.read.L3Metrics = &r.l3
	r.read.L4Metrics = &r.l4
	r.operation.Read = &r.read
	r.log.Operation = &r.operation
	return &r.log
}

// fillTransferLog is kernelTransferLogBuilder as a TransferLog: the L4 metrics of a write, the L2 of a read, and all
// three with the L2 to L4 details of the call
func fillTransferLog(event events.Event) (TransferLog, bool) {
	funcName, packages, size, start, end := transferFields(event)
	switch funcName.GetSocketOperationType() {
	case enums.SocketOperationTypeWrite:
		if m, ok := l24Fields(event); ok {
			packages, size = l24WritePackages(&m, packages, size)
			return TransferLog{
				Write:      true,
				Syscall:    int32(parseWriteSyscall(funcName)),
				StartTime:  start,
				EndTime:    end,
				HasMetrics: [3]bool{true, true, true},
				Metrics: [3][9]uint64{
					// L4: duration, transmit, retransmit, (loss), size
					{1: m.L4Duration, 2: uint64(packages), 3: uint64(m.L4RetransmitPackageCount), 5: size},
					// L3: duration, local, output, (4), resolve MAC count and duration, netfilter count and duration
					{1: m.L3Duration, 2: m.L3LocalDuration, 3: m.L3OutputDuration, 5: uint64(m.L3ResolveMacCount),
						6: m.L3ResolveMacDuration, 7: uint64(m.L3NetFilterCount), 8: m.L3NetFilterDuration},
					// L2: duration, ifindex, enter queue count, ready send, device send
					{1: m.L2Duration, 2: uint64(m.IfIndex), 3: uint64(m.L2EnterQueueCount), 4: m.L2ReadySendDuration,
						5: m.L2SendDuration},
				},
			}, true
		}
		return TransferLog{
			Write:      true,
			Syscall:    int32(parseWriteSyscall(funcName)),
			StartTime:  start,
			EndTime:    end,
			HasMetrics: [3]bool{true},
			Metrics:    [3][9]uint64{{2: uint64(packages), 5: size}},
		}, true
	case enums.SocketOperationTypeRead:
		if m, ok := l24Fields(event); ok {
			return TransferLog{
				Syscall:    int32(parseReadSyscall(funcName)),
				StartTime:  start,
				EndTime:    end,
				HasMetrics: [3]bool{true, true, true},
				Metrics: [3][9]uint64{
					// L2: ifindex, count, size, to queue, from queue
					{1: uint64(m.IfIndex), 2: uint64(packages), 3: size, 4: m.L2PackageToQueueDuration,
						5: m.L2RcvPackageFromQueueDuration},
					// L3: duration, recv, local, netfilter count and duration
					{1: m.L3Duration, 2: m.L3RcvDuration, 3: m.L3LocalDuration, 4: uint64(m.L3NetFilterCount),
						5: m.L3NetFilterDuration},
					// L4: duration
					{1: m.L4Duration},
				},
			}, true
		}
		return TransferLog{
			Syscall:    int32(parseReadSyscall(funcName)),
			StartTime:  start,
			EndTime:    end,
			HasMetrics: [3]bool{true},
			Metrics:    [3][9]uint64{{2: uint64(packages), 3: size}},
		}, true
	}
	return TransferLog{}, false
}

func parseReadSyscall(funcName enums.SocketFunctionName) v3.AccessLogKernelReadSyscall {
	switch funcName {
	case enums.SocketFunctionNameRead:
		return v3.AccessLogKernelReadSyscall_Read
	case enums.SocketFunctionNameReadv:
		return v3.AccessLogKernelReadSyscall_Readv
	case enums.SocketFunctionNameRecv:
		return v3.AccessLogKernelReadSyscall_Recv
	case enums.SocketFunctionNameRecvfrom:
		return v3.AccessLogKernelReadSyscall_RecvFrom
	case enums.SocketFunctionNameRecvMsg:
		return v3.AccessLogKernelReadSyscall_RecvMsg
	case enums.SocketFunctionNameRecvMMsg:
		return v3.AccessLogKernelReadSyscall_RecvMmsg
	default:
		return v3.AccessLogKernelReadSyscall_Read
	}
}

func parseWriteSyscall(funcName enums.SocketFunctionName) v3.AccessLogKernelWriteSyscall {
	switch funcName {
	case enums.SocketFunctionNameSend:
		return v3.AccessLogKernelWriteSyscall_Send
	case enums.SocketFunctionNameSendto:
		return v3.AccessLogKernelWriteSyscall_SendTo
	case enums.SocketFunctionNameSendMsg:
		return v3.AccessLogKernelWriteSyscall_SendMsg
	case enums.SocketFunctionNameSendMMSg:
		return v3.AccessLogKernelWriteSyscall_SendMmsg
	case enums.SocketFunctionNameSendFile:
		return v3.AccessLogKernelWriteSyscall_SendFile
	case enums.SocketFunctionNameWrite:
		return v3.AccessLogKernelWriteSyscall_Write
	case enums.SocketFunctionNameWritev:
		return v3.AccessLogKernelWriteSyscall_Writev
	default:
		return v3.AccessLogKernelWriteSyscall_Write
	}
}
