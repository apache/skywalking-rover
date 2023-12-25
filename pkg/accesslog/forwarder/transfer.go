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
	registerKernelLogBuilder(common.LogTypeKernelTransfer, kernelTransferLogBuilder)
}

func SendTransferNoProtocolEvent(context *common.AccessLogContext, event *events.SocketDetailEvent) {
	context.Queue.AppendKernelLog(common.LogTypeKernelTransfer, event)
}

func kernelTransferLogBuilder(event events.Event) *v3.AccessLogKernelLog {
	transferEvent := event.(*events.SocketDetailEvent)
	// process the read or write
	switch transferEvent.FunctionName.GetSocketOperationType() {
	case enums.SocketOperationTypeWrite:
		return &v3.AccessLogKernelLog{
			Operation: &v3.AccessLogKernelLog_Write{
				Write: &v3.AccessLogKernelWriteOperation{
					StartTime: BuildOffsetTimestamp(transferEvent.StartTime),
					EndTime:   BuildOffsetTimestamp(transferEvent.EndTime),
					Syscall:   parseWriteSyscall(transferEvent.FunctionName),
					L4Metrics: &v3.AccessLogKernelWriteL4Metrics{
						TotalDuration:               uint64(transferEvent.L4Duration),
						TotalTransmitPackageCount:   int64(transferEvent.L4PackageCount),
						TotalRetransmitPackageCount: int64(transferEvent.L4RetransmitPackageCount),
						TotalPackageSize:            int64(transferEvent.L4TotalPackageSize),
					},
					L3Metrics: &v3.AccessLogKernelWriteL3Metrics{
						TotalDuration:           uint64(transferEvent.L3Duration),
						TotalLocalDuration:      uint64(transferEvent.L3LocalDuration),
						TotalOutputDuration:     uint64(transferEvent.L3OutputDuration),
						TotalResolveMACCount:    uint64(transferEvent.L3ResolveMacCount),
						TotalResolveMACDuration: uint64(transferEvent.L3ResolveMacDuration),
						TotalNetFilterCount:     uint64(transferEvent.L3NetFilterCount),
						TotalNetFilterDuration:  uint64(transferEvent.L3NetFilterDuration),
					},
					L2Metrics: &v3.AccessLogKernelWriteL2Metrics{
						TotalDuration:              uint64(transferEvent.L2Duration),
						Ifindex:                    transferEvent.IfIndex,
						TotalEnterQueueBufferCount: uint64(transferEvent.L2EnterQueueCount),
						TotalReadySendDuration:     uint64(transferEvent.L2ReadySendDuration),
						TotalNetDeviceSendDuration: uint64(transferEvent.L2SendDuration),
					},
				},
			},
		}
	case enums.SocketOperationTypeRead:
		return &v3.AccessLogKernelLog{
			Operation: &v3.AccessLogKernelLog_Read{
				Read: &v3.AccessLogKernelReadOperation{
					StartTime: BuildOffsetTimestamp(transferEvent.StartTime),
					EndTime:   BuildOffsetTimestamp(transferEvent.EndTime),
					Syscall:   parseReadSyscall(transferEvent.FunctionName),
					L2Metrics: &v3.AccessLogKernelReadL2Metrics{
						Ifindex:                          transferEvent.IfIndex,
						TotalPackageCount:                uint32(transferEvent.L4PackageCount),
						TotalPackageSize:                 transferEvent.L4TotalPackageSize,
						TotalPackageToQueueDuration:      uint64(transferEvent.L2PackageToQueueDuration),
						TotalRcvPackageFromQueueDuration: transferEvent.L4PackageRcvFromQueueDuration,
					},
					L3Metrics: &v3.AccessLogKernelReadL3Metrics{
						TotalDuration:          uint64(transferEvent.L3Duration),
						TotalRecvDuration:      uint64(transferEvent.L3TotalRcvDuration),
						TotalLocalDuration:     uint64(transferEvent.L3LocalDuration),
						TotalNetFilterCount:    uint64(transferEvent.L3NetFilterCount),
						TotalNetFilterDuration: uint64(transferEvent.L3NetFilterDuration),
					},
					L4Metrics: &v3.AccessLogKernelReadL4Metrics{
						TotalDuration: uint64(transferEvent.L4Duration),
					},
				},
			},
		}
	}
	return nil
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
