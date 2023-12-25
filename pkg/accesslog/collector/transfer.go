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
	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/module"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var transferCollectInstance = NewTransferCollector()

type TransferCollector struct {
	protocolQueue *protocols.AnalyzeQueue
}

func NewTransferCollector() *TransferCollector {
	return &TransferCollector{}
}

func (t *TransferCollector) Start(_ *module.Manager, context *common.AccessLogContext) error {
	queue, err := protocols.NewAnalyzeQueue(context)
	if err != nil {
		return err
	}

	t.protocolQueue = queue
	t.protocolQueue.Start(context.RuntimeContext)

	context.BPF.AddTracePoint("skb", "skb_copy_datagram_iovec", context.BPF.TracepointSkbCopyDatagramIovec)

	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"security_socket_sendmsg": context.BPF.SecuritySocketSendmsg})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"security_socket_recvmsg": context.BPF.SecuritySocketRecvmsg})

	context.BPF.AddTracePoint("syscalls", "sys_enter_write", context.BPF.TracepointEnterWrite)
	context.BPF.AddTracePoint("syscalls", "sys_exit_write", context.BPF.TracepointExitWrite)
	context.BPF.AddTracePoint("syscalls", "sys_enter_read", context.BPF.TracepointEnterRead)
	context.BPF.AddTracePoint("syscalls", "sys_exit_read", context.BPF.TracepointExitRead)
	context.BPF.AddTracePoint("syscalls", "sys_enter_sendto", context.BPF.TracepointEnterSendto)
	context.BPF.AddTracePoint("syscalls", "sys_exit_sendto", context.BPF.TracepointExitSendto)
	context.BPF.AddTracePoint("syscalls", "sys_enter_writev", context.BPF.TracepointEnterWritev)
	context.BPF.AddTracePoint("syscalls", "sys_exit_writev", context.BPF.TracepointExitWritev)
	context.BPF.AddTracePoint("syscalls", "sys_enter_sendmsg", context.BPF.TracepointEnterSendmsg)
	context.BPF.AddTracePoint("syscalls", "sys_exit_sendmsg", context.BPF.TracepointExitSendmsg)
	context.BPF.AddTracePoint("syscalls", "sys_enter_sendmmsg", context.BPF.TracepointEnterSendmmsg)
	context.BPF.AddTracePoint("syscalls", "sys_exit_sendmmsg", context.BPF.TracepointExitSendmmsg)
	context.BPF.AddSysCall("recv", context.BPF.SysRecv, context.BPF.SysRecvRet)
	context.BPF.AddTracePoint("syscalls", "sys_enter_recvfrom", context.BPF.TracepointEnterRecvfrom)
	context.BPF.AddTracePoint("syscalls", "sys_exit_recvfrom", context.BPF.TracepointExitRecvfrom)
	context.BPF.AddTracePoint("syscalls", "sys_enter_recvmsg", context.BPF.TracepointEnterRecvmsg)
	context.BPF.AddTracePoint("syscalls", "sys_exit_recvmsg", context.BPF.TracepointExitRecvmsg)
	context.BPF.AddTracePoint("syscalls", "sys_enter_recvmmsg", context.BPF.TracepointEnterRecvmmsg)
	context.BPF.AddTracePoint("syscalls", "sys_exit_recvmmsg", context.BPF.TracepointExitRecvmmsg)

	return nil
}

func (t *TransferCollector) Stop() {
}
