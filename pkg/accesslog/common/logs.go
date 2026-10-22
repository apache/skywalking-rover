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

package common //nolint:revive // package name is acceptable in this context

import (
	"sync/atomic"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

type kernelLogEvent struct {
	logType LogType
	event   events.Event
}

func NewKernelLogEvent(logType LogType, event events.Event) KernelLog {
	return &kernelLogEvent{
		logType: logType,
		event:   event,
	}
}

func (k *kernelLogEvent) Type() LogType {
	return k.logType
}

func (k *kernelLogEvent) Event() events.Event {
	return k.event
}

type ProtocolEventData struct {
	KernelLogs      []events.SocketDetail
	ProtocolLogData *v3.AccessLogProtocolLogs
}

func (r *ProtocolEventData) RelateKernelLogs() []events.SocketDetail {
	return r.KernelLogs
}

func (r *ProtocolEventData) ProtocolLog() *v3.AccessLogProtocolLogs {
	return r.ProtocolLogData
}

// mergeKernelLogs is process wide because reporting one record per operation instead of one per
// syscall is a policy of the agent, not a property of a connection or an analyzer
var mergeKernelLogs atomic.Bool

// SetMergeKernelLogs is called once from the configuration, see events.MergeDetails for what it does
func SetMergeKernelLogs(enabled bool) {
	mergeKernelLogs.Store(enabled)
}

// NewProtocolLogEvent builds the log of one message. The details are merged here, where the message
// is finished, rather than when the log is flushed: between the two they sit in the flush queue, and
// merging first is what keeps the unmerged records out of it.
func NewProtocolLogEvent(kernelLogs []events.SocketDetail, protocolData *v3.AccessLogProtocolLogs) ProtocolLog {
	if mergeKernelLogs.Load() {
		kernelLogs = events.MergeDetails(kernelLogs)
	}
	return &ProtocolEventData{
		KernelLogs:      kernelLogs,
		ProtocolLogData: protocolData,
	}
}
