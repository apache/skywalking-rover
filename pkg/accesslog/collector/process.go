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
	"bytes"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
)

var processLog = logger.GetLogger("access_log", "collector", "process")

// processExecuteQueueParallels reads the process events with more than one goroutine. The queue is
// low volume by design - the kernel filters before emitting - but a process that is reported and
// then handled late is a process whose access logs sit waiting, so keep the drain prompt.
const processExecuteQueueParallels = 2

// processExecuteQueuePerCPUBuffer sizes the per-CPU perf buffer. A burst of process starts (a pod
// rolling out, a CronJob firing) must not be dropped, and the events are 32 bytes each.
const processExecuteQueuePerCPUBuffer = 32 * 1024

var processCollectInstance = NewProcessCollector()

// ProcessCollector notices processes as the kernel starts them, rather than waiting for the
// periodic /proc scan to come round.
//
// The scan cannot see a process that starts and exits between two of its rounds, so anything short
// lived - a `kubectl exec`, a CronJob, a CGI worker - produces socket traffic that is dropped in the
// kernel because the process was never marked as monitored. This collector closes that window: the
// kernel marks a process on sight and tells user space, which then confirms or removes it.
type ProcessCollector struct {
}

func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{}
}

func (p *ProcessCollector) Start(_ *module.Manager, context *common.AccessLogContext) error {
	// Nothing is attached unless user space can actually judge what the kernel reports. Leaving the
	// tracepoints off is not a degraded mode - it is exactly the behavior before this collector
	// existed, with the periodic scan still discovering every process that lives long enough.
	if !context.ConnectionMgr.ProcessExecuteMonitorReady() {
		processLog.Info("not monitoring process execution; short-lived processes will only be " +
			"discovered by the periodic process scan")
		return nil
	}

	// exec is what catches a short-lived process: only there does it carry its own pid, its final
	// cgroup and its final name. fork additionally keeps the monitor map free of pids left behind by
	// dead processes, and catches a process that only ever forks.
	context.BPF.AddTracePoint("sched", "sched_process_exec", context.BPF.TracepointSchedProcessExec)
	context.BPF.AddTracePoint("sched", "sched_process_fork", context.BPF.TracepointSchedProcessFork)

	context.BPF.ReadEventAsyncWithBufferSize(context.BPF.ProcessExecuteQueue, func(data interface{}) {
		event := data.(*ProcessExecuteEvent)
		context.ConnectionMgr.OnNewProcessExecuting(int32(event.PID), event.CgroupID, event.CommString())
	}, processExecuteQueuePerCPUBuffer, processExecuteQueueParallels, func() interface{} {
		return &ProcessExecuteEvent{}
	})

	return nil
}

func (p *ProcessCollector) Stop() {
}

// ProcessExecuteEvent must keep the exact memory layout of struct process_execute_event in
// bpf/accesslog/process/process.c: the perf record is decoded with binary.Read, which lays the
// fields out back to back and would silently shift every field after an implicit C alignment gap.
// PAD0 is the explicit stand-in for the padding the compiler inserts before the 8-byte aligned
// CgroupID.
type ProcessExecuteEvent struct {
	PID      uint32
	PAD0     uint32
	CgroupID uint64
	Comm     [16]byte
}

// CommString returns the kernel task name as a string, dropping the NUL padding that
// bpf_get_current_comm leaves in the fixed size buffer.
func (e *ProcessExecuteEvent) CommString() string {
	if idx := bytes.IndexByte(e.Comm[:], 0); idx >= 0 {
		return string(e.Comm[:idx])
	}
	return string(e.Comm[:])
}
