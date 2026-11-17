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
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/docker/go-units"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/analyze"
	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols/http1skip"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
)

var transferCollectInstance = NewTransferCollector(nil)

// ExtraProtocols makes the protocols an agent analyzes besides HTTP/1.x and HTTP/2 (such as TLS), once per
// analyzing partition
type ExtraProtocols func(mgr *module.Manager, context *common.AccessLogContext) []protocols.Protocol

// TransferCollector collects the socket data events of the access log (the socket data and the details of
// every socket call, bpf/accesslog/include/socket_data_event.h), the per-CPU batches of HTTP/2 call records and
// the h2c payload summaries, and hands them to the analyzing partitions by connection. It also attaches the
// "tcp_sendmsg" kprobe that gets the socket role, in case the connection is not created by connect/accept.
type TransferCollector struct {
	eventQueue *btf.EventQueue
	extra      ExtraProtocols
}

// NewTransferCollector makes the transfer collector; extra, when not nil, adds the protocols of an agent
func NewTransferCollector(extra ExtraProtocols) *TransferCollector {
	return &TransferCollector{extra: extra}
}

func (t *TransferCollector) Start(mgr *module.Manager, context *common.AccessLogContext) error {
	perCPUBufferSize, err := validateProtocolAnalyze(&context.Config.ProtocolAnalyze)
	if err != nil {
		return err
	}
	// self start the event queue
	t.startEventQueue(mgr, context, perCPUBufferSize)

	// the hooks with a trampoline twin attach it where the kernel runs it (rover pkg/accesslog/bpf/attach.go):
	// access_log.bpf.attach_mode tracepoint keeps the tracepoints and kprobes
	b := context.BPF
	b.AddKprobeHook("tcp_sendmsg", b.TcpSendmsg, b.FentryTcpSendmsg)

	b.AddTracePointHook("skb", "skb_copy_datagram_iovec", b.TracepointSkbCopyDatagramIovec, b.RawTpSkbCopyDatagramIovec)

	b.AddKprobeHook("security_socket_sendmsg", b.SecuritySocketSendmsg, b.FentrySecuritySocketSendmsg)
	b.AddKprobeHook("security_socket_recvmsg", b.SecuritySocketRecvmsg, b.FentrySecuritySocketRecvmsg)

	b.AddSyscall("write", b.TracepointEnterWrite, b.TracepointExitWrite, b.FentryEnterWrite, b.FexitExitWrite)
	b.AddSyscall("read", b.TracepointEnterRead, b.TracepointExitRead, b.FentryEnterRead, b.FexitExitRead)
	b.AddSyscall("readv", b.TracepointEnterReadv, b.TracepointExitReadv, b.FentryEnterReadv, b.FexitExitReadv)
	b.AddSyscall("sendto", b.TracepointEnterSendto, b.TracepointExitSendto, b.FentryEnterSendto, b.FexitExitSendto)
	b.AddSyscall("writev", b.TracepointEnterWritev, b.TracepointExitWritev, b.FentryEnterWritev, b.FexitExitWritev)
	b.AddSyscall("sendmsg", b.TracepointEnterSendmsg, b.TracepointExitSendmsg, b.FentryEnterSendmsg, b.FexitExitSendmsg)
	b.AddSyscall("sendmmsg", b.TracepointEnterSendmmsg, b.TracepointExitSendmmsg, b.FentryEnterSendmmsg, b.FexitExitSendmmsg)
	context.BPF.AddSysCall("recv", context.BPF.SysRecv, context.BPF.SysRecvRet)
	b.AddSyscall("recvfrom", b.TracepointEnterRecvfrom, b.TracepointExitRecvfrom, b.FentryEnterRecvfrom, b.FexitExitRecvfrom)
	b.AddSyscall("recvmsg", b.TracepointEnterRecvmsg, b.TracepointExitRecvmsg, b.FentryEnterRecvmsg, b.FexitExitRecvmsg)
	b.AddSyscall("recvmmsg", b.TracepointEnterRecvmmsg, b.TracepointExitRecvmmsg, b.FentryEnterRecvmmsg, b.FexitExitRecvmmsg)
	// the entry a thread keeps in socket_data_args between its socket calls goes when the thread exits
	context.BPF.AddTracePoint("sched", "sched_process_exit", context.BPF.TracepointSchedProcessExit)

	return nil
}

// validateProtocolAnalyze checks access_log.protocol_analyze and gives the size of the per-CPU buffer
func validateProtocolAnalyze(config *common.ProtocolAnalyzeConfig) (int64, error) {
	perCPUBufferSize, err := units.RAMInBytes(config.PerCPUBufferSize)
	if err != nil {
		return 0, fmt.Errorf("access_log.protocol_analyze.per_cpu_buffer: %v", err)
	}
	if int(perCPUBufferSize) < os.Getpagesize() {
		return 0, fmt.Errorf("access_log.protocol_analyze.per_cpu_buffer must be at least %dB", os.Getpagesize())
	}
	if config.AnalyzeParallelCount() < 1 {
		return 0, fmt.Errorf("access_log.protocol_analyze.analyze_parallels must be at least 1")
	}
	if config.ParseParallels < 1 {
		return 0, fmt.Errorf("access_log.protocol_analyze.parse_parallels must be at least 1")
	}
	if config.QueueSize < 1 {
		return 0, fmt.Errorf("access_log.protocol_analyze.queue_size must be at least 1")
	}
	return perCPUBufferSize, nil
}

func (t *TransferCollector) startEventQueue(mgr *module.Manager, context *common.AccessLogContext, perCPUBufferSize int64) {
	http1Analyze := analyze.NewHTTP1Analyze(mgr, context)
	http2Analyze := analyze.NewHTTP2Analyze(context)
	var extra func() []protocols.Protocol
	if t.extra != nil {
		extra = func() []protocols.Protocol { return t.extra(mgr, context) }
	}
	t.eventQueue = btf.NewEventQueue("socket data analyzer", context.Config.ProtocolAnalyze.AnalyzeParallelCount(), context.Config.ProtocolAnalyze.QueueSize,
		func(num int) btf.PartitionContext {
			analyzers := []protocols.Protocol{
				protocols.NewHTTP1Analyzer(context, http1Analyze),
				protocols.NewHTTP2Analyzer(context, http2Analyze),
			}
			if extra != nil {
				analyzers = append(analyzers, extra()...)
			}
			return analyze.NewPartitionContext(context, protocols.NewPartitionContext(context, num, analyzers))
		})
	// the events take a pooled buffer for their data, so one event in use costs its struct besides it
	buffer.EnableMemoryProtectionFromConfig(context.Config.ProtocolAnalyze.MemoryProtection(events.EventSize))
	// the events hold their data in a pooled buffer, released apart from the event: the event lists of the
	// buffers may take their elements from slabs, which keep only the metadata of a released event alive
	buffer.SetEventListSlab(32)
	// the connections that lost an event to the memory protection drop the rest of the cut message
	observers := []func(sample []byte){noteDroppedForGaps, countDroppedRecord}
	if context.Config.ProtocolAnalyze.SkipHTTP1BodyPayload {
		// a call small enough for the event itself takes no pooled buffer: nothing to save by skipping it
		tracker := http1skip.NewTracker(events.InlineDataSize + 1)
		events.SetHTTP1BodySkipper(tracker)
		observers = append(observers, events.DroppedSampleObserver(tracker))
	}
	btf.SetDroppedSampleObserver(context.BPF.SocketDataUploadQueue.String(), droppedSampleObserver(observers...))
	// the per-CPU batches of skipped and tail-cut HTTP/2 call records (batch_h2c_records): every record is
	// routed to its connection as the event it stands for, admitted by the memory protection on its own
	btf.SetBatchSampleSplitter(context.BPF.SocketDataUploadQueue.String(), events.SplitH2CBatch)
	if buffer.MemoryBudget() > 0 {
		// under memory pressure BPF sends the socket calls without their data, and the reader takes those
		// events for refused ones (the same gap handling, counted as dropped), then decodes them into the
		// kernel logs of their calls. The listener clears the flag at once and the pressure is evaluated on
		// every release and every second, so the flag never stays set.
		btf.SetShedSampleDetector(context.BPF.SocketDataUploadQueue.String(), isShedRecord, supplyShedEvent)
		pressure := context.BPF.SocketDataPressureMap
		buffer.SetPressureListener(func(on bool) error {
			value := uint32(0)
			if on {
				value = 1
			}
			return pressure.Update(uint32(0), value, ebpf.UpdateAny)
		})
	}
	// an event read but not consumed yet is on its way, not missing, for the HTTP/2 parser (btf/delivery.go)
	t.eventQueue.TrackDelivery()
	t.eventQueue.RegisterReceiver(context.BPF.SocketDataUploadQueue, int(perCPUBufferSize),
		context.Config.ProtocolAnalyze.ParseParallels, func() interface{} {
			// only the admission is decided here: how much data the event carries is known when it is
			// read, and the buffer is taken then, from the pool class that fits it
			if !buffer.AcquireEvent() {
				return nil // memory protection active: the event is dropped by the reader
			}
			// an event of a call without protocol comes back once its kernel log is flushed
			return events.AcquireUploadEvent()
		}, func(data interface{}) int {
			if record, ok := data.(*events.H2CRecord); ok {
				// a record of a batch the splitter routes (SplitH2CBatch)
				return int(record.ConnectionID)
			}
			if summary, ok := data.(*events.H2CSummary); ok {
				// a summary of skipped DATA payload calls a batch carried
				return int(summary.ConnectionID)
			}
			return int(data.(*events.SocketDataUploadEvent).ConnectionID)
		})
	// the summaries are set before the partitions run: a stream that ends before would not drain its summaries
	summaries := t.newH2CSummaries(context)
	t.eventQueue.Start(context.RuntimeContext, context.BPF.Linker)
	if summaries != nil {
		// the flush pushes to the partitions: after they started
		summaries.Start(context.RuntimeContext)
	}
}

// newH2CSummaries makes (and sets) the user space of the summaries of the skipped h2c DATA payload
// (summarize_h2c_payload) when the BPF side has them on, nil otherwise: the drained summaries go to the partition
// of their connection, like the ones BPF sends in its batches
func (t *TransferCollector) newH2CSummaries(context *common.AccessLogContext) *analyze.H2CSummaries {
	if !context.ConnectionMgr.SummarizeH2CPayload() || context.BPF.H2cSumMap == nil {
		return nil
	}
	queue := t.eventQueue
	summaries := analyze.NewH2CSummaries(context.BPF.H2cSumMap, context.BPF.H2cSumEpochMap,
		context.BPF.ActiveConnectionMap, func(s *events.H2CSummary) {
			queue.Push(int(s.ConnectionID), s)
		})
	analyze.SetH2CSummaries(summaries)
	return summaries
}

func (t *TransferCollector) Stop() {
}
