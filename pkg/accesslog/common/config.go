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
	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
)

type Config struct {
	module.Config

	Active            bool                    `mapstructure:"active"`
	ExcludeNamespaces string                  `mapstructure:"exclude_namespaces"`
	ExcludeClusters   string                  `mapstructure:"exclude_cluster"`
	Flush             FlushConfig             `mapstructure:"flush"`
	ConnectionAnalyze ConnectionAnalyzeConfig `mapstructure:"connection_analyze"`
	ProtocolAnalyze   ProtocolAnalyzeConfig   `mapstructure:"protocol_analyze"`
	Sender            SenderConfig            `mapstructure:"sender"`
	EventReader       EventReaderConfig       `mapstructure:"event_reader"`
	BPF               BPFConfig               `mapstructure:"bpf"`
	KernelMetrics     KernelMetricsConfig     `mapstructure:"kernel_metrics"`
}

// KernelMetricsConfig selects the metrics of the kernel logs besides those every log has
type KernelMetricsConfig struct {
	// L2L3: the kernel logs of the reads and writes carry the L2 and L3 metrics of their socket calls (the interface,
	// the time in the IP layer, the netfilter hooks, the neighbor resolution and the device queue) and the L4 duration,
	// retransmits and transmitted packages, taken by the programs of bpf/accesslog/l24 that only attach with it on
	L2L3 bool `mapstructure:"l2_l3"`
}

// BPFConfig selects how the access log programs attach to the kernel
type BPFConfig struct {
	// AttachMode: auto (the default, also when empty) attaches the socket call programs from BPF trampolines or raw
	// tracepoints where the kernel runs them, and from the syscall tracepoints and kprobes elsewhere; trampoline is
	// auto without the check that the kernel runs trampoline programs without preemption; tracepoint keeps the
	// syscall tracepoints and kprobes everywhere (see pkg/accesslog/bpf/attach.go)
	AttachMode string `mapstructure:"attach_mode"`
	// NATHook: where the remote address behind a DNAT is read: auto (the default, also when empty), confirm, kprobe
	// or legacy (see pkg/accesslog/bpf/nat.go)
	NATHook string `mapstructure:"nat_hook"`
}

// LoaderOptions are the options of the BPF loader of the configuration
func (c *Config) LoaderOptions() bpf.LoaderOptions {
	return bpf.LoaderOptions{AttachMode: c.BPF.AttachMode, NATHook: c.BPF.NATHook, KernelMetricsL2L3: c.KernelMetrics.L2L3}
}

// SenderConfig controls how the access logs are streamed to the backend
type SenderConfig struct {
	// Parallelism: the count of streams sending at the same time. The backend consumes a stream serially,
	// so one stream bounds the access log rate; a single batch still goes over a single stream.
	Parallelism int `mapstructure:"parallelism"`
	// MaxLogsPerSend: the most logs (protocol logs and kernel logs) one stream carries
	MaxLogsPerSend int `mapstructure:"max_logs_per_send"`
	// MaxPendingLogs: the most logs waiting to be sent; past it the oldest batches are dropped (counted).
	// It bounds a count of logs, not bytes. 0, the default, does not bound them.
	MaxPendingLogs int `mapstructure:"max_pending_logs"`
}

// EventReaderConfig controls how the perf event rings of the socket data and connection events are read
type EventReaderConfig struct {
	// WakeupEvents: wake the reader once this many events are in one per CPU ring instead of for every
	// event, 0 for every event. The rings are flushed every FlushPeriod, so no event waits longer.
	WakeupEvents int `mapstructure:"wakeup_events"`
	// FlushPeriod: how often the rings are flushed when WakeupEvents or BatchSize is set, and the longest a
	// partial batch waits (e.g. 100ms)
	FlushPeriod string `mapstructure:"flush_period"`
	// BatchSize: hand the events to the analyzing partitions in batches of up to this many, collected
	// until the ring is drained or FlushPeriod has passed, instead of one by one; 0 or 1 hands them one by
	// one. The queue size of the partitions stays a count of events.
	BatchSize int `mapstructure:"batch_size"`
}

type FlushConfig struct {
	MaxCountOneStream int    `mapstructure:"max_count"`
	Period            string `mapstructure:"period"`
	// MergeKernelLogs: report one kernel log per operation of a message instead of one per socket
	// syscall, with the counters and durations summed. It bounds the access log volume of large
	// messages, which otherwise costs one record per syscall, at the price of the per syscall timing.
	MergeKernelLogs bool `mapstructure:"merge_kernel_logs"`
}

type ConnectionAnalyzeConfig struct {
	PerCPUBufferSize string `mapstructure:"per_cpu_buffer"`
	ParseParallels   int    `mapstructure:"parse_parallels"`
	// AnalyzeParallels: a positive integer, or "auto" (or 0) for 2 x GOMAXPROCS bounded to [2, 10]
	AnalyzeParallels Parallels `mapstructure:"analyze_parallels"`
	QueueSize        int       `mapstructure:"queue_size"`

	analyzeParallels int
}

type ProtocolAnalyzeConfig struct {
	PerCPUBufferSize string `mapstructure:"per_cpu_buffer"`
	ParseParallels   int    `mapstructure:"parse_parallels"`
	// AnalyzeParallels: a positive integer, or "auto" (or 0) for 2 x GOMAXPROCS bounded to [2, 10]
	AnalyzeParallels Parallels `mapstructure:"analyze_parallels"`
	QueueSize        int       `mapstructure:"queue_size"`
	// TriggerEvents: analyze the buffered socket data of a partition as soon as this many data events are
	// pending, instead of only on the flush period tick. Bounds the memory held by the unparsed events
	// (each one keeps a 20 KB buffer until it is parsed). 0 disables the trigger.
	TriggerEvents int `mapstructure:"trigger_events"`
	// MaxMemoryPercent: the socket data events held in memory may take at most this percent of the memory
	// the agent can be allocated (its cgroup limit, else the memory of the host); a new event is dropped
	// (counted) while they hold it. 0 disables it.
	MaxMemoryPercent int `mapstructure:"max_memory_percent"`
	// DropH2CUnusedFrame: do not upload the h2c socket calls that carry only unused frames, see syscalls/h2c.h
	DropH2CUnusedFrame bool `mapstructure:"drop_h2c_unused_frame"`
	// SkipH2CDataPayload: upload the h2c socket calls that lie wholly inside a DATA payload as their size
	// alone, see syscalls/h2c.h. It makes the BPF side follow the frames with or without DropH2CUnusedFrame.
	SkipH2CDataPayload bool `mapstructure:"skip_h2c_data_payload"`
	// BatchH2CRecords: with SkipH2CDataPayload and flush.merge_kernel_logs on, send the skipped and tail-cut
	// h2c socket calls as compact records in per-CPU batches (one perf event for many calls) instead of one
	// event each, see common/h2c_batch.h. The records carry exactly what the events would, so the access logs
	// and kernel logs stay the same. Only the agents built with the batching BPF side use it.
	BatchH2CRecords bool `mapstructure:"batch_h2c_records"`
	// SummarizeH2CPayload: with BatchH2CRecords on, do not send the h2c socket calls that lie wholly inside a
	// DATA payload at all: BPF sums them up per stream (common/h2c_sum.h) and the parser counts their bytes from
	// the positional events, so the access logs and the kernel logs of the messages stay the same. Only the
	// agents built with the summarizing BPF side use it.
	SummarizeH2CPayload bool `mapstructure:"summarize_h2c_payload"`
	// AnalyzeTraceContext: the HTTP logs carry the tracing context of their requests (the SkyWalking sw8 and the Zipkin
	// b3 headers). Off, no header is looked at for it.
	AnalyzeTraceContext bool `mapstructure:"analyze_trace_context"`
	// SkipHTTP1BodyPayload: decode the HTTP/1 socket calls that lie wholly inside a Content-Length body
	// without their bytes (the analyzer only counts them), see collector/protocols/http1skip
	SkipHTTP1BodyPayload bool `mapstructure:"skip_http1_body_payload"`
	// SkipHTTP1BodyPayloadBPF: upload the HTTP/1 socket calls that lie wholly inside a Content-Length body
	// as their size alone, see syscalls/h1.h. With merge_kernel_logs on, the consecutive calls of one body
	// are uploaded as one event. It works with or without SkipHTTP1BodyPayload.
	SkipHTTP1BodyPayloadBPF bool `mapstructure:"skip_http1_body_payload_bpf"`

	analyzeParallels int
}

func (c *Config) IsActive() bool {
	return c.Active
}

// MemoryProtection is the memory protection configuration; eventSize is the size of the socket data event
// struct, 0 for an event that embeds the 20KB array
func (c *ProtocolAnalyzeConfig) MemoryProtection(eventSize int) buffer.MemoryConfig {
	return buffer.MemoryConfig{MaxPercent: c.MaxMemoryPercent, EventSize: eventSize}
}
