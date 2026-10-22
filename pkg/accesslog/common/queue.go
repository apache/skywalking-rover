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
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/logger"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

var log = logger.GetLogger("access_log", "common")

type KernelLog interface {
	Type() LogType
	Event() events.Event
}

type ProtocolLog interface {
	RelateKernelLogs() []events.SocketDetail
	ProtocolLog() *v3.AccessLogProtocolLogs
}

type Queue struct {
	kernelLogs   chan KernelLog
	protocolLogs chan ProtocolLog

	maxFlushCount int
	period        time.Duration
	consumer      QueueConsumer
	consumeLock   *sync.Mutex

	dropKernelLogCount   int64
	dropProtocolLogCount int64
	// the counters above are reset when they are logged; these are the totals the metrics report
	droppedKernelLogs   int64
	droppedProtocolLogs int64
}

type QueueConsumer interface {
	Consume(kernels chan KernelLog, protocols chan ProtocolLog)
}

func NewQueue(maxFlushCount int, period time.Duration, consumer QueueConsumer) *Queue {
	return &Queue{
		kernelLogs:    make(chan KernelLog, maxFlushCount*3),
		protocolLogs:  make(chan ProtocolLog, maxFlushCount*3),
		maxFlushCount: maxFlushCount,
		period:        period,
		consumer:      consumer,
		consumeLock:   &sync.Mutex{},
	}
}

func (q *Queue) AppendKernelLog(log KernelLog) {
	select {
	case q.kernelLogs <- log:
	default:
		atomic.AddInt64(&q.dropKernelLogCount, 1)
		atomic.AddInt64(&q.droppedKernelLogs, 1)
		return
	}
	q.consumeIfNeed()
}

func (q *Queue) AppendProtocolLog(log ProtocolLog) {
	select {
	case q.protocolLogs <- log:
	default:
		atomic.AddInt64(&q.dropProtocolLogCount, 1)
		atomic.AddInt64(&q.droppedProtocolLogs, 1)
		return
	}
	q.consumeIfNeed()
}

func (q *Queue) consumeIfNeed() {
	if len(q.kernelLogs)+len(q.protocolLogs) >= q.maxFlushCount {
		go q.consume()
	}
}

// RegisterMetrics exposes the depth of the flush queues and what they had to drop
func (q *Queue) RegisterMetrics() {
	telemetry.Register("rover_access_log_kernel_logs_pending",
		"Kernel logs waiting for the next flush", telemetry.Gauge,
		func() float64 { return float64(len(q.kernelLogs)) })
	telemetry.Register("rover_access_log_protocol_logs_pending",
		"Protocol logs waiting for the next flush", telemetry.Gauge,
		func() float64 { return float64(len(q.protocolLogs)) })
	telemetry.Register("rover_access_log_kernel_logs_dropped_total",
		"Kernel logs dropped because the flush queue was full", telemetry.Counter,
		func() float64 { return float64(atomic.LoadInt64(&q.droppedKernelLogs)) })
	telemetry.Register("rover_access_log_protocol_logs_dropped_total",
		"Protocol logs dropped because the flush queue was full", telemetry.Counter,
		func() float64 { return float64(atomic.LoadInt64(&q.droppedProtocolLogs)) })
}

func (q *Queue) Start(ctx context.Context) {
	q.RegisterMetrics()
	go func() {
		timeTicker := time.NewTicker(q.period)
		for {
			select {
			case <-timeTicker.C:
				q.consume()
			case <-ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()
	go func() {
		timeTicker := time.NewTicker(time.Second * 5)
		for {
			select {
			case <-timeTicker.C:
				if q.dropKernelLogCount > 0 || q.dropProtocolLogCount > 0 {
					kernelLogCount := atomic.SwapInt64(&q.dropKernelLogCount, 0)
					protocolLogCount := atomic.SwapInt64(&q.dropProtocolLogCount, 0)
					log.Warnf("drop kernel log count: %d, drop protocol log count: %d", kernelLogCount, protocolLogCount)
				}
			case <-ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()
}

func (q *Queue) consume() {
	if !q.consumeLock.TryLock() {
		log.Debugf("consume lock is locked, skip this consume")
		return
	}
	defer q.consumeLock.Unlock()
	if log.Enable(logrus.DebugLevel) {
		log.Debugf("start to consume kernel logs: %d, protocol logs: %d", len(q.kernelLogs), len(q.protocolLogs))
	}
	q.consumer.Consume(q.kernelLogs, q.protocolLogs)
}
