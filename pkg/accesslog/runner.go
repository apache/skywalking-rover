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

package accesslog

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	process2 "github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/collector"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/sender"
	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/core/backend"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

const (
	kernelAccessLogCacheTime = time.Second * 10
)

var log = logger.GetLogger("access_log", "runner")

// Options are the extension points of the access log an agent sets: everything is optional, the zero value is the
// access log of the rover
type Options struct {
	// MonitorFilter makes the filter of the monitored processes from the static one of the configuration
	// (exclude_namespaces, exclude_cluster); nil uses that one
	MonitorFilter func(static *common.StaticMonitorFilter) (common.MonitorFilter, error)
	// Collectors are the collectors to start; nil starts collector.Collectors()
	Collectors []collector.Collector
	// ExcludeConnection tells that the logs of the connection are not reported; nil reports every connection
	ExcludeConnection func(connection *common.ConnectionInfo) bool
	// OnProtocolLog is told of every protocol log added to a batch with its kernel logs, such as for a service
	// discovery of the agent
	OnProtocolLog func(connection *common.ConnectionInfo, protocolLog common.ProtocolLog)
	// DisableSendMultipleProtocols: a protocol log goes without the kernel logs of its message (they are not
	// reported); OnProtocolLog is still told of it
	DisableSendMultipleProtocols bool
	// DisableResolutionDefer: the logs of a connection whose destination a resolver (the ztunnel lb mapping) has
	// not attached yet are not held back, see common.ConnectionManager.ShouldDeferForResolution; the zero value
	// holds them back for at most the resolution grace period
	DisableResolutionDefer bool
}

// connectionLookup is what the runner asks the connection manager when it builds the logs of a flush
type connectionLookup interface {
	Find(event events.Event) *common.ConnectionInfo
	ShouldDeferForResolution(conn *common.ConnectionInfo) bool
	ProcessIsMonitor(pid uint32) bool
}

type Runner struct {
	context    *common.AccessLogContext
	collectors []collector.Collector
	mgr        *module.Manager
	backendOp  backend.Operator
	ctx        context.Context
	sender     *sender.GRPCSender
	options    Options
	// connections is the connection manager of the context, see connectionLookup
	connections connectionLookup
	// started are the collectors that started, stopOnce stops them once
	started  []collector.Collector
	stopOnce sync.Once

	disableFlushMultipleProtocols bool
	// mergeKernelLogs folds the kernel logs of one message that describe the same operation into one
	// record, see forwarder.MergeKernelLogs for what the backend makes of that
	mergeKernelLogs bool
	// mergeProtocolKernelLogs folds the kernel logs of a protocol log as they are encoded, see
	// sender.BatchLogs.EnableProtocolKernelLogMerge
	mergeProtocolKernelLogs bool
}

func NewRunner(mgr *module.Manager, config *common.Config) (*Runner, error) {
	return NewRunnerWithOptions(mgr, config, Options{})
}

// NewRunnerWithOptions is NewRunner with the extension points of an agent
func NewRunnerWithOptions(mgr *module.Manager, config *common.Config, options Options) (*Runner, error) {
	if err := config.ResolveAnalyzeParallels(); err != nil {
		return nil, err
	}
	bpfLoader, err := bpf.NewLoaderWithOptions(config.LoaderOptions())
	if err != nil {
		return nil, err
	}
	flushDuration, err := time.ParseDuration(config.Flush.Period)
	if err != nil {
		return nil, fmt.Errorf("parse flush period error: %v", err)
	}
	coreModule := mgr.FindModule(core.ModuleName).(core.Operator)
	backendOP := coreModule.BackendOperator()
	staticFilter := common.NewStaticMonitorFilter(strings.Split(config.ExcludeNamespaces, ","), strings.Split(config.ExcludeClusters, ","))
	var monitorFilter common.MonitorFilter = staticFilter
	if options.MonitorFilter != nil {
		if monitorFilter, err = options.MonitorFilter(staticFilter); err != nil {
			return nil, err
		}
	}
	collectors := options.Collectors
	if collectors == nil {
		collectors = collector.Collectors()
	}
	connectionManager := common.NewConnectionManager(config, mgr, bpfLoader, monitorFilter)
	runner := &Runner{
		context: &common.AccessLogContext{
			BPF:           bpfLoader,
			Config:        config,
			ConnectionMgr: connectionManager,
		},
		collectors: collectors,
		mgr:        mgr,
		backendOp:  backendOP,
		sender:     sender.NewGRPCSender(mgr, connectionManager, config.Sender),
		options:    options,

		connections:                   connectionManager,
		disableFlushMultipleProtocols: options.DisableSendMultipleProtocols,
		mergeKernelLogs:               config.Flush.MergeKernelLogs,
	}
	// with the L2 to L4 details of the calls the kernel logs of a message are merged as they are encoded, by their
	// interface and with every metric summed (sender.BatchLogs.EnableProtocolKernelLogMerge), not as details before
	common.SetMergeKernelLogs(config.Flush.MergeKernelLogs && !config.KernelMetrics.L2L3)
	runner.mergeProtocolKernelLogs = config.Flush.MergeKernelLogs && config.KernelMetrics.L2L3
	runner.context.Queue = common.NewQueue(config.Flush.MaxCountOneStream, flushDuration, runner)
	return runner, nil
}

func (r *Runner) Start(ctx context.Context) error {
	r.ctx = ctx
	r.context.RuntimeContext = ctx
	r.context.Queue.Start(ctx)
	r.context.ConnectionMgr.Start(ctx, r.context)
	r.sender.Start(ctx)
	for _, c := range r.collectors {
		if err := c.Start(r.mgr, r.context); err != nil {
			// what started is stopped: the module does not stop a runner that did not start
			r.stop()
			return err
		}
		r.started = append(r.started, c)
	}

	if err := r.context.BPF.HasError(); err != nil {
		r.stop()
		return err
	}

	return nil
}

func (r *Runner) Consume(kernels chan common.KernelLog, protocols chan common.ProtocolLog) {
	if r.backendOp.GetConnectionStatus() != backend.Connected {
		log.Warnf("failure to connect to the backend, skip generating access log")
		return
	}

	batch := r.sender.NewBatch()
	if r.mergeKernelLogs {
		batch.EnableKernelLogMerge()
	}
	if r.mergeProtocolKernelLogs {
		batch.EnableProtocolKernelLogMerge()
	}
	r.buildConnectionLogs(batch, kernels, protocols)
	log.Debugf("ready to send access log, connection count: %d", batch.ConnectionCount())
	r.sender.AddBatch(batch)
}

func (r *Runner) buildConnectionLogs(batch *sender.BatchLogs, kernels chan common.KernelLog, protocols chan common.ProtocolLog) {
	kernelCount := r.buildKernelLogs(kernels, batch)
	protocolCount := r.buildProtocolLogs(protocols, batch)

	log.Infof("building access log, kernel log count: %d, protocol log count: %d", kernelCount, protocolCount)
	r.context.ConnectionMgr.OnBuildConnectionLogFinished()
}

func (r *Runner) buildKernelLogs(kernels chan common.KernelLog, batch *sender.BatchLogs) (logCount int) {
	delayAppends := make([]common.KernelLog, 0)
	defer func() {
		for _, delayAppend := range delayAppends {
			select {
			case kernels <- delayAppend:
			default:
				recycleKernelLogEvent(delayAppend)
				noteDelayedLogDropped()
			}
		}
	}()
	maxCount := len(kernels)
	log.Debugf("found reduce kernel log count is: %d", maxCount)
	for {
		select {
		case kernelLog := <-kernels:
			connection, delay := r.kernelLogConnection(kernelLog)
			if connection != nil {
				// the log is built (or, for a kernel transfer log, encoded without building it) into the batch
				if batch.AppendKernelEvent(connection, kernelLog.Type(), kernelLog.Event()) {
					if log.Enable(logrus.DebugLevel) {
						log.Debugf("append kernel log to the connection for sending, connection ID: %d, random ID: %d, log type: %d",
							connection.ConnectionID, connection.RandomID, kernelLog.Type())
					}
					logCount++
				} else if log.Enable(logrus.DebugLevel) {
					log.Debugf("cannot convert the kernel log to native event, type: %d, connection ID: %d, random ID: %d",
						kernelLog.Type(), connection.ConnectionID, connection.RandomID)
				}
				recycleKernelLogEvent(kernelLog)
			} else if delay {
				delayAppends = append(delayAppends, kernelLog)
			} else {
				recycleKernelLogEvent(kernelLog)
			}
			maxCount--
			if maxCount == 0 {
				return
			}
		default:
			return
		}
	}
}

func (r *Runner) buildProtocolLogs(protocols chan common.ProtocolLog, batch *sender.BatchLogs) (logCount int) {
	delayAppends := make([]common.ProtocolLog, 0)
	defer func() {
		for _, delayAppend := range delayAppends {
			select {
			case protocols <- delayAppend:
			default:
				noteDelayedLogDropped()
			}
		}
	}()
	maxCount := len(protocols)
	log.Debugf("found reduce protocol log count is: %d", maxCount)
	for {
		select {
		case protocolLog := <-protocols:
			connection, details, protocolLogs, delay := r.buildProtocolLog(protocolLog)
			if connection != nil && protocolLogs != nil {
				if kernelLogCount, added := r.appendProtocolLog(batch, connection, details, protocolLogs); added {
					if r.options.OnProtocolLog != nil {
						r.options.OnProtocolLog(connection, protocolLog)
					}
					logCount++
					if log.Enable(logrus.DebugLevel) {
						log.Debugf("append protocol log to the connection, connection ID: %d, random ID: %d, kernel logs count: %d",
							connection.ConnectionID, connection.RandomID, kernelLogCount)
					}
				}
			} else if delay {
				delayAppends = append(delayAppends, protocolLog)
			}
			maxCount--
			if maxCount == 0 {
				return
			}
		default:
			return
		}
	}
}

// delayedLogsDropped counts the logs whose connection was not known yet (or not resolved yet) that could not go back
// into their full queue for the next flush
var (
	delayedLogsDropped atomic.Int64
	lastDelayedDropLog atomic.Int64
)

func noteDelayedLogDropped() {
	total := delayedLogsDropped.Add(1)
	now := time.Now().UnixNano()
	last := lastDelayedDropLog.Load()
	if now-last < int64(time.Minute) || !lastDelayedDropLog.CompareAndSwap(last, now) {
		return
	}
	log.Warnf("dropped an access log waiting for its connection: the log queue is full, %d dropped in total", total)
}

func (r *Runner) shouldReportProcessLog(pid uint32) bool {
	// if the process not monitoring, then check the process is existed or not
	if r.connections.ProcessIsMonitor(pid) {
		return true
	}
	exists, err := process2.PidExists(int32(pid))
	if err != nil {
		log.Warnf("check pid exists error, pid: %d, error: %v", pid, err)
		return false
	}
	if exists {
		return false
	}
	log.Debugf("the log should be also uploaded because the process quick shutdown but the log exist, pid: %d", pid)
	return true
}

// buildProtocolLog gives the connection, the kernel log details and the protocol log of a protocol log, whose
// kernel logs the batch encodes straight from the details, see sender.BatchLogs.AppendTransferProtocolLog
func (r *Runner) buildProtocolLog(protocolLog common.ProtocolLog) (*common.ConnectionInfo,
	[]events.SocketDetail, *v3.AccessLogProtocolLogs, bool) {
	if len(protocolLog.RelateKernelLogs()) == 0 {
		return nil, nil, nil, false
	}
	firstKernelLog := protocolLog.RelateKernelLogs()[0]
	pid, _ := events.ParseConnectionID(firstKernelLog.GetConnectionID())
	// if the process not monitoring, then ignore it
	if !r.shouldReportProcessLog(pid) {
		return nil, nil, nil, false
	}
	connection := r.connections.Find(firstKernelLog)
	if connection == nil {
		// if the connection cannot be found, it means that the connection have not been established
		// just re-add into the queue for checking in the next period
		if time.Since(firstKernelLog.Timestamp()) > kernelAccessLogCacheTime {
			return nil, nil, nil, false
		}
		return nil, nil, nil, true
	}
	if r.shouldExcludeConnection(connection) {
		return nil, nil, nil, false
	}
	if r.shouldDeferForResolution(connection) {
		return nil, nil, nil, true
	}
	// the details were merged when the message was finished, see messageDetails and common.NewProtocolLogEvent
	return connection, protocolLog.RelateKernelLogs(), protocolLog.ProtocolLog(), false
}

// appendProtocolLog adds the protocol log to the batch with the kernel logs of its details, or without any
// (Options.DisableSendMultipleProtocols), and tells whether it was added: with its kernel logs, a log none of
// whose details makes a kernel log is not added
func (r *Runner) appendProtocolLog(batch *sender.BatchLogs, connection *common.ConnectionInfo, details []events.SocketDetail,
	protocolLog *v3.AccessLogProtocolLogs) (kernelLogCount int, added bool) {
	if r.disableFlushMultipleProtocols {
		return 0, batch.AppendProtocolLog(connection, nil, protocolLog)
	}
	kernelLogCount = batch.AppendTransferProtocolLog(connection, details, protocolLog)
	return kernelLogCount, kernelLogCount > 0
}

// shouldExcludeConnection tells that the logs of the connection are not reported (Options.ExcludeConnection)
func (r *Runner) shouldExcludeConnection(connection *common.ConnectionInfo) bool {
	return r.options.ExcludeConnection != nil && r.options.ExcludeConnection(connection)
}

// shouldDeferForResolution holds the logs of the connection for one more flush while the ztunnel lb mapping is
// still being correlated (bounded per connection), so a short connection resolves to the real pod IP instead of
// being emitted with the raw service IP (Options.DisableResolutionDefer turns it off)
func (r *Runner) shouldDeferForResolution(connection *common.ConnectionInfo) bool {
	return !r.options.DisableResolutionDefer && r.connections.ShouldDeferForResolution(connection)
}

func recycleKernelLogEvent(kernelLog common.KernelLog) {
	if !kernelLog.Owned() {
		return
	}
	if event, ok := kernelLog.Event().(*events.SocketDataUploadEvent); ok {
		events.RecycleUploadEvent(event)
	}
}

// kernelLogConnection is the connection the kernel log is reported for, nil when it is not reported; delay
// tells that its connection is not known yet and the log should be looked at again in the next flush
func (r *Runner) kernelLogConnection(kernelLog common.KernelLog) (*common.ConnectionInfo, bool) {
	pid, _ := events.ParseConnectionID(kernelLog.Event().GetConnectionID())
	// if the process not monitoring, then ignore it
	if !r.shouldReportProcessLog(pid) {
		return nil, false
	}
	connection := r.connections.Find(kernelLog.Event())
	if connection == nil {
		if log.Enable(logrus.DebugLevel) {
			log.Debugf("cannot find the connection, connection ID: %d, random ID: %d",
				kernelLog.Event().GetConnectionID(), kernelLog.Event().GetRandomID())
		}
		// if the connection cannot be found, it means that the connection have not been established
		// just re-add into the queue for checking in the next period
		if time.Since(kernelLog.Event().Timestamp()) > kernelAccessLogCacheTime {
			return nil, false
		}
		return nil, true
	}
	if r.shouldExcludeConnection(connection) {
		if log.Enable(logrus.DebugLevel) {
			log.Debugf("detected the connection should be excluded, connection ID: %d, random ID: %d",
				connection.ConnectionID, connection.RandomID)
		}
		return nil, false
	}
	if r.shouldDeferForResolution(connection) {
		return nil, true
	}
	return connection, false
}

// Stop stops the collectors, the connection manager and the BPF programs (the sender and the queues end with the
// context of Start)
func (r *Runner) Stop() error {
	return r.stop()
}

func (r *Runner) stop() error {
	var err error
	r.stopOnce.Do(func() {
		for _, c := range r.started {
			c.Stop()
		}
		r.context.ConnectionMgr.Stop()
		if r.context.BPF != nil {
			err = r.context.BPF.Close()
		}
	})
	return err
}
