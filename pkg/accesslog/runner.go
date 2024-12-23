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
	"time"

	process2 "github.com/shirou/gopsutil/process"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/collector"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/accesslog/sender"
	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/core/backend"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

const kernelAccessLogCacheTime = time.Second * 10

var log = logger.GetLogger("access_log", "runner")

type Runner struct {
	context    *common.AccessLogContext
	collectors []collector.Collector
	mgr        *module.Manager
	backendOp  backend.Operator
	cluster    string
	ctx        context.Context
	sender     *sender.GRPCSender
}

func NewRunner(mgr *module.Manager, config *common.Config) (*Runner, error) {
	bpfLoader, err := bpf.NewLoader()
	if err != nil {
		return nil, err
	}
	flushDuration, err := time.ParseDuration(config.Flush.Period)
	if err != nil {
		return nil, fmt.Errorf("parse flush period error: %v", err)
	}
	coreModule := mgr.FindModule(core.ModuleName).(core.Operator)
	backendOP := coreModule.BackendOperator()
	clusterName := coreModule.ClusterName()
	monitorFilter := common.NewStaticMonitorFilter(strings.Split(config.ExcludeNamespaces, ","), strings.Split(config.ExcludeClusters, ","))
	connectionMgr := common.NewConnectionManager(config, mgr, bpfLoader, monitorFilter)
	runner := &Runner{
		context: &common.AccessLogContext{
			BPF:           bpfLoader,
			Config:        config,
			ConnectionMgr: connectionMgr,
		},
		collectors: collector.Collectors(),
		mgr:        mgr,
		backendOp:  backendOP,
		cluster:    clusterName,
		sender:     sender.NewGRPCSender(mgr, connectionMgr),
	}
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
		err := c.Start(r.mgr, r.context)
		if err != nil {
			return err
		}
	}

	if err := r.context.BPF.HasError(); err != nil {
		return err
	}

	return nil
}

func (r *Runner) Consume(kernels chan *common.KernelLog, protocols chan *common.ProtocolLog) {
	if r.backendOp.GetConnectionStatus() != backend.Connected {
		log.Warnf("failure to connect to the backend, skip generating access log")
		return
	}

	batch := r.sender.NewBatch()
	r.buildConnectionLogs(batch, kernels, protocols)
	log.Debugf("ready to send access log, connection count: %d", batch.ConnectionCount())
	r.sender.AddBatch(batch)
}

func (r *Runner) buildConnectionLogs(batch *sender.BatchLogs, kernels chan *common.KernelLog, protocols chan *common.ProtocolLog) {
	r.buildKernelLogs(kernels, batch)
	r.buildProtocolLogs(protocols, batch)

	r.context.ConnectionMgr.OnBuildConnectionLogFinished()
}

func (r *Runner) buildKernelLogs(kernels chan *common.KernelLog, batch *sender.BatchLogs) {
	delayAppends := make([]*common.KernelLog, 0)
	for {
		select {
		case kernelLog := <-kernels:
			connection, curLog, delay := r.buildKernelLog(kernelLog)
			log.Debugf("building kernel log result, connetaion ID: %d, random ID: %d, exist connection: %t, delay: %t",
				kernelLog.Event.GetConnectionID(), kernelLog.Event.GetRandomID(), connection != nil, delay)
			if connection != nil && curLog != nil {
				batch.AppendKernelLog(connection, curLog)
			} else if delay {
				delayAppends = append(delayAppends, kernelLog)
			}
		default:
			for _, delayAppend := range delayAppends {
				select {
				case kernels <- delayAppend:
				default:
					return
				}
			}
			return
		}
	}
}

func (r *Runner) buildProtocolLogs(protocols chan *common.ProtocolLog, batch *sender.BatchLogs) {
	delayAppends := make([]*common.ProtocolLog, 0)
	for {
		select {
		case protocolLog := <-protocols:
			connection, kernelLogs, protocolLogs, delay := r.buildProtocolLog(protocolLog)
			if log.Enable(logrus.DebugLevel) {
				kernelLogCount := len(protocolLog.KernelLogs)
				var conID, randomID uint64
				if kernelLogCount > 0 {
					conID, randomID = protocolLog.KernelLogs[0].GetConnectionID(), protocolLog.KernelLogs[0].GetRandomID()
				}
				log.Debugf("building protocol log result, connetaion ID: %d, random ID: %d, connection exist: %t, delay: %t",
					conID, randomID, connection != nil, delay)
			}
			if connection != nil && len(kernelLogs) > 0 && protocolLogs != nil {
				batch.AppendProtocolLog(connection, kernelLogs, protocolLogs)
			} else if delay {
				delayAppends = append(delayAppends, protocolLog)
			}
		default:
			for _, delayAppend := range delayAppends {
				select {
				case protocols <- delayAppend:
				default:
					return
				}
			}
			return
		}
	}
}

func (r *Runner) shouldReportProcessLog(pid uint32) bool {
	// if the process not monitoring, then check the process is existed or not
	if r.context.ConnectionMgr.ProcessIsMonitor(pid) {
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

func (r *Runner) buildProtocolLog(protocolLog *common.ProtocolLog) (*common.ConnectionInfo,
	[]*v3.AccessLogKernelLog, *v3.AccessLogProtocolLogs, bool) {
	if len(protocolLog.KernelLogs) == 0 {
		return nil, nil, nil, false
	}
	firstKernelLog := protocolLog.KernelLogs[0]
	pid, _ := events.ParseConnectionID(firstKernelLog.GetConnectionID())
	// if the process not monitoring, then ignore it
	if !r.shouldReportProcessLog(pid) {
		return nil, nil, nil, false
	}
	connection := r.context.ConnectionMgr.Find(firstKernelLog)
	if connection == nil {
		// if the connection cannot be found, it means that the connection have not been established
		// just re-add into the queue for checking in the next period
		if time.Since(firstKernelLog.Timestamp()) > kernelAccessLogCacheTime {
			return nil, nil, nil, false
		}
		return nil, nil, nil, true
	}
	kernelLogs := make([]*v3.AccessLogKernelLog, 0)
	for _, kl := range protocolLog.KernelLogs {
		event := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, kl)
		if event == nil {
			continue
		}
		kernelLogs = append(kernelLogs, event)
	}

	return connection, kernelLogs, protocolLog.Protocol, false
}

func (r *Runner) buildKernelLog(kernelLog *common.KernelLog) (*common.ConnectionInfo, *v3.AccessLogKernelLog, bool) {
	pid, _ := events.ParseConnectionID(kernelLog.Event.GetConnectionID())
	// if the process not monitoring, then ignore it
	if !r.shouldReportProcessLog(pid) {
		return nil, nil, false
	}
	connection := r.context.ConnectionMgr.Find(kernelLog.Event)
	if connection == nil {
		// if the connection cannot be found, it means that the connection have not been established
		// just re-add into the queue for checking in the next period
		if time.Since(kernelLog.Event.Timestamp()) > kernelAccessLogCacheTime {
			return nil, nil, false
		}
		return nil, nil, true
	}
	event := forwarder.BuildKernelLogFromEvent(kernelLog.Type, kernelLog.Event)
	return connection, event, false
}

func (r *Runner) Stop() error {
	r.context.ConnectionMgr.Stop()
	return nil
}
