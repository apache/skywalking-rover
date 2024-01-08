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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/collector"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/core/backend"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
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
	alsClient  v3.EBPFAccessLogServiceClient
	ctx        context.Context
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
	runner := &Runner{
		context: &common.AccessLogContext{
			BPF:           bpfLoader,
			Config:        config,
			ConnectionMgr: common.NewConnectionManager(config, mgr, bpfLoader),
		},
		collectors: collector.Collectors(),
		mgr:        mgr,
		backendOp:  backendOP,
		cluster:    clusterName,
		alsClient:  v3.NewEBPFAccessLogServiceClient(backendOP.GetConnection()),
	}
	runner.context.Queue = common.NewQueue(config.Flush.MaxCountOneStream, flushDuration, runner)
	return runner, nil
}

func (r *Runner) Start(ctx context.Context) error {
	r.ctx = ctx
	r.context.RuntimeContext = ctx
	r.context.Queue.Start(ctx)
	r.context.ConnectionMgr.Start()
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

	allLogs := r.buildConnectionLogs(kernels, protocols)
	log.Debugf("ready to send access log, connection count: %d", len(allLogs))
	if len(allLogs) == 0 {
		return
	}
	if err := r.sendLogs(allLogs); err != nil {
		log.Warnf("send access log failure: %v", err)
	}
}

func (r *Runner) buildConnectionLogs(kernels chan *common.KernelLog, protocols chan *common.ProtocolLog) map[*common.ConnectionInfo]*connectionLogs {
	result := make(map[*common.ConnectionInfo]*connectionLogs)
	r.buildKernelLogs(kernels, result)
	r.buildProtocolLogs(protocols, result)

	r.context.ConnectionMgr.OnBuildConnectionLogFinished()
	return result
}

func (r *Runner) buildKernelLogs(kernels chan *common.KernelLog, result map[*common.ConnectionInfo]*connectionLogs) {
	delayAppends := make([]*common.KernelLog, 0)
	for {
		select {
		case kernelLog := <-kernels:
			connection, curLog, delay := r.buildKernelLog(kernelLog)
			log.Debugf("building kernel log result, connetaion ID: %d, random ID: %d, exist connection: %t, delay: %t",
				kernelLog.Event.GetConnectionID(), kernelLog.Event.GetRandomID(), connection != nil, delay)
			if connection != nil && curLog != nil {
				logs, exist := result[connection]
				if !exist {
					logs = newConnectionLogs()
					result[connection] = logs
				}

				logs.kernels = append(logs.kernels, curLog)
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

func (r *Runner) buildProtocolLogs(protocols chan *common.ProtocolLog, result map[*common.ConnectionInfo]*connectionLogs) {
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
				logs, exist := result[connection]
				if !exist {
					logs = newConnectionLogs()
					result[connection] = logs
				}
				logs.protocols = append(logs.protocols, &connectionProtocolLog{
					kernels:  kernelLogs,
					protocol: protocolLogs,
				})
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

func (r *Runner) sendLogs(allLogs map[*common.ConnectionInfo]*connectionLogs) error {
	timeout, cancelFunc := context.WithTimeout(r.ctx, time.Second*20)
	defer cancelFunc()
	streaming, err := r.alsClient.Collect(timeout)
	if err != nil {
		return err
	}

	firstLog := true
	firstConnection := true
	for connection, logs := range allLogs {
		if len(logs.kernels) > 0 {
			r.sendLogToTheStream(streaming, r.buildAccessLogMessage(firstLog, firstConnection, connection, logs.kernels, nil))
			firstLog, firstConnection = false, false
		}
		for _, protocolLog := range logs.protocols {
			r.sendLogToTheStream(streaming, r.buildAccessLogMessage(firstLog, firstConnection, connection, protocolLog.kernels, protocolLog.protocol))
			firstLog, firstConnection = false, false
		}

		firstConnection = true
	}

	if _, err := streaming.CloseAndRecv(); err != nil {
		log.Warnf("closing the access log streaming error: %v", err)
	}
	return nil
}

func (r *Runner) sendLogToTheStream(streaming v3.EBPFAccessLogService_CollectClient, logMsg *v3.EBPFAccessLogMessage) {
	if err := streaming.Send(logMsg); err != nil {
		log.Warnf("send access log failure: %v", err)
	}
}

func (r *Runner) buildAccessLogMessage(firstLog, firstConnection bool, conn *common.ConnectionInfo,
	kernelLogs []*v3.AccessLogKernelLog, protocolLog *v3.AccessLogProtocolLogs) *v3.EBPFAccessLogMessage {
	var rpcCon *v3.AccessLogConnection
	if firstConnection {
		rpcCon = conn.RPCConnection
		if log.Enable(logrus.DebugLevel) {
			log.Debugf("ready to sending access log with connection, connection ID: %d, random ID: %d, "+
				"local: %s, remote: %s, role: %s",
				conn.ConnectionID, conn.RandomID, rpcCon.Local, rpcCon.Remote, rpcCon.Role)
		}
	}
	return &v3.EBPFAccessLogMessage{
		Node:        r.BuildNodeInfo(firstLog),
		Connection:  rpcCon,
		KernelLogs:  kernelLogs,
		ProtocolLog: protocolLog,
	}
}

func (r *Runner) BuildNodeInfo(needs bool) *v3.EBPFAccessLogNodeInfo {
	if !needs {
		return nil
	}
	netInterfaces := make([]*v3.EBPFAccessLogNodeNetInterface, 0)
	for i, n := range host.AllNetworkInterfaces() {
		netInterfaces = append(netInterfaces, &v3.EBPFAccessLogNodeNetInterface{
			Index: int32(i),
			Mtu:   int32(n.MTU),
			Name:  n.Name,
		})
	}
	return &v3.EBPFAccessLogNodeInfo{
		Name:          r.mgr.FindModule(process.ModuleName).(process.K8sOperator).NodeName(),
		NetInterfaces: netInterfaces,
		BootTime:      r.convertTimeToInstant(host.BootTime),
		ClusterName:   r.cluster,
	}
}

func (r *Runner) convertTimeToInstant(t time.Time) *v32.Instant {
	return &v32.Instant{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
}

func (r *Runner) buildProtocolLog(protocolLog *common.ProtocolLog) (*common.ConnectionInfo,
	[]*v3.AccessLogKernelLog, *v3.AccessLogProtocolLogs, bool) {
	if len(protocolLog.KernelLogs) == 0 {
		return nil, nil, nil, false
	}
	firstKernelLog := protocolLog.KernelLogs[0]
	pid, _ := events.ParseConnectionID(firstKernelLog.GetConnectionID())
	// if the process not monitoring, then ignore it
	if !r.context.ConnectionMgr.ProcessIsMonitor(pid) {
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
	if !r.context.ConnectionMgr.ProcessIsMonitor(pid) {
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

type connectionLogs struct {
	kernels   []*v3.AccessLogKernelLog
	protocols []*connectionProtocolLog
}

type connectionProtocolLog struct {
	kernels  []*v3.AccessLogKernelLog
	protocol *v3.AccessLogProtocolLogs
}

func newConnectionLogs() *connectionLogs {
	return &connectionLogs{
		kernels:   make([]*v3.AccessLogKernelLog, 0),
		protocols: make([]*connectionProtocolLog, 0),
	}
}
