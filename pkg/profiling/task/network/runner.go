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

package network

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/hashicorp/go-multierror"

	"github.com/cilium/ebpf/link"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze"
	analyzeBase "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
	logv3 "skywalking.apache.org/repo/goapi/collect/logging/v3"
)

var log = logger.GetLogger("profiling", "task", "network")

type Runner struct {
	initOnce       sync.Once
	startLock      sync.Mutex
	stopOnce       sync.Once
	meterClient    v3.MeterReportServiceClient
	logClient      logv3.LogReportServiceClient
	eventClient    v3.SpanAttachedEventReportServiceClient
	reportInterval time.Duration
	meterPrefix    string

	bpf            *bpf.Loader
	processes      map[int32][]api.ProcessInterface
	analyzeContext *analyzeBase.AnalyzerContext

	ctx    context.Context
	cancel context.CancelFunc
}

func NewGlobalRunnerContext() *Runner {
	processes := make(map[int32][]api.ProcessInterface)
	return &Runner{
		processes:      processes,
		analyzeContext: analyze.NewContext(processes),
	}
}

func (r *Runner) init(config *base.TaskConfig, moduleMgr *module.Manager) error {
	var err error
	r.initOnce.Do(func() {
		err = r.init0(config, moduleMgr)
	})
	return err
}

func (r *Runner) DeleteProcesses(processes []api.ProcessInterface) (bool, error) {
	var err error
	for _, p := range processes {
		pid := p.Pid()
		existsProcesses := make([]api.ProcessInterface, 0)
		existsProcesses = append(existsProcesses, r.processes[pid]...)

		// update process entities
		newProcesses := make([]api.ProcessInterface, 0)

		for _, existProcess := range existsProcesses {
			if p.ID() != existProcess.ID() {
				newProcesses = append(newProcesses, existProcess)
			}
		}

		// no process need delete, then just ignore
		if len(newProcesses) == len(existsProcesses) {
			continue
		}

		// the process no need to monitor, then just ignore
		if len(newProcesses) == 0 {
			if err1 := r.bpf.ProcessMonitorControl.Delete(uint32(pid)); err1 != nil {
				err = multierror.Append(err, err1)
			}
			log.Debugf("delete monitor process: %d", pid)
			delete(r.processes, pid)
			continue
		}
		r.processes[pid] = newProcesses
	}
	return len(r.processes) == 0, err
}

func (r *Runner) Start(ctx context.Context, task *base.ProfilingTask, processes []api.ProcessInterface) error {
	r.startLock.Lock()
	defer r.startLock.Unlock()
	// if already start, then just adding the processes
	if r.bpf != nil {
		return r.updateTask(task, processes)
	}

	r.ctx, r.cancel = context.WithCancel(ctx)
	// load bpf program
	bpfLoader, err := bpf.NewLoader()
	if err != nil {
		return err
	}
	r.bpf = bpfLoader

	if err := r.updateTask(task, processes); err != nil {
		return err
	}

	// register all handlers
	r.analyzeContext.RegisterAllHandlers(r.ctx, bpfLoader)
	r.analyzeContext.StartSocketAddressParser(r.ctx)

	// sock opts
	bpfLoader.AddSysCall("close", bpfLoader.SysClose, bpfLoader.SysCloseRet)
	bpfLoader.AddSysCall("connect", bpfLoader.SysConnect, bpfLoader.SysConnectRet)
	bpfLoader.AddSysCall("accept", bpfLoader.SysAccept, bpfLoader.SysAcceptRet)
	bpfLoader.AddSysCall("accept4", bpfLoader.SysAccept, bpfLoader.SysAcceptRet)
	bpfLoader.AddLink(link.Kretprobe, bpfLoader.SockAllocRet, "sock_alloc")
	bpfLoader.AddLink(link.Kprobe, bpfLoader.TcpConnect, "tcp_connect")

	// write/receive data
	bpfLoader.AddSysCall("send", bpfLoader.SysSend, bpfLoader.SysSendRet)
	bpfLoader.AddSysCall("sendto", bpfLoader.SysSendto, bpfLoader.SysSendtoRet)
	bpfLoader.AddSysCall("sendmsg", bpfLoader.SysSendmsg, bpfLoader.SysSendmsgRet)
	bpfLoader.AddSysCall("sendmmsg", bpfLoader.SysSendmmsg, bpfLoader.SysSendmmsgRet)
	bpfLoader.AddSysCall("sendfile", bpfLoader.SysSendfile, bpfLoader.SysSendfileRet)
	bpfLoader.AddSysCall("sendfile64", bpfLoader.SysSendfile, bpfLoader.SysSendfileRet)
	bpfLoader.AddSysCall("write", bpfLoader.SysWrite, bpfLoader.SysWriteRet)
	bpfLoader.AddSysCall("writev", bpfLoader.SysWritev, bpfLoader.SysWritevRet)
	bpfLoader.AddSysCall("read", bpfLoader.SysRead, bpfLoader.SysReadRet)
	bpfLoader.AddSysCall("readv", bpfLoader.SysReadv, bpfLoader.SysReadvRet)
	bpfLoader.AddSysCall("recv", bpfLoader.SysRecv, bpfLoader.SysRecvRet)
	bpfLoader.AddSysCall("recvfrom", bpfLoader.SysRecvfrom, bpfLoader.SysRecvfromRet)
	bpfLoader.AddSysCall("recvmsg", bpfLoader.SysRecvmsg, bpfLoader.SysRecvmsgRet)
	bpfLoader.AddSysCall("recvmmsg", bpfLoader.SysRecvmmsg, bpfLoader.SysRecvmmsgRet)
	bpfLoader.AddLink(link.Kprobe, bpfLoader.TcpRcvEstablished, "tcp_rcv_established")
	bpfLoader.AddLink(link.Kprobe, bpfLoader.SecuritySocketSendmsg, "security_socket_sendmsg")
	bpfLoader.AddLink(link.Kprobe, bpfLoader.SecuritySocketRecvmsg, "security_socket_recvmsg")

	// retransmit/drop
	bpfLoader.AddLink(link.Kprobe, bpfLoader.TcpRetransmit, "tcp_retransmit_skb")
	bpfLoader.AddLink(link.Kprobe, bpfLoader.TcpDrop, "tcp_drop")

	if err := bpfLoader.HasError(); err != nil {
		_ = bpfLoader.Close()
		return err
	}

	// metrics report
	r.registerMetricsReport()
	return nil
}

func (r *Runner) registerMetricsReport() {
	go func() {
		timeTicker := time.NewTicker(r.reportInterval)
		for {
			select {
			case <-timeTicker.C:
				if err := r.flushData(); err != nil {
					log.Errorf("flush network monitoing metrics failure: %v", err)
				}
			case <-r.ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()
}

func (r *Runner) flushData() error {
	// flush all metrics
	metricsBuilder, err := r.analyzeContext.FlushAllMetrics(r.bpf, r.meterPrefix)
	if err != nil {
		return err
	}

	if count, err1 := r.flushMetrics(metricsBuilder); err1 != nil {
		err = multierror.Append(err, err1)
	} else if count > 0 {
		log.Infof("total send network topology meter data: %d", count)
	}

	if count, err1 := r.flushLogs(metricsBuilder); err1 != nil {
		err = multierror.Append(err, err1)
	} else if count > 0 {
		log.Infof("total send network logs data: %d", count)
	}

	eventCount, eventError := r.flushEvents(metricsBuilder)
	if eventError != nil {
		err = multierror.Append(err, eventError)
	}
	if eventCount > 0 {
		log.Infof("total send network events data: %d", eventCount)
	}
	return err
}

func (r *Runner) flushMetrics(builder *analyzeBase.MetricsBuilder) (int, error) {
	metrics := builder.BuildMetrics()
	if len(metrics) == 0 {
		return 0, nil
	}

	// send metrics
	batch, err := r.meterClient.CollectBatch(r.ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		if _, e := batch.CloseAndRecv(); e != nil {
			log.Warnf("close the metrics stream error: %v", e)
		}
	}()
	count := 0
	for _, m := range metrics {
		count += len(m.MeterData)
		if err := batch.Send(m); err != nil {
			return 0, err
		}
	}
	return count, nil
}

func (r *Runner) flushLogs(builder *analyzeBase.MetricsBuilder) (int, error) {
	logsCollection := builder.BuildLogs()
	if len(logsCollection) == 0 {
		return 0, nil
	}

	count := 0
	for _, logs := range logsCollection {
		collector, err := r.logClient.Collect(r.ctx)
		if err != nil {
			return 0, err
		}
		count += len(logs)
		for _, l := range logs {
			if err := collector.Send(l); err != nil {
				if _, e := collector.CloseAndRecv(); e != nil {
					log.Warnf("close the logs stream error: %v", e)
				}
				return 0, err
			}
		}

		if _, e := collector.CloseAndRecv(); e != nil {
			log.Warnf("close the logs stream error: %v", e)
		}
	}

	return count, nil
}

func (r *Runner) flushEvents(builder *analyzeBase.MetricsBuilder) (int, error) {
	events := builder.BuildEvents()
	if len(events) == 0 {
		return 0, nil
	}

	collector, err := r.eventClient.Collect(r.ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		if _, e := collector.CloseAndRecv(); e != nil {
			log.Warnf("close the event stream error: %v", e)
		}
	}()
	count := 0
	var sendErrors error
	for _, m := range events {
		if err := collector.Send(m); err != nil {
			sendErrors = multierror.Append(fmt.Errorf("send error, traceid: %s, event: %s, reason: %v", m.TraceContext.TraceId, m.Event, err))
		} else {
			count++
		}
	}
	return count, sendErrors
}

func (r *Runner) Stop() error {
	// if starting, then need to wait start finished
	r.startLock.Lock()
	defer r.startLock.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	var result error
	r.stopOnce.Do(func() {
		result = r.closeWhenExists(result, r.bpf)
	})
	return result
}

func (r *Runner) closeWhenExists(err error, c io.Closer) error {
	if c == nil {
		return err
	}
	if e := c.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	return err
}

func (r *Runner) init0(config *base.TaskConfig, moduleMgr *module.Manager) error {
	coreOperator := moduleMgr.FindModule(core.ModuleName).(core.Operator)
	connection := coreOperator.BackendOperator().GetConnection()
	r.meterClient = v3.NewMeterReportServiceClient(connection)
	r.logClient = logv3.NewLogReportServiceClient(connection)
	r.eventClient = v3.NewSpanAttachedEventReportServiceClient(connection)

	reportInterval, err := time.ParseDuration(config.Network.ReportInterval)
	if err != nil {
		return fmt.Errorf("parsing report interval failure: %v", err)
	}
	r.reportInterval = reportInterval
	if config.Network.MeterPrefix == "" {
		return fmt.Errorf("please provide the meter prefix")
	}
	r.meterPrefix = config.Network.MeterPrefix + "_"

	err = r.analyzeContext.Init(config, moduleMgr)
	if err != nil {
		return fmt.Errorf("init analyzer failure: %v", err)
	}
	return nil
}

func (r *Runner) updateTask(task *base.ProfilingTask, processes []api.ProcessInterface) error {
	var err error
	r.analyzeContext.UpdateExtensionConfig(task.ExtensionConfig)
	for _, p := range processes {
		pid := p.Pid()
		alreadyExists := false
		if len(r.processes[pid]) > 0 {
			for _, existsProcess := range r.processes[pid] {
				if p.ID() == existsProcess.ID() {
					alreadyExists = true
					break
				}
			}
		}

		if alreadyExists {
			continue
		}

		r.processes[pid] = append(r.processes[pid], p)

		// add to the process let it could be monitored
		if err1 := r.bpf.ProcessMonitorControl.Update(uint32(pid), uint32(1), ebpf.UpdateAny); err1 != nil {
			err = multierror.Append(err, err1)
		}

		// add process ssl config
		if err1 := addSSLProcess(int(pid), r.bpf); err1 != nil {
			err = multierror.Append(err, err1)
		}

		log.Debugf("add monitor process, pid: %d", pid)
	}
	return err
}
