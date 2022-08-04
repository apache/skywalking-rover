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

	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-multierror"

	"github.com/cilium/ebpf/link"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/tools/btf"

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// nolint
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf $REPO_ROOT/bpf/profiling/network/netmonitor.c -- -I$REPO_ROOT/bpf/include -D__TARGET_ARCH_x86

var log = logger.GetLogger("profiling", "task", "network", "topology")

type Runner struct {
	initOnce       sync.Once
	startLock      sync.Mutex
	stopOnce       sync.Once
	meterClient    v3.MeterReportServiceClient
	reportInterval time.Duration
	meterPrefix    string

	bpf        *bpfObjects
	linker     *Linker
	bpfContext *Context

	ctx    context.Context
	cancel context.CancelFunc
}

func NewGlobalRunnerContext() *Runner {
	return &Runner{
		bpfContext: NewContext(),
		linker:     &Linker{},
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
	return r.bpfContext.DeleteProcesses(processes)
}

func (r *Runner) Start(ctx context.Context, processes []api.ProcessInterface) error {
	r.startLock.Lock()
	defer r.startLock.Unlock()
	// if already start, then just adding the processes
	if r.bpf != nil {
		return r.bpfContext.AddProcesses(processes)
	}

	r.ctx, r.cancel = context.WithCancel(ctx)
	// load bpf program
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, btf.GetEBPFCollectionOptionsIfNeed()); err != nil {
		return err
	}
	r.bpf = &objs
	r.bpfContext.Init(&objs, r.linker)

	if err := r.bpfContext.AddProcesses(processes); err != nil {
		return err
	}

	// register all handlers
	r.bpfContext.RegisterAllHandlers()
	r.bpfContext.StartSocketAddressParser(r.ctx)

	// sock opts
	r.linker.AddSysCall("close", objs.SysClose, objs.SysCloseRet)
	r.linker.AddSysCall("connect", objs.SysConnect, objs.SysConnectRet)
	r.linker.AddSysCall("accept", objs.SysAccept, objs.SysAcceptRet)
	r.linker.AddSysCall("accept4", objs.SysAccept, objs.SysAcceptRet)
	r.linker.AddLink(link.Kretprobe, objs.SockAllocRet, "sock_alloc")
	r.linker.AddLink(link.Kprobe, objs.TcpConnect, "tcp_connect")

	// write/receive data
	r.linker.AddSysCall("send", objs.SysSend, objs.SysSendRet)
	r.linker.AddSysCall("sendto", objs.SysSendto, objs.SysSendtoRet)
	r.linker.AddSysCall("sendmsg", objs.SysSendmsg, objs.SysSendmsgRet)
	r.linker.AddSysCall("sendmmsg", objs.SysSendmmsg, objs.SysSendmmsgRet)
	r.linker.AddSysCall("sendfile", objs.SysSendfile, objs.SysSendfileRet)
	r.linker.AddSysCall("sendfile64", objs.SysSendfile, objs.SysSendfileRet)
	r.linker.AddSysCall("write", objs.SysWrite, objs.SysWriteRet)
	r.linker.AddSysCall("writev", objs.SysWritev, objs.SysWritevRet)
	r.linker.AddSysCall("read", objs.SysRead, objs.SysReadRet)
	r.linker.AddSysCall("readv", objs.SysReadv, objs.SysReadvRet)
	r.linker.AddSysCall("recv", objs.SysRecv, objs.SysRecvRet)
	r.linker.AddSysCall("recvfrom", objs.SysRecvfrom, objs.SysRecvfromRet)
	r.linker.AddSysCall("recvmsg", objs.SysRecvmsg, objs.SysRecvmsgRet)
	r.linker.AddSysCall("recvmmsg", objs.SysRecvmmsg, objs.SysRecvmmsgRet)
	r.linker.AddLink(link.Kprobe, objs.TcpRcvEstablished, "tcp_rcv_established")
	r.linker.AddLink(link.Kprobe, objs.SecuritySocketSendmsg, "security_socket_sendmsg")
	r.linker.AddLink(link.Kprobe, objs.SecuritySocketRecvmsg, "security_socket_recvmsg")

	// retransmit/drop
	r.linker.AddLink(link.Kprobe, objs.TcpRetransmit, "tcp_retransmit_skb")
	r.linker.AddLink(link.Kprobe, objs.TcpDrop, "tcp_drop")

	if err := r.linker.HasError(); err != nil {
		_ = r.linker.Close()
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
				if err := r.flushMetrics(); err != nil {
					log.Errorf("flush network monitoing metrics failure: %v", err)
				}
			case <-r.ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()
}

func (r *Runner) flushMetrics() error {
	// flush all connection from bpf
	connections, err := r.bpfContext.FlushAllConnection()
	if err != nil {
		return err
	}
	if len(connections) == 0 {
		return nil
	}

	if log.Enable(logrus.DebugLevel) {
		for _, con := range connections {
			log.Debugf("found connection: %d, %s relation: %s:%d(%d) -> %s:%d, protocol: %s, is_ssl: %t, read: %d bytes/%d, write: %d bytes/%d",
				con.ConnectionID, con.Role.String(),
				con.LocalIP, con.LocalPort, con.LocalPid, con.RemoteIP, con.RemotePort,
				con.Protocol.String(), con.IsSSL, con.WriteCounter.Cur.Bytes, con.WriteCounter.Cur.Count,
				con.ReadCounter.Cur.Bytes, con.ReadCounter.Cur.Count)
		}
	}
	// combine all connection
	analyzer := NewTrafficAnalyzer(r.bpfContext.processes)
	traffics := analyzer.CombineConnectionToTraffics(connections)
	if len(traffics) == 0 {
		return nil
	}
	r.logTheMetricsConnections(traffics)

	// send metrics
	batch, err := r.meterClient.CollectBatch(r.ctx)
	if err != nil {
		return err
	}
	defer func() {
		if _, e := batch.CloseAndRecv(); e != nil {
			log.Warnf("close the metrics stream error: %v", e)
		}
	}()
	count := 0
	for _, traffic := range traffics {
		collections := traffic.GenerateMetrics(r.meterPrefix)
		for _, col := range collections {
			count += len(col.MeterData)
			if err := batch.Send(col); err != nil {
				return err
			}
		}
	}
	if count > 0 {
		log.Infof("total send network topology meter data: %d", count)
	}
	return nil
}

func (r *Runner) logTheMetricsConnections(traffices []*ProcessTraffic) {
	if !log.Enable(logrus.DebugLevel) {
		return
	}
	for _, traffic := range traffices {
		localInfo := fmt.Sprintf("%s:%d(%d)", traffic.LocalIP, traffic.LocalPort, traffic.LocalPid)
		if len(traffic.LocalProcesses) > 0 {
			p := traffic.LocalProcesses[0]
			localInfo = fmt.Sprintf("(%s)%s:%s:%s(%s:%d)(%d)", p.Entity().Layer, p.Entity().ServiceName,
				p.Entity().InstanceName, p.Entity().ProcessName, traffic.LocalIP, traffic.LocalPort, traffic.LocalPid)
		}

		remoteInfo := fmt.Sprintf("%s:%d(%d)", traffic.RemoteIP, traffic.RemotePort, traffic.RemotePid)
		if len(traffic.RemoteProcesses) > 0 {
			p := traffic.RemoteProcesses[0]
			remoteInfo = fmt.Sprintf("(%s)%s:%s:%s(%s:%d)(%d)",
				p.Entity().Layer, p.Entity().ServiceName, p.Entity().InstanceName, p.Entity().ProcessName,
				traffic.RemoteIP, traffic.RemotePort, traffic.RemotePid)
		}
		side := traffic.ConnectionRole.String()
		log.Debugf("connection analyze result: %s : %s -> %s, protocol: %s, is SSL: %t, read: %d bytes/%d, write: %d bytes/%d",
			side, localInfo, remoteInfo, traffic.Protocol.String(), traffic.IsSSL, traffic.WriteCounter.Bytes, traffic.WriteCounter.Count,
			traffic.ReadCounter.Bytes, traffic.ReadCounter.Count)
	}
}

func (r *Runner) Stop() error {
	if r.cancel != nil {
		r.cancel()
	}
	var result error
	r.stopOnce.Do(func() {
		result = r.closeWhenExists(result, r.linker)
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

	reportInterval, err := time.ParseDuration(config.Network.ReportInterval)
	if err != nil {
		return fmt.Errorf("parsing report interval failure: %v", err)
	}
	r.reportInterval = reportInterval
	if config.Network.MeterPrefix == "" {
		return fmt.Errorf("please provide the meter prefix")
	}
	r.meterPrefix = config.Network.MeterPrefix + "_"
	return nil
}
