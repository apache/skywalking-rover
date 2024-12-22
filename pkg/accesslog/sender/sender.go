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

package sender

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	"github.com/sirupsen/logrus"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var log = logger.GetLogger("accesslog", "sender")

// GRPCSender Async to sending the access log to the backend
type GRPCSender struct {
	logs   *list.List
	notify chan bool
	mutex  sync.Mutex
	ctx    context.Context

	mgr           *module.Manager
	connectionMgr *common.ConnectionManager
	alsClient     v3.EBPFAccessLogServiceClient
	clusterName   string
}

// NewGRPCSender creates a new GRPCSender
func NewGRPCSender(mgr *module.Manager, connectionMgr *common.ConnectionManager) *GRPCSender {
	return &GRPCSender{
		logs:          list.New(),
		notify:        make(chan bool, 1),
		mgr:           mgr,
		connectionMgr: connectionMgr,
		clusterName:   mgr.FindModule(core.ModuleName).(core.Operator).ClusterName(),
		alsClient: v3.NewEBPFAccessLogServiceClient(mgr.FindModule(core.ModuleName).(core.Operator).
			BackendOperator().GetConnection()),
	}
}

func (g *GRPCSender) Start(ctx context.Context) {
	g.ctx = ctx
	go func() {
		for {
			select {
			case <-g.notify:
				if count, err := g.handleLogs(); err != nil {
					log.Warnf("sending access log error, lost %d logs, error: %v", count, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (g *GRPCSender) NewBatch() *BatchLogs {
	return &BatchLogs{
		logs: make(map[*common.ConnectionInfo]*ConnectionLogs),
	}
}

func (g *GRPCSender) AddBatch(batch *BatchLogs) {
	// split logs
	splitLogs := batch.splitBatchLogs()

	// append the resend logs
	g.mutex.Lock()
	defer g.mutex.Unlock()
	for _, l := range splitLogs {
		g.logs.PushBack(l)
	}

	// notify the sender
	select {
	case g.notify <- true:
	default:
	}
}

func (g *GRPCSender) handleLogs() (int, error) {
	for {
		// pop logs
		logs := g.popLogs()
		if logs == nil {
			return 0, nil
		}
		// send logs
		now := time.Now()
		if err := g.sendLogs(logs); err != nil {
			return len(logs.logs), err
		}
		log.Infof("sending access log success, connection count: %d, use time: %s",
			logs.ConnectionCount(), time.Since(now).String())
	}
}

func (g *GRPCSender) sendLogs(batch *BatchLogs) error {
	timeout, cancelFunc := context.WithTimeout(g.ctx, time.Second*20)
	defer cancelFunc()
	streaming, err := g.alsClient.Collect(timeout)
	if err != nil {
		return err
	}

	firstLog := true
	firstConnection := true
	var sendError error
	for connection, logs := range batch.logs {
		if len(logs.kernels) == 0 && len(logs.protocols) == 0 {
			continue
		}
		if log.Enable(logrus.DebugLevel) {
			log.Debugf("ready to sending access log with connection, connection ID: %d, random ID: %d, "+
				"local: %s, remote: %s, role: %s, contains ztunnel address: %t, kernel logs count: %d, protocol log count: %d",
				connection.ConnectionID, connection.RandomID, connection.RPCConnection.Local, connection.RPCConnection.Remote,
				connection.RPCConnection.Role, connection.RPCConnection.Attachment != nil, len(logs.kernels), len(logs.protocols))
		}

		if len(logs.kernels) > 0 {
			sendError = g.sendLogToTheStream(streaming,
				g.buildAccessLogMessage(firstLog, firstConnection, connection, logs.kernels, nil))
			firstLog, firstConnection = false, false
		}
		for _, protocolLog := range logs.protocols {
			sendError = g.sendLogToTheStream(streaming,
				g.buildAccessLogMessage(firstLog, firstConnection, connection, protocolLog.kernels, protocolLog.protocol))
			firstLog, firstConnection = false, false
		}
		if sendError != nil {
			g.closeStream(streaming)
			return fmt.Errorf("sending access log error: %v", sendError)
		}

		firstConnection = true
	}

	g.closeStream(streaming)
	return nil
}

func (g *GRPCSender) closeStream(s v3.EBPFAccessLogService_CollectClient) {
	if _, err := s.CloseAndRecv(); err != nil {
		log.Warnf("closing the access log streaming error: %v", err)
	}
}

func (g *GRPCSender) sendLogToTheStream(streaming v3.EBPFAccessLogService_CollectClient, logMsg *v3.EBPFAccessLogMessage) error {
	if err := streaming.Send(logMsg); err != nil {
		return err
	}
	return nil
}

func (g *GRPCSender) buildAccessLogMessage(firstLog, firstConnection bool, conn *common.ConnectionInfo,
	kernelLogs []*v3.AccessLogKernelLog, protocolLog *v3.AccessLogProtocolLogs) *v3.EBPFAccessLogMessage {
	var rpcCon *v3.AccessLogConnection
	if firstConnection {
		rpcCon = conn.RPCConnection
	}
	return &v3.EBPFAccessLogMessage{
		Node:        g.BuildNodeInfo(firstLog),
		Connection:  rpcCon,
		KernelLogs:  kernelLogs,
		ProtocolLog: protocolLog,
	}
}

func (g *GRPCSender) BuildNodeInfo(needs bool) *v3.EBPFAccessLogNodeInfo {
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
		Name:          g.mgr.FindModule(process.ModuleName).(process.K8sOperator).NodeName(),
		NetInterfaces: netInterfaces,
		BootTime:      g.convertTimeToInstant(host.BootTime),
		ClusterName:   g.clusterName,
		Policy: &v3.EBPFAccessLogPolicy{
			ExcludeNamespaces: g.connectionMgr.GetExcludeNamespaces(),
		},
	}
}

func (g *GRPCSender) convertTimeToInstant(t time.Time) *v32.Instant {
	return &v32.Instant{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
}

func (g *GRPCSender) popLogs() *BatchLogs {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.logs.Len() == 0 {
		return nil
	}
	e := g.logs.Front()
	logs := e.Value.(*BatchLogs)
	g.logs.Remove(e)
	return logs
}
