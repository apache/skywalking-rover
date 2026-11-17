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
	"sync/atomic"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"

	"github.com/sirupsen/logrus"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var log = logger.GetLogger("accesslog", "sender")

const (
	defaultSendParallelism = 8
	// the backend takes about 0.25 ms per log on a stream, so a send of this many takes about half a second,
	// far from the stream timeout
	defaultMaxLogsPerSend = 2000
	sendStreamTimeout     = 20 * time.Second
	droppedWarnInterval   = 30 * time.Second
)

// GRPCSender Async to sending the access log to the backend
//
// The batches wait in logs, in order, and Parallelism goroutines take them one by one, each over a stream
// of its own: the backend consumes a stream serially, so a single stream bounds the access log rate. A
// batch is at most MaxLogsPerSend logs. A stream identifies its node on its first message and every
// connection on its first message of that connection, so every batch carries what the backend needs to
// attribute its logs, whatever stream it goes over. With little traffic one goroutine takes the batch as
// soon as it is added, exactly as with a single sender.
type GRPCSender struct {
	logs   *list.List
	notify chan bool
	mutex  sync.Mutex
	ctx    context.Context

	parallelism    int
	maxLogsPerSend int
	maxPendingLogs int
	// pendingLogs is the count of logs in logs, guarded by mutex
	pendingLogs int
	// halted is set when a send fails, guarded by mutex: then only one worker takes a batch (probing), the
	// next AddBatch wakes it, and the others go on once that send succeeded. So a backend outage loses the
	// batches in flight when it starts, then one batch per AddBatch, not the backlog.
	halted  bool
	probing bool
	// probeDue is set by AddBatch while halted: the next worker sends one batch (the probe)
	probeDue bool

	sends       atomic.Int64
	sendNanos   atomic.Int64
	sendErrors  atomic.Int64
	droppedLogs atomic.Int64
	lastDropLog atomic.Int64
	// lostLogs are the logs of the batches whose send failed
	lostLogs atomic.Int64

	// nodeInfo replaces the node information built from the modules, for tests
	nodeInfo func() *v3.EBPFAccessLogNodeInfo

	mgr           *module.Manager
	connectionMgr *common.ConnectionManager
	alsClient     v3.EBPFAccessLogServiceClient
	clusterName   string
}

// NewGRPCSender creates a new GRPCSender
func NewGRPCSender(mgr *module.Manager, connectionMgr *common.ConnectionManager, config common.SenderConfig) *GRPCSender {
	coreOperator := mgr.FindModule(core.ModuleName).(core.Operator)
	g := newGRPCSender(v3.NewEBPFAccessLogServiceClient(coreOperator.BackendOperator().GetConnection()), config)
	g.mgr = mgr
	g.connectionMgr = connectionMgr
	g.clusterName = coreOperator.ClusterName()
	return g
}

// newGRPCSender is the sender of the client with the configuration, its defaults applied
func newGRPCSender(client v3.EBPFAccessLogServiceClient, config common.SenderConfig) *GRPCSender {
	return &GRPCSender{
		logs:           list.New(),
		notify:         make(chan bool, 1),
		parallelism:    positiveOr(config.Parallelism, defaultSendParallelism),
		maxLogsPerSend: positiveOr(config.MaxLogsPerSend, defaultMaxLogsPerSend),
		maxPendingLogs: config.MaxPendingLogs,
		alsClient:      client,
	}
}

// RegisterMetrics exposes how far behind the backend the agent is: the batches waiting to be sent
// are built access log messages, and they are held in memory until the stream has taken them
func (g *GRPCSender) RegisterMetrics() {
	telemetry.Register("rover_access_log_send_queue_batches", "Built access log batches waiting to be sent",
		telemetry.Gauge, func() float64 {
			g.mutex.Lock()
			defer g.mutex.Unlock()
			return float64(g.logs.Len())
		})
	telemetry.Register("rover_access_log_sends_total", "Access log batches handed to the stream",
		telemetry.Counter, func() float64 { return float64(g.sends.Load()) })
	telemetry.Register("rover_access_log_send_seconds_total",
		"Time spent sending access log batches, which against the wall clock is how busy the sender is",
		telemetry.Counter, func() float64 { return time.Duration(g.sendNanos.Load()).Seconds() })
	telemetry.Register("rover_access_log_send_errors_total", "Access log batches the stream rejected",
		telemetry.Counter, func() float64 { return float64(g.sendErrors.Load()) })
	telemetry.Register("rover_access_log_send_pending_logs", "Access logs waiting to be sent",
		telemetry.Gauge, func() float64 {
			g.mutex.Lock()
			defer g.mutex.Unlock()
			return float64(g.pendingLogs)
		})
	telemetry.Register("rover_access_log_encode_errors_total",
		"Access logs dropped because they cannot be encoded, a string that is not UTF-8",
		telemetry.Counter, func() float64 { return float64(encodeErrors.Load()) })
	telemetry.Register("rover_access_log_send_lost_logs_total",
		"Access logs of the batches whose send failed",
		telemetry.Counter, func() float64 { return float64(g.lostLogs.Load()) })
	telemetry.Register("rover_access_log_send_dropped_logs_total",
		"Access logs dropped before they were sent because too many were waiting (sender.max_pending_logs)",
		telemetry.Counter, func() float64 { return float64(g.droppedLogs.Load()) })
}

func (g *GRPCSender) Start(ctx context.Context) {
	g.ctx = ctx
	g.RegisterMetrics()
	for i := 0; i < g.parallelism; i++ {
		go func() {
			for {
				select {
				case <-g.notify:
					g.handleLogs()
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

func positiveOr(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func (g *GRPCSender) NewBatch() *BatchLogs {
	return newBatchLogs()
}

func (g *GRPCSender) AddBatch(batch *BatchLogs) {
	batch.seal()
	// split logs
	splitLogs := batch.splitBatchLogs(g.maxLogsPerSend)
	if len(splitLogs) == 0 {
		return
	}

	g.mutex.Lock()
	if g.halted && !g.probing {
		g.probeDue = true
	}
	for _, l := range splitLogs {
		pb := &pendingBatch{logs: l, count: l.LogCount()}
		g.logs.PushBack(pb)
		g.pendingLogs += pb.count
	}
	// bound the backlog when a cap is set: the oldest batches go first, the newest data is the most useful
	droppedBatches, droppedLogs := 0, 0
	for g.maxPendingLogs > 0 && g.pendingLogs > g.maxPendingLogs && g.logs.Len() > 1 {
		e := g.logs.Front()
		dropped := e.Value.(*pendingBatch)
		g.logs.Remove(e)
		g.pendingLogs -= dropped.count
		droppedBatches++
		droppedLogs += dropped.count
	}
	g.mutex.Unlock()
	if droppedLogs > 0 {
		g.droppedLogs.Add(int64(droppedLogs))
		g.warnDropped(droppedBatches, droppedLogs)
	}

	g.wakeSender()
}

// wakeSender wakes one sending goroutine, which wakes the next one when it takes a batch and more wait
func (g *GRPCSender) wakeSender() {
	select {
	case g.notify <- true:
	default:
	}
}

// shouldWarn rate limits a warning to one per droppedWarnInterval, last is when it was logged
func shouldWarn(last *atomic.Int64) bool {
	now := time.Now().UnixNano()
	l := last.Load()
	return now-l >= int64(droppedWarnInterval) && last.CompareAndSwap(l, now)
}

func (g *GRPCSender) warnDropped(batches, logs int) {
	if !shouldWarn(&g.lastDropLog) {
		return
	}
	log.Warnf("the backend does not keep up with the access logs: dropped %d logs of %d batches waiting to be sent "+
		"(more than sender.max_pending_logs %d), %d dropped in total", logs, batches, g.maxPendingLogs, g.droppedLogs.Load())
}

// handleLogs sends batches until none is waiting
func (g *GRPCSender) handleLogs() {
	for {
		// pop logs
		pb, probe := g.popBatch()
		if pb == nil {
			return
		}
		logs := pb.logs
		// send logs
		now := time.Now()
		err := g.sendLogs(logs)
		g.sendNanos.Add(int64(time.Since(now)))
		g.sends.Add(1)
		if err != nil {
			g.sendErrors.Add(1)
			lost := g.lostLogs.Add(int64(pb.count))
			// stop draining: the other batches wait for the next AddBatch, which sends one of them to find out
			// whether the backend is back, instead of every worker throwing them at a backend that is not there
			g.mutex.Lock()
			g.halted, g.probing, g.probeDue = true, false, false
			g.mutex.Unlock()
			log.Warnf("sending access log error, lost %d logs (%d in total), error: %v", pb.count, lost, err)
			return
		}
		if probe {
			// the backend is back: every worker drains again
			g.mutex.Lock()
			g.halted, g.probing = false, false
			more := g.logs.Len() > 0
			g.mutex.Unlock()
			if more {
				g.wakeSender()
			}
		}
		log.Infof("sending access log success, connection count: %d, log count: %d, use time: %s",
			logs.ConnectionCount(), pb.count, time.Since(now).String())
	}
}

type pendingBatch struct {
	logs  *BatchLogs
	count int
}

func (g *GRPCSender) sendLogs(batch *BatchLogs) error {
	timeout, cancelFunc := context.WithTimeout(g.ctx, sendStreamTimeout)
	defer cancelFunc()
	streaming, err := g.alsClient.Collect(timeout, collectCallOption)
	if err != nil {
		return err
	}

	firstLog := true
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

		// the first message of the stream names the node, the first message of the connection names it
		header, err := g.encodeMessageHeader(firstLog, connection)
		if err != nil {
			_ = g.closeStream(streaming)
			return fmt.Errorf("encoding the access log connection error: %v", err)
		}
		firstLog = false
		if len(logs.kernels) > 0 {
			sendError = g.sendLogToTheStream(streaming, header, logs.kernels...)
			header = nil
		}
		for _, protocolLog := range logs.protocols {
			if sendError != nil {
				break
			}
			sendError = g.sendLogToTheStream(streaming, header, protocolLog)
			header = nil
		}
		if sendError != nil {
			_ = g.closeStream(streaming)
			return fmt.Errorf("sending access log error: %v", sendError)
		}
	}

	// the backend tells whether it took the stream only when it is closed
	return g.closeStream(streaming)
}

func (g *GRPCSender) closeStream(s v3.EBPFAccessLogService_CollectClient) error {
	if _, err := s.CloseAndRecv(); err != nil {
		return fmt.Errorf("closing the access log streaming error: %v", err)
	}
	return nil
}

// sendLogToTheStream sends one EBPFAccessLogMessage put together from its encoded fields: the header, then the logs
func (g *GRPCSender) sendLogToTheStream(streaming v3.EBPFAccessLogService_CollectClient, header []byte, logs ...[]byte) error {
	return streaming.SendMsg(newPreEncoded(header, logs))
}

// encodeMessageHeader is the node of the stream when it is the first message, and the connection
func (g *GRPCSender) encodeMessageHeader(firstLog bool, conn *common.ConnectionInfo) ([]byte, error) {
	e := &wireEncoder{}
	e.encodeHeader(g.BuildNodeInfo(firstLog), conn.RPCConnection)
	return e.buf, e.err
}

func (g *GRPCSender) BuildNodeInfo(needs bool) *v3.EBPFAccessLogNodeInfo {
	if !needs {
		return nil
	}
	if g.nodeInfo != nil {
		return g.nodeInfo()
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

func (g *GRPCSender) popLogs() *pendingBatch {
	pb, _ := g.popBatch()
	return pb
}

// popBatch takes the next batch to send; probe tells it is the one batch sent while the sender is halted
func (g *GRPCSender) popBatch() (pb *pendingBatch, probe bool) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.logs.Len() == 0 {
		return nil, false
	}
	if g.halted {
		if g.probing || !g.probeDue {
			return nil, false
		}
		g.probing, g.probeDue = true, false
		e := g.logs.Front()
		pb = e.Value.(*pendingBatch)
		g.logs.Remove(e)
		g.pendingLogs -= pb.count
		// no other worker is woken: they wait for the probe
		return pb, true
	}
	e := g.logs.Front()
	batch := e.Value.(*pendingBatch)
	g.logs.Remove(e)
	g.pendingLogs -= batch.count
	if g.logs.Len() > 0 {
		// more wait: let another goroutine take the next one over its own stream
		g.wakeSender()
	}
	return batch, false
}
