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

package base

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"

	"github.com/cilium/ebpf"

	"github.com/sirupsen/logrus"

	cmap "github.com/orcaman/concurrent-map"

	"golang.org/x/sys/unix"
)

type AnalyzerContext struct {
	// listening process map
	processes map[int32][]api.ProcessInterface

	// connection handler
	activeConnections cmap.ConcurrentMap      // current activeConnections connections
	closedConnections []*ConnectionContext    // closed connections'
	flushClosedEvents chan *SocketCloseEvent  // connection have been closed, it is a queue to cache unknown active connections
	sockParseQueue    chan *ConnectionContext // socket address parse queue

	// analyze listener list
	listeners []AnalyzeListener

	// close connection modify locker
	closedConnectionLocker sync.RWMutex
}

func NewAnalyzerContext(processes map[int32][]api.ProcessInterface) *AnalyzerContext {
	return &AnalyzerContext{
		processes:         processes,
		activeConnections: cmap.New(),
		closedConnections: make([]*ConnectionContext, 0),
		flushClosedEvents: make(chan *SocketCloseEvent, 5000),
		sockParseQueue:    make(chan *ConnectionContext, 5000),
		listeners:         make([]AnalyzeListener, 0),
	}
}

func (c *AnalyzerContext) Init(config *base.TaskConfig, moduleManager *module.Manager) error {
	for _, l := range c.listeners {
		if err := l.Init(config, moduleManager); err != nil {
			return err
		}
	}
	return nil
}

func (c *AnalyzerContext) AddListener(l AnalyzeListener) {
	c.listeners = append(c.listeners, l)
}

func (c *AnalyzerContext) GetAllConnectionWithContext() []*ConnectionContext {
	result := make([]*ConnectionContext, 0)
	result = append(result, c.flushClosedConnection()...)
	for _, con := range c.activeConnections.Items() {
		result = append(result, con.(*ConnectionContext))
	}
	return result
}

func (c *AnalyzerContext) RegisterAllHandlers(ctx context.Context, bpfLoader *bpf.Loader) {
	// socket connect
	bpfLoader.ReadEventAsync(bpfLoader.SocketConnectionEventQueue, c.handleSocketConnectEvent, func() interface{} {
		return &SocketConnectEvent{}
	})
	// socket close
	bpfLoader.ReadEventAsync(bpfLoader.SocketCloseEventQueue, c.handleSocketCloseEvent, func() interface{} {
		return &SocketCloseEvent{}
	})
	for _, l := range c.listeners {
		l.RegisterBPFEvents(ctx, bpfLoader)
	}
}

func (c *AnalyzerContext) StartSocketAddressParser(ctx context.Context) {
	for i := 0; i < 2; i++ {
		go c.handleSocketParseQueue(ctx)
	}
}

func (c *AnalyzerContext) GetActiveConnection(conID, randomID uint64) *ConnectionContext {
	data, ok := c.activeConnections.Get(c.generateConnectionKey(conID, randomID))
	if !ok {
		return nil
	}
	return data.(*ConnectionContext)
}

func (c *AnalyzerContext) handleSocketParseQueue(ctx context.Context) {
	for {
		select {
		case cc := <-c.sockParseQueue:
			socket, err := ParseSocket(cc.LocalPid, cc.SocketFD)
			if err != nil {
				// if the remote port of connection is empty, then this connection not available basically
				if cc.RemotePort == 0 {
					log.Warnf("complete the socket error, pid: %d, fd: %d, error: %v", cc.LocalPid, cc.SocketFD, err)
				}
				continue
			}
			cc.LocalIP = socket.SrcIP
			cc.LocalPort = socket.SrcPort
			cc.RemoteIP = socket.DestIP
			cc.RemotePort = socket.DestPort
		case <-ctx.Done():
			return
		}
	}
}

func (c *AnalyzerContext) handleSocketConnectEvent(data interface{}) {
	event := data.(*SocketConnectEvent)

	if log.Enable(logrus.DebugLevel) {
		marshal, _ := json.Marshal(event)
		log.Debugf("found connect event, json: %s", string(marshal))
	}

	processes := c.processes[int32(event.Pid)]
	if len(processes) == 0 {
		log.Warnf("get process connect event, but this process is don't need to monitor, pid: %d", event.Pid)
		return
	}

	// build active connection information
	con := c.NewConnectionContext(event.ConID, event.RandomID, event.Pid, event.FD, processes, false)
	con.Role = event.Role
	if event.NeedComplete == 0 {
		con.RemotePort = uint16(event.RemoteAddrPort)
		con.LocalPort = uint16(event.LocalAddrPort)
		if event.SocketFamily == unix.AF_INET {
			con.LocalIP = parseAddressV4(event.LocalAddrV4)
			con.RemoteIP = parseAddressV4(event.RemoteAddrV4)
		} else {
			con.LocalIP = parseAddressV6(event.LocalAddrV6)
			con.RemoteIP = parseAddressV6(event.RemoteAddrV6)
		}
	} else {
		// if the remote address exists then setting it
		if event.RemoteAddrPort != 0 {
			con.RemotePort = uint16(event.RemoteAddrPort)
			if event.SocketFamily == unix.AF_INET {
				con.RemoteIP = parseAddressV4(event.RemoteAddrV4)
			} else {
				con.RemoteIP = parseAddressV6(event.RemoteAddrV6)
			}
		}
		c.sockParseQueue <- con
	}

	// notify the listeners
	for _, l := range c.listeners {
		l.ReceiveNewConnection(con, event)
	}

	// add to the context
	c.saveActiveConnection(con)
}

func (c *AnalyzerContext) handleSocketCloseEvent(data interface{}) {
	event := data.(*SocketCloseEvent)

	if log.Enable(logrus.DebugLevel) {
		marshal, _ := json.Marshal(event)
		log.Debugf("found close event: %s", string(marshal))
	}

	// try to handle the socket close event
	if !c.socketClosedEvent0(event) {
		// is not in active connection, maybe it's not have been added to activate first
		// just add to the close queue, wait for the flush connection with interval
		c.flushClosedEvents <- event
		return
	}
}

func (c *AnalyzerContext) FlushAllMetrics(bpfLoader *bpf.Loader, metricsPrefix string) (*MetricsBuilder, error) {
	metricsBuilder := NewMetricsBuilder(metricsPrefix)
	err := c.flushMetrics0(bpfLoader, metricsBuilder)
	if err != nil {
		return nil, err
	}
	return metricsBuilder, nil
}

func (c *AnalyzerContext) flushMetrics0(bpfLoader *bpf.Loader, builder *MetricsBuilder) error {
	// handling the unfinished close event
	c.processCachedCloseEvents()

	// get all connections
	ccs := c.GetAllConnectionWithContext()
	if len(ccs) == 0 {
		return nil
	}

	// prepare to flush metrics
	err := c.prepareToFlushMetrics(ccs, bpfLoader)
	if err != nil {
		return fmt.Errorf("prepare to flush the connection metrics failure: %v", err)
	}

	// combine all connections
	analyzer := c.NewTrafficAnalyzer()
	traffics := analyzer.CombineConnectionToTraffics(ccs)

	// generate connections
	for _, l := range c.listeners {
		l.FlushMetrics(traffics, builder)
	}

	// after flush metrics
	for _, l := range c.listeners {
		l.PostFlushConnectionMetrics(ccs)
	}
	return nil
}

func (c *AnalyzerContext) prepareToFlushMetrics(ccs []*ConnectionContext, bpfLoader *bpf.Loader) error {
	var active *ActiveConnectionInBPF
	closedConnections := make([]string, 0)
	connectionWithBPFList := make([]*ConnectionWithBPF, 0)

	for _, cc := range ccs {
		active, closedConnections = c.lookupTheActiveConnectionInBPf(cc, bpfLoader, closedConnections)
		connectionWithBPFList = append(connectionWithBPFList, &ConnectionWithBPF{
			Connection:  cc,
			ActiveInBPF: active,
		})
	}

	// delete closed connections
	if len(closedConnections) > 0 {
		c.deleteConnectionOnly(closedConnections)
	}

	// call the listeners
	for _, l := range c.listeners {
		err := l.PreFlushConnectionMetrics(connectionWithBPFList, bpfLoader)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *AnalyzerContext) lookupTheActiveConnectionInBPf(connection *ConnectionContext, bpfLoader *bpf.Loader,
	closedConnections []string) (active *ActiveConnectionInBPF, closedRef []string) {
	var activeConnection ActiveConnectionInBPF
	// if connection not closed, then load the basic stats from bpf map
	if !connection.ConnectionClosed {
		err := bpfLoader.ActiveConnectionMap.Lookup(connection.ConnectionID, &activeConnection)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				closedConnections = append(closedConnections, c.generateConnectionKey(connection.ConnectionID, connection.RandomID))
				connection.ConnectionClosed = true
			} else {
				log.Warnf("lookup the active connection error, connection id: %d, error: %v", connection.ConnectionID, err)
			}
			return nil, closedConnections
		}

		if log.Enable(logrus.DebugLevel) {
			marshal, _ := json.Marshal(activeConnection)
			log.Debugf("found the active connection, conid: %d, data: %s", connection.ConnectionID, string(marshal))
		}

		if connection.Role == ConnectionRoleUnknown && activeConnection.Role != ConnectionRoleUnknown {
			connection.Role = activeConnection.Role
		}
		if connection.Protocol == ConnectionProtocolUnknown && activeConnection.Protocol != ConnectionProtocolUnknown {
			connection.Protocol = activeConnection.Protocol
		}
		if !connection.IsSSL && activeConnection.IsSSL == 1 {
			connection.IsSSL = true
		}
		return &activeConnection, closedConnections
	}
	return nil, closedConnections
}

func (c *AnalyzerContext) deleteConnectionOnly(ccs []string) {
	for _, cc := range ccs {
		c.activeConnections.Remove(cc)
	}
}

func (c *AnalyzerContext) processCachedCloseEvents() {
	for len(c.flushClosedEvents) > 0 {
		event := <-c.flushClosedEvents
		if !c.socketClosedEvent0(event) {
			// if cannot the found the active connection, then just create a new closed connection context
			processes := c.processes[int32(event.Pid)]
			if len(processes) == 0 {
				continue
			}
			cc := c.NewConnectionContext(event.ConID, event.RandomID, event.Pid, event.SocketFD, processes, true)
			if event.SocketFamily == unix.AF_INET {
				cc.RemoteIP = parseAddressV4(event.RemoteAddrV4)
				cc.LocalIP = parseAddressV4(event.LocalAddrV4)
			} else if event.SocketFamily == unix.AF_INET6 {
				cc.RemoteIP = parseAddressV6(event.RemoteAddrV6)
				cc.LocalIP = parseAddressV6(event.LocalAddrV6)
			} else {
				continue
			}

			// append to the closed connection
			c.appendClosedConnection(c.combineClosedConnection(cc, event))
		}
	}
}

func (c *AnalyzerContext) generateConnectionKey(conID, randomID uint64) string {
	return fmt.Sprintf("%d_%d", conID, randomID)
}

func (c *AnalyzerContext) socketClosedEvent0(event *SocketCloseEvent) bool {
	activeCon := c.foundAndDeleteConnection(event)
	if activeCon == nil {
		return false
	}

	// combine the connection data
	c.appendClosedConnection(c.combineClosedConnection(activeCon, event))
	return true
}

func (c *AnalyzerContext) foundAndDeleteConnection(event *SocketCloseEvent) *ConnectionContext {
	conKey := c.generateConnectionKey(event.ConID, event.RandomID)
	val, exists := c.activeConnections.Pop(conKey)
	if !exists {
		return nil
	}
	return val.(*ConnectionContext)
}

func (c *AnalyzerContext) combineClosedConnection(active *ConnectionContext, closed *SocketCloseEvent) *ConnectionContext {
	active.ConnectionClosed = true

	if active.Role == ConnectionRoleUnknown && closed.Role != ConnectionRoleUnknown {
		active.Role = closed.Role
	}
	if active.Protocol == ConnectionProtocolUnknown && closed.Protocol != ConnectionProtocolUnknown {
		active.Protocol = closed.Protocol
	}
	if !active.IsSSL && closed.IsSSL == 1 {
		active.IsSSL = true
	}

	// notify listeners
	for _, l := range c.listeners {
		l.ReceiveCloseConnection(active, closed)
	}
	return active
}

func (c *AnalyzerContext) saveActiveConnection(con *ConnectionContext) {
	c.activeConnections.Set(c.generateConnectionKey(con.ConnectionID, con.RandomID), con)
}

func (c *AnalyzerContext) flushClosedConnection() []*ConnectionContext {
	c.closedConnectionLocker.Lock()
	defer c.closedConnectionLocker.Unlock()

	connections := c.closedConnections
	c.closedConnections = make([]*ConnectionContext, 0)
	return connections
}

func (c *AnalyzerContext) appendClosedConnection(con *ConnectionContext) {
	c.closedConnectionLocker.RLock()
	defer c.closedConnectionLocker.RUnlock()

	c.closedConnections = append(c.closedConnections, con)
}

func parseAddressV4(val uint32) string {
	return net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&val)))[:]).String()
}

func parseAddressV6(val [16]uint8) string {
	return net.IP((*(*[net.IPv6len]byte)(unsafe.Pointer(&val)))[:]).String()
}
