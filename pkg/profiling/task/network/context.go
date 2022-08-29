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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	cmap "github.com/orcaman/concurrent-map"

	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-multierror"

	"github.com/cilium/ebpf"

	"golang.org/x/sys/unix"

	"github.com/apache/skywalking-rover/pkg/process/api"
)

type Context struct {
	processes map[int32][]api.ProcessInterface

	bpf    *bpfObjects // current bpf programs
	linker *Linker

	// standard syscall connections
	activeConnections cmap.ConcurrentMap      // current activeConnections connections
	closedConnections []*ConnectionContext    // closed connections'
	flushClosedEvents chan *SocketCloseEvent  // connection have been closed, it is a queue to cache unknown active connections
	sockParseQueue    chan *ConnectionContext // socket address parse queue

	// socket retransmit/drop
	socketExceptionStatics       map[SocketBasicKey]*SocketExceptionValue
	socketExceptionOperationLock sync.Mutex
}

type SocketBasicKey struct {
	Pid          uint32
	Family       uint32
	RemoteAddrV4 uint32
	RemoteAddrV6 [16]uint8
	RemotePort   uint32
	LocalAddrV4  uint32
	LocalAddrV6  [16]uint8
	LocalPort    uint32
}

type SocketExceptionValue struct {
	DropCount       int
	RetransmitCount int
}

type ConnectionContext struct {
	// basic metadata
	ConnectionID     uint64
	RandomID         uint64
	LocalPid         uint32
	SocketFD         uint32
	LocalProcesses   []api.ProcessInterface
	ConnectionClosed bool
	Protocol         ConnectionProtocol
	IsSSL            bool

	// socket metadata
	Role       ConnectionRole
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16

	// basic statics
	// read/write
	WriteCounter *SocketDataCounterWithHistory
	ReadCounter  *SocketDataCounterWithHistory
	// write RTT
	WriteRTTCounter *SocketDataCounterWithHistory

	// histograms
	// write execute time and RTT
	WriteRTTHistogram     *SocketDataHistogramWithHistory
	WriteExeTimeHistogram *SocketDataHistogramWithHistory
	// read execute time
	ReadExeTimeHistogram *SocketDataHistogramWithHistory

	// the connection connect or close execute time
	ConnectExecuteTime uint64
	CloseExecuteTime   uint64

	// exception counters
	RetransmitCounter *SocketDataCounter
	DropCounter       *SocketDataCounter

	// Flush the data content to the oap count
	FlushDataCount int
}

func NewContext() *Context {
	return &Context{
		activeConnections:      cmap.New(),
		closedConnections:      make([]*ConnectionContext, 0),
		flushClosedEvents:      make(chan *SocketCloseEvent, 5000),
		sockParseQueue:         make(chan *ConnectionContext, 5000),
		processes:              make(map[int32][]api.ProcessInterface),
		socketExceptionStatics: make(map[SocketBasicKey]*SocketExceptionValue),
	}
}

func (c *Context) Init(bpf *bpfObjects, linker *Linker) {
	c.bpf = bpf
	c.linker = linker
}

func (c *Context) RegisterAllHandlers() {
	// socket connect
	c.linker.ReadEventAsync(c.bpf.SocketConnectionEventQueue, c.handleSocketConnectEvent, func() interface{} {
		return &SocketConnectEvent{}
	})
	// socket close
	c.linker.ReadEventAsync(c.bpf.SocketCloseEventQueue, c.handleSocketCloseEvent, func() interface{} {
		return &SocketCloseEvent{}
	})
	// socket retransmit
	c.linker.ReadEventAsync(c.bpf.SocketExceptionOperationEventQueue, c.handleSocketExceptionOperationEvent, func() interface{} {
		return &SocketExceptionOperationEvent{}
	})
}

func (c *Context) FlushAllConnection() ([]*ConnectionContext, error) {
	// handling the unfinished close event
	c.batchReProcessCachedCloseEvent()

	// get all connection context and fill the metrics
	allContexts := c.getAllConnectionWithContext()
	c.fillConnectionMetrics(allContexts)

	// all the exception operations to the context
	exceptionContexts := c.cleanAndGetAllExceptionContexts()
	// init all exception counters
	for _, ctx := range allContexts {
		ctx.DropCounter = NewSocketDataCounter()
		ctx.RetransmitCounter = NewSocketDataCounter()
	}
	c.combineExceptionToConnections(allContexts, exceptionContexts)

	return allContexts, nil
}

func (c *Context) StartSocketAddressParser(ctx context.Context) {
	for i := 0; i < 2; i++ {
		go c.handleSocketParseQueue(ctx)
	}
}

func (c *Context) handleSocketParseQueue(ctx context.Context) {
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

func (c *Context) combineExceptionToConnections(ccs []*ConnectionContext, exps map[SocketBasicKey]*SocketExceptionValue) {
	for key, value := range exps {
		var remotePort, localPort = uint16(key.RemotePort), uint16(key.LocalPort)
		var remoteIP, localIP string

		if key.Family == unix.AF_INET {
			remoteIP = parseAddressV4(key.RemoteAddrV4)
			localIP = parseAddressV4(key.LocalAddrV4)
		} else if key.Family == unix.AF_INET6 {
			remoteIP = parseAddressV6(key.RemoteAddrV6)
			localIP = parseAddressV6(key.LocalAddrV6)
		} else {
			continue
		}

		var firstRemoteMatch *ConnectionContext
		var foundAllAddrMatch bool
		for _, cc := range ccs {
			// only add to the first matches
			if cc.RemoteIP == remoteIP && cc.RemotePort == remotePort {
				firstRemoteMatch = cc
				if cc.LocalIP == localIP && cc.LocalPort == localPort {
					c.mergeExceptionToAppointConnection(value, cc)
					foundAllAddrMatch = true
					break
				}
			}
		}

		// if only remote address match, then just add to the first one
		if !foundAllAddrMatch && firstRemoteMatch != nil {
			c.mergeExceptionToAppointConnection(value, firstRemoteMatch)
		}
	}
}

func (c *Context) mergeExceptionToAppointConnection(expCtx *SocketExceptionValue, conCtx *ConnectionContext) {
	conCtx.DropCounter.IncreaseByValue(0, uint64(expCtx.DropCount), 0)
	conCtx.RetransmitCounter.IncreaseByValue(0, uint64(expCtx.RetransmitCount), 0)
}

func (c *Context) cleanAndGetAllExceptionContexts() map[SocketBasicKey]*SocketExceptionValue {
	c.socketExceptionOperationLock.Lock()
	defer c.socketExceptionOperationLock.Unlock()

	result := c.socketExceptionStatics
	c.socketExceptionStatics = make(map[SocketBasicKey]*SocketExceptionValue)
	return result
}

func (c *Context) getAllConnectionWithContext() []*ConnectionContext {
	result := make([]*ConnectionContext, 0)
	result = append(result, c.closedConnections...)
	for _, con := range c.activeConnections.Items() {
		result = append(result, con.(*ConnectionContext))
	}

	c.closedConnections = make([]*ConnectionContext, 0)
	return result
}

type ActiveConnectionInBPF struct {
	RandomID     uint64
	Pid          uint32
	SocketFD     uint32
	Role         ConnectionRole
	SocketFamily uint32

	RemoteAddrV4   uint32
	RemoteAddrV6   [16]uint8
	RemoteAddrPort uint32
	LocalAddrV4    uint32
	LocalAddrV6    [16]uint8
	LocalAddrPort  uint32

	WriteBytes   uint64
	WriteCount   uint64
	WriteExeTime uint64
	ReadBytes    uint64
	ReadCount    uint64
	ReadExeTime  uint64

	WriteRTTCount   uint64
	WriteRTTExeTime uint64

	// Protocol analyze context
	Protocol              ConnectionProtocol
	Fix                   uint32
	ProtocolPrevCount     uint64
	ProtocolPrevBuf       [4]byte
	ProtocolPrependHeader uint32
	IsSSL                 uint32

	// the connect event is already sent
	ConnectEventIsSent uint32
}

type HistogramDataKey struct {
	ConnectionID  uint64
	RandomID      uint64
	DataDirection SocketDataDirection
	DataType      SocketDataStaticsType
	Bucket        uint64
}

func (c *Context) fillConnectionMetrics(ccs []*ConnectionContext) {
	// rebuild to the map for helping quick search correlate ConnectionContext
	keyWithContext := make(map[string]*ConnectionContext)
	var activeConnection ActiveConnectionInBPF
	closedConns := make([]string, 0)
	for _, cc := range ccs {
		connectionKey := c.generateConnectionKey(cc.ConnectionID, cc.RandomID)
		// refresh the histogram for prepare to update the buckets
		cc.WriteRTTHistogram.RefreshCurrent()
		cc.WriteExeTimeHistogram.RefreshCurrent()
		cc.ReadExeTimeHistogram.RefreshCurrent()
		keyWithContext[connectionKey] = cc

		// if connection not closed, then load the basic stats from bpf map
		if !cc.ConnectionClosed {
			err := c.bpf.ActiveConnectionMap.Lookup(cc.ConnectionID, &activeConnection)

			if err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					closedConns = append(closedConns, connectionKey)
				} else {
					log.Warnf("lookup the active connection error, connection id: %d, error: %v", cc.ConnectionID, err)
				}
				continue
			}

			if log.Enable(logrus.DebugLevel) {
				marshal, _ := json.Marshal(activeConnection)
				log.Debugf("found the active connection, conid: %d, data: %s", cc.ConnectionID, string(marshal))
			}

			if cc.Role == ConnectionRoleUnknown && activeConnection.Role != ConnectionRoleUnknown {
				cc.Role = activeConnection.Role
			}
			if cc.Protocol == ConnectionProtocolUnknown && activeConnection.Protocol != ConnectionProtocolUnknown {
				cc.Protocol = activeConnection.Protocol
			}
			if !cc.IsSSL && activeConnection.IsSSL == 1 {
				cc.IsSSL = true
			}

			// update the role
			cc.WriteCounter.UpdateToCurrent(activeConnection.WriteBytes, activeConnection.WriteCount, activeConnection.WriteExeTime)
			cc.ReadCounter.UpdateToCurrent(activeConnection.ReadBytes, activeConnection.ReadCount, activeConnection.ReadExeTime)
			cc.WriteRTTCounter.UpdateToCurrent(0, activeConnection.WriteRTTCount, activeConnection.WriteRTTExeTime)
		}
	}
	if len(closedConns) > 0 {
		c.deleteConnectionOnly(closedConns)
	}

	// fill the histogram metrics
	c.fillHistograms(keyWithContext)
}

func (c *Context) fillHistograms(keyWithContext map[string]*ConnectionContext) {
	var key HistogramDataKey
	var count uint32
	histogramIt := c.bpf.SocketConnectionStatsHistogram.Iterate()
	// for-each the stats map
	for histogramIt.Next(&key, &count) {
		// if it's not relate to the ConnectionContext just ignore
		cc := keyWithContext[c.generateConnectionKey(key.ConnectionID, key.RandomID)]
		if cc == nil {
			continue
		}

		// add the histogram data
		var histogram *SocketDataHistogramWithHistory
		if key.DataDirection == SocketDataDirectionEgress {
			if key.DataType == SocketDataStaticsTypeExeTime {
				histogram = cc.WriteExeTimeHistogram
			} else if key.DataType == SocketDataStaticsTypeRTT {
				histogram = cc.WriteRTTHistogram
			}
		} else if key.DataDirection == SocketDataDirectionIngress {
			histogram = cc.ReadExeTimeHistogram
		}
		if histogram == nil {
			log.Warnf("unknown the histogram data: %v", cc)
			continue
		}
		histogram.UpdateToCurrent(key.Bucket, count)

		// delete the stats if the connection already closed
		if cc.ConnectionClosed {
			if err := c.bpf.SocketConnectionStatsHistogram.Delete(key); err != nil {
				log.Warnf("delete the connection stats failure: %v", err)
			}
		}
	}
}

// SocketConnectEvent Socket have been connection/accept event
type SocketConnectEvent struct {
	ConID        uint64
	RandomID     uint64
	ExeTime      uint64
	NeedComplete uint32
	Pid          uint32
	FD           uint32
	FuncName     uint32

	// socket information if exists
	Role           ConnectionRole
	SocketFamily   uint32
	RemoteAddrV4   uint32
	RemoteAddrV6   [16]uint8
	RemoteAddrPort uint32
	LocalAddrV4    uint32
	LocalAddrV6    [16]uint8
	LocalAddrPort  uint32
}

func (c *Context) handleSocketConnectEvent(data interface{}) {
	event := data.(*SocketConnectEvent)
	processes := c.processes[int32(event.Pid)]
	if len(processes) == 0 {
		log.Warnf("get process connect event, but this process is don't need to monitor, pid: %d", event.Pid)
		return
	}

	// build active connection information
	con := c.newConnectionContext(event.ConID, event.RandomID, event.Pid, event.FD, processes, false)
	con.ConnectExecuteTime = event.ExeTime
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

	// add to the context
	c.saveActiveConnection(con)

	if log.Enable(logrus.DebugLevel) {
		marshal, _ := json.Marshal(event)
		log.Debugf("found connect event: role: %s, %s:%d:%d -> %s:%d, json: %s", con.Role.String(),
			con.LocalIP, con.LocalPort, con.LocalPid, con.RemoteIP, con.RemotePort, string(marshal))
	}
}

func (c *Context) saveActiveConnection(con *ConnectionContext) {
	c.activeConnections.Set(c.generateConnectionKey(con.ConnectionID, con.RandomID), con)
}

type SocketCloseEvent struct {
	ConID    uint64
	RandomID uint64
	ExeTime  uint64
	Pid      uint32
	SocketFD uint32
	Role     ConnectionRole
	Protocol ConnectionProtocol
	IsSSL    uint32
	Fix      uint32

	SocketFamily   uint32
	RemoteAddrV4   uint32
	RemoteAddrV6   [16]uint8
	RemoteAddrPort uint32
	LocalAddrV4    uint32
	LocalAddrV6    [16]uint8
	LocalAddrPort  uint32
	Fix1           uint32

	WriteBytes   uint64
	WriteCount   uint64
	WriteExeTime uint64
	ReadBytes    uint64
	ReadCount    uint64
	ReadExeTime  uint64

	WriteRTTCount   uint64
	WriteRTTExeTime uint64
}

// batch to re-process all cached closed event
func (c *Context) batchReProcessCachedCloseEvent() {
	for len(c.flushClosedEvents) > 0 {
		event := <-c.flushClosedEvents
		if !c.socketClosedEvent0(event) {
			// if cannot the found the active connection, then just create a new closed connection context
			processes := c.processes[int32(event.Pid)]
			if len(processes) == 0 {
				continue
			}
			cc := c.newConnectionContext(event.ConID, event.RandomID, event.Pid, event.SocketFD, processes, true)
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
			c.closedConnections = append(c.closedConnections, c.combineClosedConnection(cc, event))
		}
	}
}

func (c *Context) newConnectionContext(conID, randomID uint64, pid, fd uint32, processes []api.ProcessInterface, conClosed bool) *ConnectionContext {
	return &ConnectionContext{
		// metadata
		ConnectionID:     conID,
		RandomID:         randomID,
		LocalPid:         pid,
		SocketFD:         fd,
		LocalProcesses:   processes,
		ConnectionClosed: conClosed,

		// metrics
		WriteCounter:          NewSocketDataCounterWithHistory(),
		ReadCounter:           NewSocketDataCounterWithHistory(),
		WriteRTTCounter:       NewSocketDataCounterWithHistory(),
		WriteRTTHistogram:     NewSocketDataHistogramWithHistory(HistogramDataUnitUS),
		WriteExeTimeHistogram: NewSocketDataHistogramWithHistory(HistogramDataUnitNS),
		ReadExeTimeHistogram:  NewSocketDataHistogramWithHistory(HistogramDataUnitNS),
	}
}

func (c *Context) handleSocketCloseEvent(data interface{}) {
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

// SocketExceptionOperationEvent Socket have been retransmitted/drop the package event
type SocketExceptionOperationEvent struct {
	Pid            uint32
	SocketFamily   uint32
	RemoteAddrV4   uint32
	RemoteAddrV6   [16]uint8
	RemoteAddrPort uint32
	Type           SocketExceptionOperationType
}

func (c *Context) handleSocketExceptionOperationEvent(data interface{}) {
	event := data.(*SocketExceptionOperationEvent)
	c.socketExceptionOperationLock.Lock()
	defer c.socketExceptionOperationLock.Unlock()

	key := SocketBasicKey{
		Pid:          event.Pid,
		Family:       event.SocketFamily,
		RemoteAddrV4: event.RemoteAddrV4,
		RemoteAddrV6: event.RemoteAddrV6,
		RemotePort:   event.RemoteAddrPort,
	}
	exceptionValue := c.socketExceptionStatics[key]
	if exceptionValue == nil {
		exceptionValue = &SocketExceptionValue{}
		c.socketExceptionStatics[key] = exceptionValue
	}

	switch event.Type {
	case SocketExceptionOperationRetransmit:
		exceptionValue.RetransmitCount++
	case SocketExceptionOperationDrop:
		exceptionValue.DropCount++
	default:
		log.Warnf("unknown socket exception operation type: %d", event.Type)
	}

	if log.Enable(logrus.DebugLevel) {
		marshal, _ := json.Marshal(event)
		log.Debugf("found socket exception operation event: %s", string(marshal))
	}
}

func (c *Context) socketClosedEvent0(event *SocketCloseEvent) bool {
	activeCon := c.foundAndDeleteConnection(event)
	if activeCon == nil {
		return false
	}

	// combine the connection data
	c.closedConnections = append(c.closedConnections, c.combineClosedConnection(activeCon, event))
	return true
}

func (c *Context) foundAndDeleteConnection(event *SocketCloseEvent) *ConnectionContext {
	conKey := c.generateConnectionKey(event.ConID, event.RandomID)
	val, exists := c.activeConnections.Pop(conKey)
	if !exists {
		return nil
	}
	return val.(*ConnectionContext)
}

func (c *Context) deleteConnectionOnly(ccs []string) {
	for _, cc := range ccs {
		c.activeConnections.Remove(cc)
	}
}

func (c *Context) combineClosedConnection(active *ConnectionContext, closed *SocketCloseEvent) *ConnectionContext {
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

	active.WriteCounter.UpdateToCurrent(closed.WriteBytes, closed.WriteCount, closed.WriteExeTime)
	active.ReadCounter.UpdateToCurrent(closed.ReadBytes, closed.ReadCount, closed.ReadExeTime)
	active.WriteRTTCounter.UpdateToCurrent(0, closed.WriteRTTCount, closed.WriteRTTExeTime)
	active.CloseExecuteTime = closed.ExeTime
	return active
}

func (c *Context) generateConnectionKey(conID, randomID uint64) string {
	return fmt.Sprintf("%d_%d", conID, randomID)
}

func (c *Context) AddProcesses(processes []api.ProcessInterface) error {
	var err error
	for _, p := range processes {
		pid := p.Pid()
		alreadyExists := false
		if len(c.processes[pid]) > 0 {
			for _, existsProcess := range c.processes[pid] {
				if p.ID() == existsProcess.ID() {
					alreadyExists = true
					break
				}
			}
		}

		if alreadyExists {
			continue
		}

		c.processes[pid] = append(c.processes[pid], p)

		// add to the process let it could be monitored
		if err1 := c.bpf.ProcessMonitorControl.Update(uint32(pid), uint32(1), ebpf.UpdateAny); err1 != nil {
			err = multierror.Append(err, err1)
		}

		// add process ssl config
		if err1 := addSSLProcess(int(pid), c.bpf, c.linker); err1 != nil {
			err = multierror.Append(err, err1)
		}

		log.Debugf("add monitor process, pid: %d", pid)
	}
	return err
}

func (c *Context) DeleteProcesses(processes []api.ProcessInterface) (emptyProcesses bool, deleteError error) {
	var err error
	for _, p := range processes {
		pid := p.Pid()
		existsProcesses := make([]api.ProcessInterface, 0)
		existsProcesses = append(existsProcesses, c.processes[pid]...)

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
			if err1 := c.bpf.ProcessMonitorControl.Delete(uint32(pid)); err1 != nil {
				err = multierror.Append(err, err1)
			}
			log.Debugf("delete monitor process: %d", pid)
			delete(c.processes, pid)
			continue
		}
		c.processes[pid] = newProcesses
	}
	return len(c.processes) == 0, err
}

func parseAddressV4(val uint32) string {
	return net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&val)))[:]).String()
}

func parseAddressV6(val [16]uint8) string {
	return net.IP((*(*[net.IPv6len]byte)(unsafe.Pointer(&val)))[:]).String()
}
