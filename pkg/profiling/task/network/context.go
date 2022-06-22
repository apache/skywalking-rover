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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-multierror"

	"github.com/cilium/ebpf"

	"golang.org/x/sys/unix"

	"github.com/apache/skywalking-rover/pkg/process/api"
)

type Context struct {
	processes map[int32][]api.ProcessInterface

	bpf *bpfObjects // current bpf programs

	// standard syscall connections
	activeConnections map[string]*ConnectionContext // current activeConnections connections
	closedConnections []*ConnectionContext          // closed connections'
	flushClosedEvents chan *SocketCloseEventWrapper // connection have been closed, it is a queue to cache unknown active connections
	connectionLock    sync.Mutex                    // make sure read write closedConnections is synchronized
	// if the socket close event not handled when flushing, then cache to this array to prevent dead-lock with flushClosedEvents
	secondCloseEventCache []*SocketCloseEventWrapper

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
		activeConnections:      make(map[string]*ConnectionContext),
		closedConnections:      make([]*ConnectionContext, 0),
		flushClosedEvents:      make(chan *SocketCloseEventWrapper, 5000),
		secondCloseEventCache:  make([]*SocketCloseEventWrapper, 0),
		processes:              make(map[int32][]api.ProcessInterface),
		socketExceptionStatics: make(map[SocketBasicKey]*SocketExceptionValue),
	}
}

func (c *Context) Init(bpf *bpfObjects) {
	c.bpf = bpf
}

func (c *Context) RegisterAllHandlers(linker *Linker) {
	// socket connect
	linker.ReadEventAsync(c.bpf.SocketConnectionEventQueue, c.handleSocketConnectEvent, func() interface{} {
		return &SocketConnectEvent{}
	})
	// socket close
	linker.ReadEventAsync(c.bpf.SocketCloseEventQueue, c.handleSocketCloseEvent, func() interface{} {
		return &SocketCloseEvent{}
	})
	// socket retransmit
	linker.ReadEventAsync(c.bpf.SocketExceptionOperationEventQueue, c.handleSocketExceptionOperationEvent, func() interface{} {
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
	c.connectionLock.Lock()
	defer c.connectionLock.Unlock()

	result := make([]*ConnectionContext, 0)
	result = append(result, c.closedConnections...)
	for _, con := range c.activeConnections {
		result = append(result, con)
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

	WriteBytes   uint64
	WriteCount   uint64
	WriteExeTime uint64
	ReadBytes    uint64
	ReadCount    uint64
	ReadExeTime  uint64

	WriteRTTCount   uint64
	WriteRTTExeTime uint64

	// Protocol analyze context
	Protocol              uint32
	ProtocolPrevCount     uint64
	ProtocolPrevBuf       [4]byte
	ProtocolPrependHeader uint32
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

			if cc.Role == ConnectionRoleUnknown && activeConnection.Role != ConnectionRoleUnknown {
				cc.Role = activeConnection.Role
			}

			// update the role
			cc.Role = activeConnection.Role
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
	con := &ConnectionContext{
		// metadata
		ConnectionID:     event.ConID,
		RandomID:         event.RandomID,
		LocalPid:         event.Pid,
		SocketFD:         event.FD,
		LocalProcesses:   processes,
		ConnectionClosed: false,

		// metrics
		WriteCounter:          NewSocketDataCounterWithHistory(),
		ReadCounter:           NewSocketDataCounterWithHistory(),
		WriteRTTCounter:       NewSocketDataCounterWithHistory(),
		WriteRTTHistogram:     NewSocketDataHistogramWithHistory(),
		WriteExeTimeHistogram: NewSocketDataHistogramWithHistory(),
		ReadExeTimeHistogram:  NewSocketDataHistogramWithHistory(),
		ConnectExecuteTime:    event.ExeTime,
	}

	con.Role = event.Role
	var trace string
	if event.NeedComplete == 0 {
		trace = "0"
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
		socket, err := ParseSocket(event.Pid, event.FD)
		if err != nil {
			trace = "1-1"
			// if the remote address exists then setting it
			if event.RemoteAddrPort == 0 {
				log.Debugf("complete the socket error, pid: %d, fd: %d, error: %v", event.Pid, event.FD, err)
			} else {
				con.RemotePort = uint16(event.RemoteAddrPort)
				if event.SocketFamily == unix.AF_INET {
					con.RemoteIP = parseAddressV4(event.RemoteAddrV4)
				} else {
					con.RemoteIP = parseAddressV6(event.RemoteAddrV6)
				}
			}
		} else {
			trace = "1-2"
			con.LocalIP = socket.SrcIP
			con.LocalPort = socket.SrcPort
			con.RemoteIP = socket.DestIP
			con.RemotePort = socket.DestPort
		}
	}

	// add to the context
	c.saveActiveConnection(con)

	if log.Enable(logrus.DebugLevel) {
		marshal, _ := json.Marshal(event)
		log.Debugf("found connect event(%s): role: %s, %s:%d:%d -> %s:%d, json: %s", trace, con.Role.String(),
			con.LocalIP, con.LocalPort, con.LocalPid, con.RemoteIP, con.RemotePort, string(marshal))
	}
}

func (c *Context) saveActiveConnection(con *ConnectionContext) {
	c.connectionLock.Lock()
	defer c.connectionLock.Unlock()
	c.activeConnections[c.generateConnectionKey(con.ConnectionID, con.RandomID)] = con
}

type SocketCloseEvent struct {
	ConID    uint64
	RandomID uint64
	ExeTime  uint64
	Pid      uint32
	SocketFD uint32
	Role     ConnectionRole
	Fix      uint32

	WriteBytes   uint64
	WriteCount   uint64
	WriteExeTime uint64
	ReadBytes    uint64
	ReadCount    uint64
	ReadExeTime  uint64

	WriteRTTCount   uint64
	WriteRTTExeTime uint64
}

type SocketCloseEventWrapper struct {
	*SocketCloseEvent
	NotExistsCount int
}

// batch to re-process all cached closed event
// if the event re-processes once, then just ignore it
func (c *Context) batchReProcessCachedCloseEvent() {
	// handling the second close event cache first, if it's could not be handle, then ignored
	if len(c.secondCloseEventCache) > 0 {
		for _, wrapper := range c.secondCloseEventCache {
			event := wrapper.SocketCloseEvent
			if !c.socketClosedEvent0(event) {
				log.Warnf("found close connection event, but current connection is not in active cache: pid: %d, "+
					"socket fd: %d", event.Pid, event.SocketFD)
			}
		}
		c.secondCloseEventCache = make([]*SocketCloseEventWrapper, 0)
	}

	for len(c.flushClosedEvents) > 0 {
		wrapper := <-c.flushClosedEvents
		if c.socketClosedEvent0(wrapper.SocketCloseEvent) {
			continue
		}
		wrapper.NotExistsCount++
		// try to add the flush queue to re-process when next flush all connections
		c.secondCloseEventCache = append(c.secondCloseEventCache, wrapper)
	}
}

func (c *Context) handleSocketCloseEvent(data interface{}) {
	event := data.(*SocketCloseEvent)

	// try to handle the socket close event
	if !c.socketClosedEvent0(event) {
		// is not in active connection, maybe it's not have been added to activate first
		// just add to the close queue, wait for the flush connection with interval
		c.flushClosedEvents <- &SocketCloseEventWrapper{SocketCloseEvent: event, NotExistsCount: 1}
		return
	}
	if log.Enable(logrus.DebugLevel) {
		marshal, _ := json.Marshal(event)
		log.Debugf("found close event: %s", string(marshal))
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
	c.connectionLock.Lock()
	defer c.connectionLock.Unlock()

	conKey := c.generateConnectionKey(event.ConID, event.RandomID)
	activeCon := c.activeConnections[conKey]
	if activeCon == nil {
		return false
	}

	// delete the active connection
	delete(c.activeConnections, conKey)

	// combine the connection data
	c.closedConnections = append(c.closedConnections, c.combineClosedConnection(activeCon, event))
	return true
}

func (c *Context) deleteConnectionOnly(ccs []string) {
	c.connectionLock.Lock()
	defer c.connectionLock.Unlock()
	for _, cc := range ccs {
		delete(c.activeConnections, cc)
	}
}

func (c *Context) combineClosedConnection(active *ConnectionContext, closed *SocketCloseEvent) *ConnectionContext {
	active.ConnectionClosed = true

	if active.Role == ConnectionRoleUnknown && closed.Role != ConnectionRoleUnknown {
		active.Role = closed.Role
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

		if err1 := c.bpf.ProcessMonitorControl.Update(uint32(pid), uint32(1), ebpf.UpdateAny); err1 != nil {
			err = multierror.Append(err, err1)
		}
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
