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

package common

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/kubernetes"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/ip"
	"github.com/apache/skywalking-rover/pkg/tools/path"

	"github.com/cilium/ebpf"

	cmap "github.com/orcaman/concurrent-map"

	"k8s.io/apimachinery/pkg/util/cache"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

const (
	// clean the active connection in BPF interval
	cleanActiveConnectionInterval = time.Second * 20

	// in case the reading the data from BPF queue is disordered, so add a delay time to delete the connection information
	connectionDeleteDelayTime = time.Second * 20

	// the connection check exist time
	connectionCheckExistTime = time.Second * 30
)

type ConnectEventWithSocket struct {
	*events.SocketConnectEvent
	SocketPair *ip.SocketPair
}

type CloseEventWithNotify struct {
	*events.SocketCloseEvent
}

type ConnectionProcessFinishCallback func()

type ConnectionProcessor interface {
}

type FlusherListener interface {
	// ReadyToFlushConnection notify which connection ready to flush
	ReadyToFlushConnection(connection *ConnectionInfo, getConnectionFromEvent events.Event)
}

type ProcessListener interface {
	OnNewProcessMonitoring(pid int32)
	OnProcessRemoved(pid int32)
}

type ConnectionManager struct {
	moduleMgr   *module.Manager
	processOP   process.Operator
	connections cmap.ConcurrentMap
	// localIPWithPid cache all local monitoring process bind IP address
	// for checking the remote address is local or not
	localIPWithPid map[string]int32
	// monitoringProcesses management all monitoring processes
	monitoringProcesses   map[int32][]api.ProcessInterface
	monitoringProcessLock sync.RWMutex
	// monitoring process map in BPF
	processMonitorMap   *ebpf.Map
	activeConnectionMap *ebpf.Map

	monitorFilter MonitorFilter

	processors       []ConnectionProcessor
	processListeners []ProcessListener

	flushListeners []FlusherListener

	connectTracker *ip.ConnTrack

	connectionProtocolBreakMap *cache.Expiring
}

func (c *ConnectionManager) RegisterProcessor(processor ConnectionProcessor) {
	c.processors = append(c.processors, processor)
}

func (c *ConnectionManager) AddProcessListener(listener ProcessListener) {
	c.processListeners = append(c.processListeners, listener)
}

func (c *ConnectionManager) RegisterNewFlushListener(listener FlusherListener) {
	c.flushListeners = append(c.flushListeners, listener)
}

type ConnectionInfo struct {
	ConnectionID       uint64
	RandomID           uint64
	RPCConnection      *v3.AccessLogConnection
	MarkDeletable      bool
	PID                uint32
	Socket             *ip.SocketPair
	LastCheckExistTime time.Time
	DeleteAfter        *time.Time
	ProtocolBreak      bool
}

func NewConnectionManager(_ *Config, moduleMgr *module.Manager, bpfLoader *bpf.Loader, filter MonitorFilter) *ConnectionManager {
	track, err := ip.NewConnTrack()
	if err != nil {
		log.Warnf("cannot create the connection tracker, %v", err)
	}
	mgr := &ConnectionManager{
		moduleMgr:                  moduleMgr,
		processOP:                  moduleMgr.FindModule(process.ModuleName).(process.Operator),
		connections:                cmap.New(),
		localIPWithPid:             make(map[string]int32),
		monitoringProcesses:        make(map[int32][]api.ProcessInterface),
		processMonitorMap:          bpfLoader.ProcessMonitorControl,
		activeConnectionMap:        bpfLoader.ActiveConnectionMap,
		monitorFilter:              filter,
		flushListeners:             make([]FlusherListener, 0),
		connectTracker:             track,
		connectionProtocolBreakMap: cache.NewExpiring(),
	}
	return mgr
}

func (c *ConnectionManager) Start(ctx context.Context, accessLogContext *AccessLogContext) {
	c.processOP.AddListener(c)

	// starting to clean up the un-active connection in BPF
	go func() {
		ticker := time.NewTicker(cleanActiveConnectionInterval)
		for {
			select {
			case <-ticker.C:
				activeConnections := c.activeConnectionMap.Iterate()
				var conID uint64
				var activateConn ActiveConnection
				for activeConnections.Next(&conID, &activateConn) {
					// if the connection is existed, then check the next one
					pid, fd := events.ParseConnectionID(conID)
					if c.checkProcessFDExist(pid, fd) {
						continue
					}

					// if the connection is not existed, then delete it
					if err := c.activeConnectionMap.Delete(conID); err != nil {
						if !errors.Is(err, ebpf.ErrKeyNotExist) {
							log.Warnf("failed to delete the active connection, pid: %d, fd: %d, connection ID: %d, random ID: %d, error: %v",
								pid, fd, conID, activateConn.RandomID, err)
						}
						continue
					}
					log.Debugf("deleted the active connection as not exist in file system, pid: %d, fd: %d, connection ID: %d, random ID: %d",
						pid, fd, conID, activateConn.RandomID)

					// building and send the close event
					wapperedEvent := c.OnConnectionClose(&events.SocketCloseEvent{
						ConnectionID: conID,
						RandomID:     activateConn.RandomID,
						StartTime:    0,
						EndTime:      0,
						PID:          activateConn.PID,
						SocketFD:     activateConn.SocketFD,
						Success:      0,
					})
					accessLogContext.Queue.AppendKernelLog(NewKernelLogEvent(LogTypeClose, wapperedEvent))
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *ConnectionManager) checkProcessFDExist(pid, fd uint32) bool {
	return path.Exists(host.GetHostProcInHost(fmt.Sprintf("%d/fd/%d", pid, fd)))
}

func (c *ConnectionManager) Stop() {
	c.processOP.DeleteListener(c)
}

func (c *ConnectionManager) OnNewProcessExecuting(pid int32) {
	// if the process should not be monitoring, then delete in the map
	if !c.processOP.ShouldMonitor(pid) {
		c.updateMonitorStatusForProcess(pid, false)
	}
}

func (c *ConnectionManager) GetExcludeNamespaces() []string {
	return c.monitorFilter.ExcludeNamespaces()
}

func (c *ConnectionManager) Find(event events.Event) *ConnectionInfo {
	connectionKey := fmt.Sprintf("%d_%d", event.GetConnectionID(), event.GetRandomID())
	data, exist := c.connections.Get(connectionKey)
	if exist {
		connection := data.(*ConnectionInfo)
		c.connectionPostHandle(connection, event)
		return connection
	}
	// is current is connected event, then getting the socket pair
	if e, socket := getSocketPairFromConnectEvent(event); e != nil && socket != nil {
		var localAddress, remoteAddress *v3.ConnectionAddress
		localPID, _ := events.ParseConnectionID(event.GetConnectionID())
		localAddress = c.buildLocalAddress(localPID, socket.SrcPort, socket)
		remoteAddress = c.buildRemoteAddress(e, socket)
		if localAddress == nil || remoteAddress == nil {
			return nil
		}
		connection := c.buildConnection(e, socket, localAddress, remoteAddress, connectionKey)
		c.connections.Set(connectionKey, connection)
		if log.Enable(logrus.DebugLevel) {
			log.Debugf("building flushing connection, connection ID: %d, randomID: %d, role: %s, local: %s:%d, remote: %s:%d, "+
				"local address: %s, remote address: %s, protocol: %s",
				e.GetConnectionID(), e.GetRandomID(), socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort,
				localAddress.String(), remoteAddress.String(), connection.RPCConnection.Protocol.String())
		}
		c.connectionPostHandle(connection, event)
		return connection
	}
	return nil
}

func (c *ConnectionManager) buildRemoteAddress(e *events.SocketConnectEvent, socket *ip.SocketPair) *v3.ConnectionAddress {
	// if the remote address is local, then no needs to build the address(access log no need to send by communicate with self)
	if tools.IsLocalHostAddress(socket.DestIP) {
		return nil
	}

	// if the remote connection is need to use conntrack, then update the real peer address
	if socket.NeedConnTrack {
		if err := c.connectTracker.UpdateRealPeerAddress(socket); err != nil {
			log.Debugf("cannot update the real peer address, %v", err)
		}
	}

	// found local address with pid
	if pid, exist := c.localIPWithPid[socket.DestIP]; exist && pid != 0 {
		return c.buildLocalAddress(uint32(pid), socket.DestPort, socket)
	}

	log.Debugf("building the remote address to unknown, connection: %d-%d, role: %s, local: %s:%d, remote: %s:%d",
		e.GetConnectionID(), e.GetRandomID(), socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort)
	return c.buildAddressFromRemote(socket.DestIP, socket.DestPort)
}

func (c *ConnectionManager) connectionPostHandle(connection *ConnectionInfo, event events.Event) {
	if connection == nil {
		return
	}
	switch e := event.(type) {
	case *CloseEventWithNotify:
		connection.MarkDeletable = true
	case events.SocketDetail:
		tlsMode := connection.RPCConnection.TlsMode
		protocol := connection.RPCConnection.Protocol
		if e.GetSSL() == 1 && connection.RPCConnection.TlsMode == v3.AccessLogConnectionTLSMode_Plain {
			tlsMode = v3.AccessLogConnectionTLSMode_TLS
		}
		if !connection.ProtocolBreak && e.GetProtocol() != enums.ConnectionProtocolUnknown &&
			connection.RPCConnection.Protocol == v3.AccessLogProtocolType_TCP {
			switch e.GetProtocol() {
			case enums.ConnectionProtocolHTTP:
				protocol = v3.AccessLogProtocolType_HTTP_1
			case enums.ConnectionProtocolHTTP2:
				protocol = v3.AccessLogProtocolType_HTTP_2
			}
		}
		if connection.ProtocolBreak && connection.RPCConnection.Protocol != v3.AccessLogProtocolType_TCP {
			protocol = v3.AccessLogProtocolType_TCP
		}
		c.rebuildRPCConnectionWithTLSModeAndProtocol(connection, tlsMode, protocol)
	}

	// notify all flush listeners the connection is ready to flush
	for _, flush := range c.flushListeners {
		flush.ReadyToFlushConnection(connection, event)
	}
}

// According to https://github.com/golang/protobuf/issues/1609
// if the message is modified during marshaling, it may cause the error when send the message to the backend
// so, we need to clone the message and change it before sending it to the channel
func (c *ConnectionManager) rebuildRPCConnectionWithTLSModeAndProtocol(connection *ConnectionInfo,
	tls v3.AccessLogConnectionTLSMode, protocol v3.AccessLogProtocolType) {
	original := connection.RPCConnection
	connection.RPCConnection = &v3.AccessLogConnection{
		Local:      original.Local,
		Remote:     original.Remote,
		Role:       original.Role,
		TlsMode:    tls,
		Protocol:   protocol,
		Attachment: original.Attachment,
	}
}

func (c *ConnectionManager) ProcessIsMonitor(pid uint32) bool {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	return len(c.monitoringProcesses[int32(pid)]) > 0
}

func (c *ConnectionManager) ProcessIsDetectBy(pid uint32, detectType api.ProcessDetectType) bool {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	for _, p := range c.monitoringProcesses[int32(pid)] {
		if p.DetectType() == detectType {
			return true
		}
	}
	return false
}

func (c *ConnectionManager) buildConnection(event *events.SocketConnectEvent, socket *ip.SocketPair,
	local, remote *v3.ConnectionAddress, conKey string) *ConnectionInfo {
	var role v32.DetectPoint
	switch socket.Role {
	case enums.ConnectionRoleClient:
		role = v32.DetectPoint_client
	case enums.ConnectionRoleServer:
		role = v32.DetectPoint_server
	}
	connection := &v3.AccessLogConnection{
		Local:    local,
		Remote:   remote,
		Role:     role,
		TlsMode:  v3.AccessLogConnectionTLSMode_Plain,
		Protocol: v3.AccessLogProtocolType_TCP,
	}
	val, exist := c.connectionProtocolBreakMap.Get(conKey)
	protocolBreak := false
	if exist {
		protocolBreak = val.(bool)
		c.connectionProtocolBreakMap.Delete(conKey)
	}
	return &ConnectionInfo{
		ConnectionID:       event.ConID,
		RandomID:           event.RandomID,
		RPCConnection:      connection,
		PID:                event.PID,
		Socket:             socket,
		LastCheckExistTime: time.Now(),
		ProtocolBreak:      protocolBreak,
	}
}

func (c *ConnectionManager) buildLocalAddress(pid uint32, port uint16, socket *ip.SocketPair) *v3.ConnectionAddress {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	for _, pi := range c.monitoringProcesses[int32(pid)] {
		if pi.DetectType() == api.Kubernetes {
			entity := pi.Entity()
			podContainer := pi.DetectProcess().(*kubernetes.Process).PodContainer()
			return &v3.ConnectionAddress{
				Address: &v3.ConnectionAddress_Kubernetes{
					Kubernetes: &v3.KubernetesProcessAddress{
						ServiceName:   entity.ServiceName,
						PodName:       podContainer.Pod.Name,
						ContainerName: podContainer.ContainerSpec.Name,
						ProcessName:   entity.ProcessName,
						Port:          int32(port),
					},
				},
			}
		}
	}
	return &v3.ConnectionAddress{
		Address: &v3.ConnectionAddress_Ip{
			Ip: &v3.IPAddress{
				Host: socket.SrcIP,
				Port: int32(port),
			},
		},
	}
}

func (c *ConnectionManager) buildAddressFromRemote(ipHost string, port uint16) *v3.ConnectionAddress {
	return &v3.ConnectionAddress{
		Address: &v3.ConnectionAddress_Ip{
			Ip: &v3.IPAddress{
				Host: ipHost,
				Port: int32(port),
			},
		},
	}
}

func (c *ConnectionManager) OnConnectionClose(event *events.SocketCloseEvent) *CloseEventWithNotify {
	return &CloseEventWithNotify{
		SocketCloseEvent: event,
	}
}

func (c *ConnectionManager) AddNewProcess(pid int32, entities []api.ProcessInterface) {
	// filtering the namespace
	monitorProcesses := c.shouldMonitorProcesses(entities)
	if len(monitorProcesses) == 0 {
		c.RemoveProcess(pid, entities)
		return
	}

	c.monitoringProcessLock.Lock()
	defer c.monitoringProcessLock.Unlock()

	// adding monitoring process and IP addresses
	var entity *api.ProcessEntity
	if len(entities) > 0 {
		entity = entities[0].Entity()
	}
	log.Infof("adding monitoring process, pid: %d, entity: %v", pid, entity)
	if _, ok := c.monitoringProcesses[pid]; ok {
		log.Infof("the process %d already monitoring, so no needs to add again", pid)
		return
	}
	c.monitoringProcesses[pid] = monitorProcesses
	c.updateMonitorStatusForProcess(pid, true)
	for _, entity := range monitorProcesses {
		for _, host := range entity.ExposeHosts() {
			c.localIPWithPid[host] = pid
		}
	}
	c.printTotalAddressesWithPid("adding monitoring process")
	for _, l := range c.processListeners {
		l.OnNewProcessMonitoring(pid)
	}
}

func (c *ConnectionManager) rebuildLocalIPWithPID() {
	result := make(map[string]int32)
	for pid, entities := range c.monitoringProcesses {
		for _, entity := range entities {
			for _, host := range entity.ExposeHosts() {
				result[host] = pid
			}
		}
	}
	c.localIPWithPid = result
}

func (c *ConnectionManager) printTotalAddressesWithPid(prefix string) {
	if !log.Enable(logrus.DebugLevel) {
		return
	}
	log.Debugf("%s, print all local address with pid", prefix)
	log.Debugf("----------------------------")
	log.Debugf("total local address with pid: %d", len(c.localIPWithPid))
	for k, v := range c.localIPWithPid {
		log.Debugf("local address: %s, pid: %d", k, v)
	}
	log.Debugf("----------------------------")
}

func (c *ConnectionManager) shouldMonitorProcesses(entities []api.ProcessInterface) []api.ProcessInterface {
	return c.monitorFilter.ShouldIncludeProcesses(entities)
}

func (c *ConnectionManager) checkConnectionIsExist(con *ConnectionInfo) bool {
	// skip the check if the check time is not reach
	if time.Since(con.LastCheckExistTime) < connectionCheckExistTime {
		return true
	}
	con.LastCheckExistTime = time.Now()
	var activateConn ActiveConnection
	if err := c.activeConnectionMap.Lookup(con.ConnectionID, &activateConn); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			con.MarkDeletable = true
			return false
		}
		log.Warnf("cannot found the active connection: %d-%d, err: %v", con.ConnectionID, con.RandomID, err)
		return false
	} else if activateConn.RandomID != 0 && activateConn.RandomID != con.RandomID {
		log.Debugf("detect the connection: %d-%d is already closed(by difference random ID), so remove from the connection manager",
			con.ConnectionID, con.RandomID)
		con.MarkDeletable = true
		return false
	}
	return true
}

func (c *ConnectionManager) RemoveProcess(pid int32, _ []api.ProcessInterface) {
	c.monitoringProcessLock.Lock()
	defer c.monitoringProcessLock.Unlock()
	// delete monitoring process and IP addresses
	delete(c.monitoringProcesses, pid)
	c.updateMonitorStatusForProcess(pid, false)
	c.rebuildLocalIPWithPID()
	c.printTotalAddressesWithPid("remove monitoring process")
	for _, l := range c.processListeners {
		l.OnProcessRemoved(pid)
	}
}

func (c *ConnectionManager) RecheckAllProcesses(processes map[int32][]api.ProcessInterface) {
	shouldMonitoringProcesses := make(map[int32][]api.ProcessInterface)
	for pid, p := range processes {
		monitorProcesses := c.shouldMonitorProcesses(p)
		if len(monitorProcesses) == 0 {
			continue
		}
		shouldMonitoringProcesses[pid] = monitorProcesses
	}
	// checking the monitoring process
	c.monitoringProcesses = shouldMonitoringProcesses
	// for-each the existing monitored map, it should not be monitored, then remote it
	iterate := c.processMonitorMap.Iterate()
	processInBPF := make(map[int32]bool)
	var pid uint32
	var monitor uint32
	for iterate.Next(&pid, &monitor) {
		processInBPF[int32(pid)] = true
	}

	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	// make sure BPF and user space are consistent
	for pid := range processInBPF {
		if _, ok := c.monitoringProcesses[pid]; !ok {
			c.updateMonitorStatusForProcess(pid, false)
			for _, l := range c.processListeners {
				l.OnProcessRemoved(pid)
			}
		}
	}
	for pid := range c.monitoringProcesses {
		if _, ok := processInBPF[pid]; !ok {
			c.updateMonitorStatusForProcess(pid, true)
			for _, l := range c.processListeners {
				l.OnNewProcessMonitoring(pid)
			}
		}
	}

	// update all IP addresses
	c.rebuildLocalIPWithPID()
}

func (c *ConnectionManager) updateMonitorStatusForProcess(pid int32, monitor bool) {
	var err error
	if monitor {
		err = c.processMonitorMap.Update(pid, uint32(1), ebpf.UpdateAny)
	} else {
		err = c.processMonitorMap.Delete(pid)
	}
	if err != nil {
		if !monitor && errors.Is(err, ebpf.ErrKeyNotExist) {
			return
		}
		log.Warnf("failed to update the process %d monitor status to %t: %v", pid, monitor, err)
	} else {
		log.Debugf("update the process %d monitor status to %t", pid, monitor)
	}
}

// OnBuildConnectionLogFinished notify the connection log build finished
func (c *ConnectionManager) OnBuildConnectionLogFinished() {
	// delete all connections which marked as deletable
	// all deletable connection events been sent
	deletableConnections := make(map[string]bool)
	now := time.Now()
	c.connections.IterCb(func(key string, v interface{}) {
		con, ok := v.(*ConnectionInfo)
		if !ok || con == nil {
			return
		}
		// already mark as deletable or process not monitoring
		shouldDelete := con.MarkDeletable || !c.ProcessIsMonitor(con.PID)
		if !shouldDelete {
			shouldDelete = !c.checkConnectionIsExist(con)
		}

		if shouldDelete && con.DeleteAfter == nil {
			deleteAfterTime := now.Add(connectionDeleteDelayTime)
			con.DeleteAfter = &deleteAfterTime
			log.Debugf("detected the connection has mark as deletable, so add a delay timer, connection ID: %d, random ID: %d",
				con.ConnectionID, con.RandomID)
		}

		if shouldDelete && now.After(*con.DeleteAfter) {
			deletableConnections[key] = true
		}
	})

	for key := range deletableConnections {
		log.Debugf("deleting the connection in manager: %s", key)
		c.connections.Remove(key)
	}
}

func (c *ConnectionManager) SkipAllDataAnalyzeAndDowngradeProtocol(conID, ranID uint64) {
	// setting connection protocol is break
	connectionKey := fmt.Sprintf("%d_%d", conID, ranID)
	data, exist := c.connections.Get(connectionKey)
	if exist {
		connection := data.(*ConnectionInfo)
		connection.ProtocolBreak = true
	} else {
		// setting to the protocol break map for encase the runner not starting building logs
		c.connectionProtocolBreakMap.Set(connectionKey, true, time.Minute)
	}

	// setting the connection skip data upload
	var activateConn ActiveConnection
	if err := c.activeConnectionMap.Lookup(conID, &activateConn); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return
		}
		log.Warnf("cannot found the active connection: %d-%d, err: %v", conID, ranID, err)
		return
	}
	if activateConn.RandomID != ranID {
		// make sure the connection is the same
		return
	}

	activateConn.SkipDataUpload = 1
	if err := c.activeConnectionMap.Update(conID, activateConn, ebpf.UpdateAny); err != nil {
		log.Warnf("failed to update the active connection: %d-%d", conID, ranID)
	}
}

func getSocketPairFromConnectEvent(event events.Event) (*events.SocketConnectEvent, *ip.SocketPair) {
	if e, ok := event.(*ConnectEventWithSocket); ok {
		return e.SocketConnectEvent, e.SocketPair
	}
	return nil, nil
}

type ActiveConnection struct {
	RandomID       uint64
	PID            uint32
	SocketFD       uint32
	Role           uint32
	SocketFamily   uint32
	Protocol       uint8
	SSL            uint8
	SkipDataUpload uint8
	// PAD for make sure it have same size when marshal data to the BPF
	PAD0 uint8
	PAD1 uint32
}
