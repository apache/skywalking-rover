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
	"errors"
	"fmt"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/kubernetes"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	"github.com/cilium/ebpf"

	cmap "github.com/orcaman/concurrent-map"

	"k8s.io/apimachinery/pkg/util/cache"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

const localAddressPairCacheTime = time.Hour * 6

type addressProcessType int

const (
	addressProcessTypeUnknown addressProcessType = iota
	addressProcessTypeLocal
	addressProcessTypeKubernetes
)

type ConnectEventWithSocket struct {
	*events.SocketConnectEvent
	SocketPair *ip.SocketPair
}

type CloseEventWithNotify struct {
	*events.SocketCloseEvent
	allProcessorFinished bool
}

type ConnectionProcessFinishCallback func()

type ConnectionProcessor interface {
	OnConnectionClose(event *events.SocketCloseEvent, callback ConnectionProcessFinishCallback)
}

type ProcessListener interface {
	OnNewProcessMonitoring(pid int32)
	OnProcessRemoved(pid int32)
}

type ConnectionManager struct {
	moduleMgr   *module.Manager
	processOP   process.Operator
	connections cmap.ConcurrentMap
	// addressWithPid cache all local ip+port and pid mapping for match the process on the same host
	// such as service mesh(process with envoy)
	addressWithPid *cache.Expiring
	// localIPWithPid cache all local monitoring process bind IP address
	// for checking the remote address is local or not
	localIPWithPid map[string]int32
	// monitoringProcesses management all monitoring processes
	monitoringProcesses map[int32][]api.ProcessInterface
	// monitoring process map in BPF
	processMonitorMap   *ebpf.Map
	activeConnectionMap *ebpf.Map

	processors       []ConnectionProcessor
	processListeners []ProcessListener

	// connection already close but the connection (protocols)log not build finished
	allUnfinishedConnections map[string]*bool
}

func (c *ConnectionManager) RegisterProcessor(processor ConnectionProcessor) {
	c.processors = append(c.processors, processor)
}

func (c *ConnectionManager) AddProcessListener(listener ProcessListener) {
	c.processListeners = append(c.processListeners, listener)
}

type addressInfo struct {
	pid         uint32
	processType addressProcessType
}

type ConnectionInfo struct {
	RPCConnection *v3.AccessLogConnection
	MarkDeletable bool
	PID           uint32
}

func NewConnectionManager(moduleMgr *module.Manager, bpfLoader *bpf.Loader) *ConnectionManager {
	mgr := &ConnectionManager{
		moduleMgr:                moduleMgr,
		processOP:                moduleMgr.FindModule(process.ModuleName).(process.Operator),
		connections:              cmap.New(),
		addressWithPid:           cache.NewExpiring(),
		localIPWithPid:           make(map[string]int32),
		monitoringProcesses:      make(map[int32][]api.ProcessInterface),
		processMonitorMap:        bpfLoader.ProcessMonitorControl,
		activeConnectionMap:      bpfLoader.ActiveConnectionMap,
		allUnfinishedConnections: make(map[string]*bool),
	}
	return mgr
}

func (c *ConnectionManager) Start() {
	c.processOP.AddListener(c)
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
		localAddress = c.buildAddressFromLocalKubernetesProcess(localPID, socket.SrcPort, addressProcessTypeKubernetes)
		// trying to get the remote process if in the same host
		remoteAddressInfo, ok := c.addressWithPid.Get(fmt.Sprintf("%s_%d", socket.DestIP, socket.DestPort))
		if ok && remoteAddressInfo != nil {
			address := remoteAddressInfo.(*addressInfo)
			remoteAddress = c.buildAddressFromLocalKubernetesProcess(address.pid, socket.DestPort, address.processType)
		} else {
			remoteAddress = c.buildAddressFromRemote(socket.DestIP, socket.DestPort)
		}
		connection := c.buildConnection(e, socket, localAddress, remoteAddress)
		c.connections.Set(connectionKey, connection)
		return connection
	}
	return nil
}

func (c *ConnectionManager) connectionPostHandle(connection *ConnectionInfo, event events.Event) {
	if connection == nil {
		return
	}
	switch e := event.(type) {
	case *CloseEventWithNotify:
		if e.allProcessorFinished {
			connection.MarkDeletable = true
		} else {
			// if not all processor finished, then add into the map
			c.allUnfinishedConnections[fmt.Sprintf("%d_%d", event.GetConnectionID(), event.GetRandomID())] = &e.allProcessorFinished
		}
	case *events.SocketDetailEvent:
		if e.SSL == 1 && connection.RPCConnection.TlsMode == v3.AccessLogConnectionTLSMode_Plain {
			connection.RPCConnection.TlsMode = v3.AccessLogConnectionTLSMode_TLS
		}
	}
}

func (c *ConnectionManager) ProcessIsMonitor(pid uint32) bool {
	return len(c.monitoringProcesses[int32(pid)]) > 0
}

func (c *ConnectionManager) buildConnection(event *events.SocketConnectEvent, socket *ip.SocketPair,
	local, remote *v3.ConnectionAddress) *ConnectionInfo {
	var role v32.DetectPoint
	switch socket.Role {
	case enums.ConnectionRoleClient:
		role = v32.DetectPoint_client
	case enums.ConnectionRoleServer:
		role = v32.DetectPoint_server
	}
	connection := &v3.AccessLogConnection{
		Local:   local,
		Remote:  remote,
		Role:    role,
		TlsMode: v3.AccessLogConnectionTLSMode_Plain,
	}
	return &ConnectionInfo{
		RPCConnection: connection,
		PID:           event.PID,
	}
}

func (c *ConnectionManager) buildAddressFromLocalKubernetesProcess(pid uint32, port uint16, _ addressProcessType) *v3.ConnectionAddress {
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
	return nil
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
	result := &CloseEventWithNotify{
		SocketCloseEvent:     event,
		allProcessorFinished: false,
	}
	processCount := len(c.processors)
	for _, l := range c.processors {
		l.OnConnectionClose(event, func() {
			processCount--
			if processCount > 0 {
				return
			}
			result.allProcessorFinished = true
		})
	}
	return result
}

func (c *ConnectionManager) OnConnectEvent(event *events.SocketConnectEvent, pair *ip.SocketPair) {
	// only adding the local ip port when remote is local address
	if tp := c.isLocalTarget(pair); tp != addressProcessTypeUnknown {
		c.addressWithPid.Set(fmt.Sprintf("%s_%d", pair.SrcIP, pair.SrcPort), &addressInfo{
			pid:         event.PID,
			processType: tp,
		}, localAddressPairCacheTime)
	}
}

func (c *ConnectionManager) isLocalTarget(pair *ip.SocketPair) addressProcessType {
	destIP := pair.DestIP
	if tools.IsLocalHostAddress(destIP) {
		return addressProcessTypeLocal
	}
	if _, exist := c.localIPWithPid[destIP]; exist {
		return addressProcessTypeKubernetes
	}
	return addressProcessTypeUnknown
}

func (c *ConnectionManager) AddNewProcess(pid int32, entities []api.ProcessInterface) {
	// adding monitoring process and IP addresses
	c.monitoringProcesses[pid] = entities
	c.updateMonitorStatusForProcess(pid, true)
	for _, entity := range entities {
		for _, host := range entity.ExposeHosts() {
			c.localIPWithPid[host] = pid
		}
	}
	for _, l := range c.processListeners {
		l.OnNewProcessMonitoring(pid)
	}
}

func (c *ConnectionManager) RemoveProcess(pid int32, entities []api.ProcessInterface) {
	// delete monitoring process and IP addresses
	delete(c.monitoringProcesses, pid)
	c.updateMonitorStatusForProcess(pid, false)
	for _, entity := range entities {
		for _, host := range entity.ExposeHosts() {
			delete(c.localIPWithPid, host)
		}
	}
	for _, l := range c.processListeners {
		l.OnProcessRemoved(pid)
	}
}

func (c *ConnectionManager) RecheckAllProcesses(processes map[int32][]api.ProcessInterface) {
	// checking the monitoring process
	c.monitoringProcesses = processes
	// for-each the existing monitored map, it should not be monitored, then remote it
	iterate := c.processMonitorMap.Iterate()
	processInBPF := make(map[int32]bool)
	var pid uint32
	var monitor uint32
	for iterate.Next(&pid, &monitor) {
		processInBPF[int32(pid)] = true
	}

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
	result := make(map[string]int32)
	for _, p := range processes {
		for _, entity := range p {
			for _, host := range entity.ExposeHosts() {
				result[host] = entity.Pid()
			}
		}
	}

	c.localIPWithPid = result
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
	}
}

// OnBuildConnectionLogFinished notify the connection log build finished
func (c *ConnectionManager) OnBuildConnectionLogFinished() {
	// delete all connections which marked as deletable
	// all deletable connection events been sent
	deletableConnections := make([]string, 0)
	c.connections.IterCb(func(key string, v interface{}) {
		con, ok := v.(*ConnectionInfo)
		if !ok || con == nil {
			return
		}
		// already mark as deletable or process not monitoring
		shouldDelete := con.MarkDeletable || len(c.monitoringProcesses[int32(con.PID)]) == 0

		if shouldDelete {
			deletableConnections = append(deletableConnections, key)
		}
	})

	deleteFromUnfinished := make([]string, 0)
	for conKey, processorFinished := range c.allUnfinishedConnections {
		if *processorFinished {
			deletableConnections = append(deletableConnections, conKey)
			deleteFromUnfinished = append(deleteFromUnfinished, conKey)
		}
	}
	for _, key := range deleteFromUnfinished {
		delete(c.allUnfinishedConnections, key)
	}

	for _, key := range deletableConnections {
		c.connections.Remove(key)
	}
}

func (c *ConnectionManager) SkipAllDataAnalyze(conID, ranID uint64) {
	var activateConn ActiveConnection
	if err := c.activeConnectionMap.Lookup(conID, &activateConn); err != nil {
		log.Warnf("cannot found the active connection: %d-%d", conID, ranID)
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
