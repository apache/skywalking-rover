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
	"strings"
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
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	"github.com/cilium/ebpf"

	cmap "github.com/orcaman/concurrent-map"

	"k8s.io/apimachinery/pkg/util/cache"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// only using to match the remote IP address
const localAddressPairCacheTime = time.Second * 15

type addressProcessType int

const (
	addressProcessTypeUnknown addressProcessType = iota
	addressProcessTypeLocal
	addressProcessTypeKubernetes
)

const (
	strLocal  = "local"
	strRemote = "remote"
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
	addressWithPid   *cache.Expiring
	localPortWithPid *cache.Expiring // in some case, we can only get the 127.0.0.1 from server side, so we only cache the port for this
	// localIPWithPid cache all local monitoring process bind IP address
	// for checking the remote address is local or not
	localIPWithPid map[string]int32
	// monitoringProcesses management all monitoring processes
	monitoringProcesses   map[int32][]api.ProcessInterface
	monitoringProcessLock sync.RWMutex
	// monitoring process map in BPF
	processMonitorMap   *ebpf.Map
	activeConnectionMap *ebpf.Map

	excludeNamespaces map[string]bool
	excludeClusters   map[string]bool

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
	pid uint32
}

type ConnectionInfo struct {
	ConnectionID  uint64
	RandomID      uint64
	RPCConnection *v3.AccessLogConnection
	MarkDeletable bool
	PID           uint32
}

func NewConnectionManager(config *Config, moduleMgr *module.Manager, bpfLoader *bpf.Loader) *ConnectionManager {
	excludeNamespaces := make(map[string]bool)
	for _, ns := range strings.Split(config.ExcludeNamespaces, ",") {
		excludeNamespaces[ns] = true
	}
	excludeClusters := make(map[string]bool)
	for _, cluster := range strings.Split(config.ExcludeClusters, ",") {
		excludeClusters[cluster] = true
	}
	mgr := &ConnectionManager{
		moduleMgr:                moduleMgr,
		processOP:                moduleMgr.FindModule(process.ModuleName).(process.Operator),
		connections:              cmap.New(),
		addressWithPid:           cache.NewExpiring(),
		localPortWithPid:         cache.NewExpiring(),
		localIPWithPid:           make(map[string]int32),
		monitoringProcesses:      make(map[int32][]api.ProcessInterface),
		processMonitorMap:        bpfLoader.ProcessMonitorControl,
		activeConnectionMap:      bpfLoader.ActiveConnectionMap,
		allUnfinishedConnections: make(map[string]*bool),
		excludeNamespaces:        excludeNamespaces,
		excludeClusters:          excludeClusters,
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

func (c *ConnectionManager) GetExcludeNamespaces() []string {
	namespaces := make([]string, len(c.excludeNamespaces))
	for namespace := range c.excludeNamespaces {
		namespaces = append(namespaces, namespace)
	}
	return namespaces
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
		localAddress = c.buildAddressFromLocalKubernetesProcess(localPID, socket.SrcPort)
		remoteAddress = c.buildRemoteAddress(e, socket)
		if localAddress == nil || remoteAddress == nil {
			return nil
		}
		connection := c.buildConnection(e, socket, localAddress, remoteAddress)
		c.connections.Set(connectionKey, connection)
		if log.Enable(logrus.DebugLevel) {
			log.Debugf("building flushing connection, connection ID: %d, randomID: %d, role: %s, local: %s:%d, remote: %s:%d, "+
				"local address: %s, remote address: %s",
				e.GetConnectionID(), e.GetRandomID(), socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort,
				localAddress.String(), remoteAddress.String())
		}
		return connection
	}
	return nil
}

func (c *ConnectionManager) buildRemoteAddress(e *events.SocketConnectEvent, socket *ip.SocketPair) *v3.ConnectionAddress {
	tp := c.isLocalTarget(socket)
	if tp == addressProcessTypeUnknown {
		log.Debugf("building the remote address to unknown, connection: %d-%d, role: %s, local: %s:%d, remote: %s:%d",
			e.GetConnectionID(), e.GetRandomID(), socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort)
		return c.buildAddressFromRemote(socket.DestIP, socket.DestPort)
	}

	var addrInfo *addressInfo
	var fromType string
	switch socket.Role {
	case enums.ConnectionRoleClient:
		addrInfo = c.getAddressPid(socket.SrcIP, socket.SrcPort, false)
		fromType = strLocal
	case enums.ConnectionRoleServer:
		addrInfo = c.getAddressPid(socket.DestIP, socket.DestPort, true)
		fromType = strRemote
	}

	if addrInfo != nil {
		log.Debugf("building the remote address from %s process, pid: %d, connection: %d-%d, role: %s, local: %s:%d, remote: %s:%d",
			fromType, addrInfo.pid, e.GetConnectionID(), e.GetRandomID(), socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort)
		return c.buildAddressFromLocalKubernetesProcess(addrInfo.pid, socket.DestPort)
	} else if tp == addressProcessTypeKubernetes {
		if p := c.localIPWithPid[socket.DestIP]; p != 0 {
			log.Debugf("building the remote address from kubernetes process, connection: %d-%d, role: %s, pid: %d, local: %s:%d, remote: %s:%d",
				e.GetConnectionID(), e.GetRandomID(), socket.Role, p, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort)
			return c.buildAddressFromLocalKubernetesProcess(uint32(p), socket.DestPort)
		}
	}

	log.Debugf("cannot found the peer pid for the connection: %d-%d, remote type: %v, role: %s, local: %s:%d, remote: %s:%d",
		e.GetConnectionID(), e.GetRandomID(), tp, socket.Role, socket.SrcIP, socket.SrcPort, socket.DestIP, socket.DestPort)
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
		if e.Protocol != enums.ConnectionProtocolUnknown && connection.RPCConnection.Protocol == v3.AccessLogProtocolType_TCP {
			switch e.Protocol {
			case enums.ConnectionProtocolHTTP:
				connection.RPCConnection.Protocol = v3.AccessLogProtocolType_HTTP_1
			case enums.ConnectionProtocolHTTP2:
				connection.RPCConnection.Protocol = v3.AccessLogProtocolType_HTTP_2
			}
		}
	}
}

func (c *ConnectionManager) ProcessIsMonitor(pid uint32) bool {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
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
		Local:    local,
		Remote:   remote,
		Role:     role,
		TlsMode:  v3.AccessLogConnectionTLSMode_Plain,
		Protocol: v3.AccessLogProtocolType_TCP,
	}
	return &ConnectionInfo{
		ConnectionID:  event.ConID,
		RandomID:      event.RandomID,
		RPCConnection: connection,
		PID:           event.PID,
	}
}

func (c *ConnectionManager) buildAddressFromLocalKubernetesProcess(pid uint32, port uint16) *v3.ConnectionAddress {
	c.monitoringProcessLock.RLock()
	defer c.monitoringProcessLock.RUnlock()
	for _, pi := range c.monitoringProcesses[int32(pid)] {
		if pi.DetectType() == api.Kubernetes {
			entity := pi.Entity()
			if cluster, _, found := strings.Cut(entity.ServiceName, "::"); found && c.excludeClusters[cluster] {
				continue
			}
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

func (c *ConnectionManager) savingTheAddress(host string, port uint16, localPid bool, pid uint32) {
	localAddrInfo := &addressInfo{
		pid: pid,
	}
	c.addressWithPid.Set(fmt.Sprintf("%s_%d_%t", host, port, localPid), localAddrInfo, localAddressPairCacheTime)
	localStr := strRemote
	if localPid {
		localStr = strLocal
	}
	log.Debugf("saving the %s address with pid cache, address: %s:%d, pid: %d", localStr, host, port, pid)
}

func (c *ConnectionManager) getAddressPid(host string, port uint16, localPid bool) *addressInfo {
	addrInfo, ok := c.addressWithPid.Get(fmt.Sprintf("%s_%d_%t", host, port, localPid))
	if ok && addrInfo != nil {
		return addrInfo.(*addressInfo)
	}
	return nil
}

func (c *ConnectionManager) OnConnectEvent(event *events.SocketConnectEvent, pair *ip.SocketPair) {
	// only adding the local ip port when remote is local address
	switch c.isLocalTarget(pair) {
	case addressProcessTypeUnknown:
		log.Debugf("the target address is not local, so no needs to save the cache. "+
			"address: %s:%d, pid: %d", pair.DestIP, pair.DestPort, event.PID)
	case addressProcessTypeLocal:
		switch pair.Role {
		case enums.ConnectionRoleClient:
			// if current is client, so the local port should be unique
			c.savingTheAddress(pair.SrcIP, pair.SrcPort, true, event.PID)
		case enums.ConnectionRoleServer:
			// if current is server, so the remote port should be unique
			c.savingTheAddress(pair.DestIP, pair.DestPort, false, event.PID)
		case enums.ConnectionRoleUnknown:
			log.Debugf("the target address local but unknown role, so no needs to save the cache. socket: [%s], pid: %d",
				pair, event.PID)
		}
	case addressProcessTypeKubernetes:
		switch pair.Role {
		case enums.ConnectionRoleClient:
			// if current is client, so the local port should be unique
			c.savingTheAddress(pair.SrcIP, pair.SrcPort, true, event.PID)
		case enums.ConnectionRoleServer:
			// if current is server, so the remote port should be unique
			c.savingTheAddress(pair.DestIP, pair.DestPort, false, event.PID)
		case enums.ConnectionRoleUnknown:
			log.Debugf("the target address kubernetes but unknown role, so no needs to save the cache. socket: [%s], pid: %d",
				pair, event.PID)
		}
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
	// filtering the namespace
	if c.shouldExcludeTheProcess(entities) {
		c.RemoveProcess(pid, entities)
		return
	}

	c.monitoringProcessLock.Lock()
	defer c.monitoringProcessLock.Unlock()

	// adding monitoring process and IP addresses
	c.monitoringProcesses[pid] = entities
	c.updateMonitorStatusForProcess(pid, true)
	for _, entity := range entities {
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

func (c *ConnectionManager) shouldExcludeTheProcess(entities []api.ProcessInterface) bool {
	// when the process contains multiple entity, and contains the cluster not exclude, then should not exclude the process
	containsNotExcludeCluster := false
	for _, entity := range entities {
		if entity.DetectType() == api.Kubernetes { // for now, we only have the kubernetes detected process
			namespace := entity.DetectProcess().(*kubernetes.Process).PodContainer().Pod.Namespace
			if c.excludeNamespaces[namespace] {
				return true
			}
			if cluster, _, found := strings.Cut(entity.Entity().ServiceName, "::"); found {
				if !c.excludeClusters[cluster] {
					containsNotExcludeCluster = true
				}
			} else {
				containsNotExcludeCluster = true
				break
			}
		}
	}
	return !containsNotExcludeCluster
}

func (c *ConnectionManager) RemoveProcess(pid int32, entities []api.ProcessInterface) {
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
		if c.shouldExcludeTheProcess(p) {
			continue
		}
		shouldMonitoringProcesses[pid] = p
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
	deletableConnections := make(map[string]bool, 0)
	c.connections.IterCb(func(key string, v interface{}) {
		con, ok := v.(*ConnectionInfo)
		if !ok || con == nil {
			return
		}
		// already mark as deletable or process not monitoring
		shouldDelete := con.MarkDeletable || !c.ProcessIsMonitor(con.PID)

		if shouldDelete {
			deletableConnections[key] = true
		}
	})

	deleteFromUnfinished := make([]string, 0)
	for conKey, processorFinished := range c.allUnfinishedConnections {
		if *processorFinished {
			deletableConnections[conKey] = true
			deleteFromUnfinished = append(deleteFromUnfinished, conKey)
		} else {
			// if the processor not finished, then ignore it from deletable connections
			delete(deletableConnections, conKey)
		}
	}
	for _, key := range deleteFromUnfinished {
		delete(c.allUnfinishedConnections, key)
	}

	for key := range deletableConnections {
		log.Debugf("deleting the connection in manager: %s", key)
		c.connections.Remove(key)
	}
}

func (c *ConnectionManager) SkipAllDataAnalyze(conID, ranID uint64) {
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
