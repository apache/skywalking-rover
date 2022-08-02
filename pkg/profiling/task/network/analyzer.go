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
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/tools"
)

const (
	layerMeshDP  = "MESH_DP"
	layerMeshApp = "MESH"
	processEnvoy = "envoy"
)

type TrafficAnalyzer struct {
	existingProcesses map[int32][]api.ProcessInterface
	// used to find local same with remote address
	// the connect request(local:a -> remote:b) same with accept address(remote:a -> local:b)
	// key: localIP:port+RemoteIP+port
	// value: localPid
	localWithPeerCache map[LocalWithPeerAddress]*PidWithRole

	// used to find only have the remote address connection
	// the connect request(local:unknown -> remote:b), server side accept(local:b)
	// key: RemoteIP:port
	// value: remotePid list
	peerAddressCache map[PeerAddress][]uint32

	// used to find the envoy client, service connect to the service(outbound), but envoy accept the request through iptables
	// the connect request(local:a -> remote:b(upstream service)), envoy side accept(local:c -> remote:a)
	// key: LocalIP:port(service ip:port)
	// value: remotePid(envoy)
	envoyAcceptClientAddressCache map[PeerAddress]*AddressWithPid

	// process data
	// key: pid
	// value: process entities
	processData map[uint32][]api.ProcessInterface

	// all local addresses(host only)
	// key: ip
	// value: [entity layer]process
	localAddresses map[string]map[string]api.ProcessInterface
}

func NewTrafficAnalyzer(processes map[int32][]api.ProcessInterface) *TrafficAnalyzer {
	return &TrafficAnalyzer{
		existingProcesses:             processes,
		localWithPeerCache:            make(map[LocalWithPeerAddress]*PidWithRole),
		peerAddressCache:              make(map[PeerAddress][]uint32),
		envoyAcceptClientAddressCache: make(map[PeerAddress]*AddressWithPid),
		processData:                   make(map[uint32][]api.ProcessInterface),
		localAddresses:                make(map[string]map[string]api.ProcessInterface),
	}
}

func (t *TrafficAnalyzer) CombineConnectionToTraffics(connections []*ConnectionContext) []*ProcessTraffic {
	// build cache first
	t.buildCache(connections)

	// build traffics
	pidMatchedTraffic := make(map[PidMatchTrafficKey]*ProcessTraffic)
	pidToRemoteTraffic := make(map[PidToRemoteTrafficKey]*ProcessTraffic)
	for _, con := range connections {
		// find pid first
		remotePid := t.findRemotePid(con)
		if remotePid != 0 {
			key := PidMatchTrafficKey{
				LocalPid:  con.LocalPid,
				RemotePid: remotePid,
				Role:      con.Role,
			}
			traffic := pidMatchedTraffic[key]
			pidMatchedTraffic[key] = t.generateOrCombineTraffic(traffic, con, remotePid)

			traffic = pidMatchedTraffic[key]
			log.Debugf("save pid match traffic[%d_%d_%d], %s:%d(%d)->%s:%d(%d)",
				con.LocalPid, remotePid, con.Role, traffic.LocalIP, traffic.LocalPort, traffic.LocalPid,
				traffic.RemoteIP, traffic.RemotePort, traffic.RemotePid)
			continue
		}

		// if the remote IP and Port is empty, then ignore it
		if !t.ipNotEmpty(con.RemoteIP, con.RemotePort) {
			continue
		}

		t.tryingToGenerateTheRoleWhenRemotePidCannotFound(con)
		var pidToRemoteKey PidToRemoteTrafficKey
		pidToRemoteKey.LocalPid = con.LocalPid
		pidToRemoteKey.RemoteIP = con.RemoteIP
		// if connection role is not server side, then add the remote port
		if con.Role != ConnectionRoleServer {
			// uniformly identified as a client
			pidToRemoteKey.Role = ConnectionRoleClient
			pidToRemoteKey.RemotePort = con.RemotePort
		} else {
			pidToRemoteKey.Role = ConnectionRoleServer
		}
		traffic := pidToRemoteTraffic[pidToRemoteKey]
		traffic = t.generateOrCombineTraffic(traffic, con, 0)
		pidToRemoteTraffic[pidToRemoteKey] = traffic

		log.Debugf("save remote address traffic[%d_%d_%s_%d], %s:%d(%d)->%s:%d(%d)",
			con.LocalPid, con.Role, con.RemoteIP, con.RemotePort, traffic.LocalIP, traffic.LocalPort,
			traffic.LocalPid, traffic.RemoteIP, traffic.RemotePort, traffic.RemotePid)
	}

	// combine all result
	result := make([]*ProcessTraffic, 0)
	for _, v := range pidMatchedTraffic {
		if v.ContainsAnyTraffic() {
			result = append(result, v)
		}
	}
	for _, v := range pidToRemoteTraffic {
		if v.ContainsAnyTraffic() {
			result = append(result, v)
		}
	}

	return result
}

func (t *TrafficAnalyzer) tryingToGenerateTheRoleWhenRemotePidCannotFound(con *ConnectionContext) {
	if con.Role != ConnectionRoleUnknown {
		return
	}
	// local process address or process could not found, then could analyze the role
	if con.LocalPort == 0 || len(con.LocalProcesses) == 0 {
		return
	}
	var role ConnectionRole
	// if port is expose, and remote address is not local pid
	// then the role of connection is server side usually
	if con.LocalProcesses[0].PortIsExpose(int(con.LocalPort)) {
		role = ConnectionRoleServer
	} else {
		role = ConnectionRoleClient
	}

	con.Role = role
	log.Debugf("found current connection role is unknown, analyzed role is %s through local port. %s:%d(%d)->%s:%d",
		role.String(), con.LocalIP, con.LocalPort, con.LocalPid, con.RemoteIP, con.RemotePort)
}

func (t *TrafficAnalyzer) generateOrCombineTraffic(traffic *ProcessTraffic, con *ConnectionContext, remotePid uint32) *ProcessTraffic {
	if traffic == nil {
		traffic = &ProcessTraffic{
			analyzer: t,

			LocalPid:       con.LocalPid,
			LocalProcesses: con.LocalProcesses,
			LocalIP:        con.LocalIP,
			LocalPort:      con.LocalPort,

			ConnectionRole: con.Role,

			WriteCounter:            NewSocketDataCounter(),
			ReadCounter:             NewSocketDataCounter(),
			WriteRTTCounter:         NewSocketDataCounter(),
			ConnectCounter:          NewSocketDataCounter(),
			CloseCounter:            NewSocketDataCounter(),
			RetransmitCounter:       NewSocketDataCounter(),
			DropCounter:             NewSocketDataCounter(),
			WriteRTTHistogram:       NewSocketDataHistogram(),
			WriteExeTimeHistogram:   NewSocketDataHistogram(),
			ReadExeTimeHistogram:    NewSocketDataHistogram(),
			ConnectExeTimeHistogram: NewSocketDataHistogram(),
			CloseExeTimeHistogram:   NewSocketDataHistogram(),
		}
	}
	if len(traffic.LocalProcesses) == 0 && len(con.LocalProcesses) > 0 {
		traffic.LocalProcesses = con.LocalProcesses
	}
	if traffic.ConnectionRole == ConnectionRoleUnknown && con.Role != ConnectionRoleUnknown {
		traffic.ConnectionRole = con.Role
	}
	if traffic.Protocol == ConnectionProtocolUnknown && con.Protocol != ConnectionProtocolUnknown {
		traffic.Protocol = con.Protocol
	}
	if !traffic.IsSSL && con.IsSSL {
		traffic.IsSSL = true
	}

	if remotePid != 0 {
		traffic.RemotePid = remotePid
		traffic.RemoteProcesses = t.processData[remotePid]
	}
	traffic.RemoteIP = con.RemoteIP
	traffic.RemotePort = con.RemotePort

	traffic.WriteCounter.Increase(con.WriteCounter.CalculateIncrease())
	traffic.ReadCounter.Increase(con.ReadCounter.CalculateIncrease())
	traffic.WriteRTTCounter.Increase(con.WriteRTTCounter.CalculateIncrease())
	traffic.RetransmitCounter.Increase(con.RetransmitCounter)
	traffic.DropCounter.Increase(con.DropCounter)
	traffic.WriteRTTHistogram.Increase(con.WriteRTTHistogram.CalculateIncrease())
	traffic.WriteExeTimeHistogram.Increase(con.WriteExeTimeHistogram.CalculateIncrease())
	traffic.ReadExeTimeHistogram.Increase(con.ReadExeTimeHistogram.CalculateIncrease())

	if con.FlushDataCount == 0 && con.ConnectExecuteTime > 0 {
		traffic.ConnectCounter.IncreaseByValue(0, 1, con.ConnectExecuteTime)
		traffic.ConnectExeTimeHistogram.IncreaseByValue(con.ConnectExecuteTime)
	}
	if con.FlushDataCount == 0 && con.CloseExecuteTime > 0 {
		traffic.CloseCounter.IncreaseByValue(0, 1, con.CloseExecuteTime)
		traffic.CloseExeTimeHistogram.IncreaseByValue(con.CloseExecuteTime)
	}
	con.FlushDataCount++
	return traffic
}

func (t *TrafficAnalyzer) IsLocalAddressInCache(ip string) bool {
	return len(t.localAddresses[ip]) > 0
}

func (t *TrafficAnalyzer) buildCache(connections []*ConnectionContext) {
	for _, con := range connections {
		if t.ipNotEmpty(con.LocalIP, con.LocalPort) && t.ipNotEmpty(con.RemoteIP, con.RemotePort) {
			t.localWithPeerCache[LocalWithPeerAddress{
				LocalIP:    con.LocalIP,
				LocalPort:  con.LocalPort,
				RemoteIP:   con.RemoteIP,
				RemotePort: con.RemotePort,
			}] = &PidWithRole{
				Pid:  con.LocalPid,
				Role: con.Role,
			}
		}
		if t.ipNotEmpty(con.LocalIP, con.LocalPort) {
			peerAddress := PeerAddress{
				RemoteIP:   con.LocalIP,
				RemotePort: con.LocalPort,
			}
			t.peerAddressCache[peerAddress] = append(t.peerAddressCache[peerAddress], con.LocalPid)

			if len(con.LocalProcesses) > 0 {
				localAddressProcesses := t.localAddresses[con.LocalIP]
				if len(localAddressProcesses) == 0 {
					localAddressProcesses = make(map[string]api.ProcessInterface)
					t.localAddresses[con.LocalIP] = localAddressProcesses
				}
				for _, p := range con.LocalProcesses {
					localAddressProcesses[p.Entity().Layer] = p
				}
			}
		} else if t.ipNotEmpty(con.RemoteIP, con.RemotePort) {
			// if server side is envoy
			if con.Role == ConnectionRoleServer && len(con.LocalProcesses) > 0 {
				name, err := con.LocalProcesses[0].ExeName()
				if err != nil {
					log.Warnf("get process exe name failure, pid: %d, error: %v", con.LocalPid, err)
				}
				if name == processEnvoy {
					t.envoyAcceptClientAddressCache[PeerAddress{
						RemoteIP:   con.RemoteIP,
						RemotePort: con.RemotePort,
					}] = &AddressWithPid{
						RemoteIP:   con.LocalIP,
						RemotePort: con.LocalPort,
						Pid:        con.LocalPid,
					}
				}
			}
		}

		if len(t.processData[con.LocalPid]) == 0 {
			t.processData[con.LocalPid] = con.LocalProcesses
		}
		t.processExportPortAnalyze(con)
	}
}

func (t *TrafficAnalyzer) processExportPortAnalyze(con *ConnectionContext) {
	// if the process exists, role of connection is server mode and local port is exists1
	// add the detected port into the processes
	if len(con.LocalProcesses) > 0 && con.Role == ConnectionRoleServer && con.LocalPort > 0 {
		for _, p := range con.LocalProcesses {
			p.DetectNewExposePort(int(con.LocalPort))
		}
	}
}

func (t *TrafficAnalyzer) findRemotePid(con *ConnectionContext) uint32 {
	// full address
	if pid := t.findRemotePidWhenContainsFullAddress(con); pid > 0 {
		return pid
	}

	// only remote address
	if pid := t.findRemotePidWhenContainsRemoteAddress(con); pid > 0 {
		return pid
	}

	// mesh environment
	if pid := t.findRemotePidWhenMeshEnvironment(con); pid > 0 {
		return pid
	}
	return 0
}

func (t *TrafficAnalyzer) findRemotePidWhenContainsFullAddress(con *ConnectionContext) uint32 {
	// match to localWithPeerCache
	if t.ipNotEmpty(con.LocalIP, con.LocalPort) && t.ipNotEmpty(con.RemoteIP, con.RemotePort) {
		data := t.localWithPeerCache[LocalWithPeerAddress{
			LocalIP:    con.RemoteIP,
			LocalPort:  con.RemotePort,
			RemoteIP:   con.LocalIP,
			RemotePort: con.LocalPort,
		}]
		if data != nil {
			log.Debugf("found in peer cache: %s:%d->%s:%d, pid: %d", con.RemoteIP, con.RemotePort, con.LocalIP, con.LocalPort, data.Pid)
			// if current connection is unknown, but peer network has role, then just use the revert role
			// such as: cur:(a->b) unknown, remote:(b->a) client, then current connection must have the server role
			if con.Role == ConnectionRoleUnknown && data.Role != ConnectionRoleUnknown {
				con.Role = data.Role.Revert()
			}
			return data.Pid
		}
		log.Debugf("not found in peer cache: %s:%d->%s:%d", con.RemoteIP, con.RemotePort, con.LocalIP, con.LocalPort)

		// if current role is client side, and localIP:port match to envoy
		if con.Role == ConnectionRoleClient {
			// need update the remote address to real address
			addr := t.envoyAcceptClientAddressCache[PeerAddress{
				RemoteIP:   con.LocalIP,
				RemotePort: con.LocalPort,
			}]
			if addr != nil {
				if t.ipNotEmpty(addr.RemoteIP, addr.RemotePort) {
					con.RemoteIP = addr.RemoteIP
					con.RemotePort = addr.RemotePort
				}
				log.Debugf("found envoy connection: %s:%d->%s:%d", con.LocalIP, con.LocalPort, con.RemoteIP, con.RemotePort)
				return addr.Pid
			}
			log.Debugf("not envoy connection: %s:%d->%s:%d", con.LocalIP, con.LocalPort, con.RemoteIP, con.RemotePort)
		}
	}

	return 0
}

func (t *TrafficAnalyzer) findRemotePidWhenContainsRemoteAddress(con *ConnectionContext) uint32 {
	if !t.ipNotEmpty(con.RemoteIP, con.RemotePort) {
		return 0
	}
	// use non-strict verification, don't verify the client role, ensure that pid is available to be greatest extent
	// because the information of role maybe missing when not trigger the connect/accept
	pidCaches := t.peerAddressCache[PeerAddress{
		RemoteIP:   con.RemoteIP,
		RemotePort: con.RemotePort,
	}]
	if len(pidCaches) > 0 {
		result := pidCaches[0]
		// when the remote peer address contains multiple pid
		// the process usually not self
		for _, pid := range pidCaches {
			if pid != con.LocalPid {
				result = pid
			}
		}
		log.Debugf("found remote address by peer address cache: %s:%d -> %d", con.RemoteIP, con.RemotePort, result)
		return result
	}
	return 0
}

func (t *TrafficAnalyzer) findRemotePidWhenMeshEnvironment(con *ConnectionContext) uint32 {
	// special handle for mesh application, when it could not match the process through address
	if len(con.LocalProcesses) == 0 || !t.ipNotEmpty(con.RemoteIP, con.RemotePort) {
		return 0
	}
	for _, localProcess := range con.LocalProcesses {
		// match when the MESH data plane not found the MESH application
		if localProcess.Entity().Layer == layerMeshDP {
			addresses := t.localAddresses[con.RemoteIP]
			if len(addresses) == 0 {
				continue
			}
			if p := addresses[layerMeshApp]; p != nil {
				log.Debugf("found in the mesh application, remote ip: %s", con.RemoteIP)
				return uint32(p.Pid())
			}
			continue
		}
		// if current is mesh application, and remote address is not local and dns, them it's must be sent to the MESH_DP
		if localProcess.Entity().Layer == layerMeshApp && con.RemotePort != 53 &&
			len(t.localAddresses[con.RemoteIP]) == 0 && !tools.IsLocalHostAddress(con.RemoteIP) {
			if envoyPid := t.findSameInstanceMeshDP(localProcess.Entity()); envoyPid != 0 {
				log.Debugf("found in the mesh data plane, remote ip: %s", con.RemoteIP)
				return envoyPid
			}
		}
	}
	return 0
}

func (t *TrafficAnalyzer) findSameInstanceMeshDP(entity *api.ProcessEntity) uint32 {
	for _, psList := range t.existingProcesses {
		for _, p := range psList {
			if p.Entity().Layer == layerMeshDP && p.Entity().ServiceName == entity.ServiceName && p.Entity().InstanceName == entity.InstanceName {
				name, err := p.ExeName()
				if err != nil {
					log.Warnf("query the process execute file name failure: %d, error: %v", p.Pid(), err)
					continue
				}
				if name == processEnvoy {
					return uint32(p.Pid())
				}
			}
		}
	}
	return 0
}

type LocalWithPeerAddress struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
}

type PeerAddress struct {
	RemoteIP   string
	RemotePort uint16
}

type AddressWithPid struct {
	RemoteIP   string
	RemotePort uint16
	Pid        uint32
}

type PidMatchTrafficKey struct {
	LocalPid  uint32
	RemotePid uint32
	Role      ConnectionRole
}

type PidToRemoteTrafficKey struct {
	LocalPid   uint32
	Role       ConnectionRole
	RemoteIP   string
	RemotePort uint16
}

type PidWithRole struct {
	Pid  uint32
	Role ConnectionRole
}

func (t *TrafficAnalyzer) ipNotEmpty(ip string, port uint16) bool {
	return ip != "" && port != 0
}
