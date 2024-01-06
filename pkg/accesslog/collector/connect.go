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

package collector

import (
	"encoding/binary"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"golang.org/x/sys/unix"
)

var connectLogger = logger.GetLogger("access_log", "collector", "connect")

var connectCollectInstance = NewConnectCollector()

type ConnectCollector struct {
	connTracker *ip.ConnTrack
}

func NewConnectCollector() *ConnectCollector {
	track, err := ip.NewConnTrack()
	if err != nil {
		connectLogger.Warnf("cannot create the connection tracker, %v", err)
	}
	return &ConnectCollector{connTracker: track}
}

func (c *ConnectCollector) Start(_ *module.Manager, context *common.AccessLogContext) error {
	context.BPF.AddTracePoint("syscalls", "sys_enter_connect", context.BPF.TracepointEnterConnect)
	context.BPF.AddTracePoint("syscalls", "sys_exit_connect", context.BPF.TracepointExitConnect)
	context.BPF.AddTracePoint("syscalls", "sys_enter_accept", context.BPF.TracepointEnterAccept)
	context.BPF.AddTracePoint("syscalls", "sys_exit_accept", context.BPF.TracepointExitAccept)
	context.BPF.AddTracePoint("syscalls", "sys_enter_accept4", context.BPF.TracepointEnterAccept)
	context.BPF.AddTracePoint("syscalls", "sys_exit_accept4", context.BPF.TracepointExitAccept)

	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{
		"tcp_connect": context.BPF.TcpConnect,
	})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{
		"sock_alloc": context.BPF.SockAllocRet,
	})

	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{
		"__nf_conntrack_hash_insert": context.BPF.NfConntrackHashInsert,
		"nf_confirm":                 context.BPF.NfConfirm,
	})

	context.BPF.ReadEventAsync(context.BPF.SocketConnectionEventQueue, func(data interface{}) {
		event := data.(*events.SocketConnectEvent)
		connectLogger.Debugf("receive connect event, connection ID: %d, randomID: %d, "+
			"pid: %d, fd: %d, role: %s: func: %s, family: %d, success: %d, conntrack exist: %t",
			event.ConID, event.RandomID, event.PID, event.SocketFD, enums.ConnectionRole(event.Role), enums.SocketFunctionName(event.FuncName),
			event.SocketFamily, event.ConnectSuccess, event.ConnTrackUpstreamPort != 0)
		socketPair := c.buildSocketFromConnectEvent(event)
		if socketPair == nil {
			connectLogger.Debugf("cannot found the socket paire from connect event, connection ID: %d, randomID: %d",
				event.ConID, event.RandomID)
			return
		}
		connectLogger.Debugf("build socket pair success, connection ID: %d, randomID: %d, role: %s, local: %s:%d, remote: %s:%d",
			event.ConID, event.RandomID, socketPair.Role, socketPair.SrcIP, socketPair.SrcPort, socketPair.DestIP, socketPair.DestPort)
		context.ConnectionMgr.OnConnectEvent(event, socketPair)
		forwarder.SendConnectEvent(context, event, socketPair)
	}, func() interface{} {
		return &events.SocketConnectEvent{}
	})

	return nil
}

func (c *ConnectCollector) Stop() {
}

func (c *ConnectCollector) buildSocketFromConnectEvent(event *events.SocketConnectEvent) *ip.SocketPair {
	if event.SocketFamily != unix.AF_INET && event.SocketFamily != unix.AF_INET6 && event.SocketFamily != enums.SocketFamilyUnknown {
		// if not ipv4, ipv6 or unknown, ignore
		return nil
	}
	socketPair := c.buildSocketPair(event)
	if socketPair != nil && socketPair.IsValid() {
		return socketPair
	}
	// if only the local port not success, maybe the upstream port is not open, so it could be continued
	if c.isOnlyLocalPortEmpty(socketPair) {
		event.ConnectSuccess = 0
		return socketPair
	}

	pair, err := ip.ParseSocket(event.PID, event.SocketFD)
	if err != nil {
		connectLogger.Warnf("cannot found the socket, pid: %d, socket FD: %d", event.PID, event.SocketFD)
		return nil
	}
	connectLogger.Debugf("found the connection from the socket, connection ID: %d, randomID: %d",
		event.ConID, event.RandomID)
	pair.Role = enums.ConnectionRole(event.Role)
	c.tryToUpdateSocketFromConntrack(event, pair)
	return pair
}

func (c *ConnectCollector) isOnlyLocalPortEmpty(socketPair *ip.SocketPair) bool {
	if socketPair == nil {
		return false
	}
	port := socketPair.SrcPort
	defer func() {
		socketPair.SrcPort = port
	}()
	socketPair.SrcPort = 1
	return socketPair.IsValid()
}

func (c *ConnectCollector) buildSocketPair(event *events.SocketConnectEvent) *ip.SocketPair {
	var result *ip.SocketPair
	haveConnTrack := false
	if event.SocketFamily == unix.AF_INET {
		result = &ip.SocketPair{
			Family:  uint32(event.SocketFamily),
			Role:    enums.ConnectionRole(event.Role),
			SrcIP:   ip.ParseIPV4(event.LocalAddrV4),
			SrcPort: uint16(event.LocalAddrPort),
		}
		if event.ConnTrackUpstreamIPl != 0 && event.ConnTrackUpstreamPort != 0 {
			haveConnTrack = true
			result.DestIP = ip.ParseIPV4(uint32(event.ConnTrackUpstreamIPl))
			result.DestPort = uint16(event.ConnTrackUpstreamPort)

			if connectLogger.Enable(logrus.DebugLevel) {
				connectLogger.Debugf("found the connection from the conntrack, connection ID: %d, randomID: %d, original: %s:%d, conntrack: %s:%d",
					event.ConID, event.RandomID, ip.ParseIPV4(event.RemoteAddrV4), uint16(event.RemoteAddrPort), result.DestIP, result.DestPort)
			}
		} else {
			result.DestIP = ip.ParseIPV4(event.RemoteAddrV4)
			result.DestPort = uint16(event.RemoteAddrPort)
		}
	} else if event.SocketFamily == unix.AF_INET6 {
		result = &ip.SocketPair{
			Family:  uint32(event.SocketFamily),
			Role:    enums.ConnectionRole(event.Role),
			SrcIP:   ip.ParseIPV6(event.LocalAddrV6),
			SrcPort: uint16(event.LocalAddrPort),
		}
		if event.ConnTrackUpstreamIPl != 0 && event.ConnTrackUpstreamPort != 0 {
			haveConnTrack = true
			if event.ConnTrackUpstreamIPh != 0 {
				var ipv6 [16]uint8
				binary.BigEndian.PutUint64(ipv6[0:8], event.ConnTrackUpstreamIPh)
				binary.BigEndian.PutUint64(ipv6[8:16], event.ConnTrackUpstreamIPl)
				result.DestIP = ip.ParseIPV6(ipv6)
			} else {
				result.DestIP = ip.ParseIPV4(uint32(event.ConnTrackUpstreamIPl))
			}
			result.DestPort = uint16(event.ConnTrackUpstreamPort)
			if connectLogger.Enable(logrus.DebugLevel) {
				connectLogger.Debugf("found the connection from the conntrack, connection ID: %d, randomID: %d, original: %s:%d, conntrack: %s:%d",
					event.ConID, event.RandomID, ip.ParseIPV6(event.RemoteAddrV6), uint16(event.RemoteAddrPort), result.DestIP, result.DestPort)
			}
		} else {
			result.DestIP = ip.ParseIPV6(event.RemoteAddrV6)
			result.DestPort = uint16(event.RemoteAddrPort)
		}
	}

	if haveConnTrack {
		return result
	}

	c.tryToUpdateSocketFromConntrack(event, result)
	return result
}

func (c *ConnectCollector) tryToUpdateSocketFromConntrack(event *events.SocketConnectEvent, socket *ip.SocketPair) {
	if socket != nil && socket.IsValid() && c.connTracker != nil && !tools.IsLocalHostAddress(socket.DestIP) {
		// if no contract and socket data is valid, then trying to get the remote address from the socket
		// to encase the remote address is not the real remote address
		originalIP := socket.DestIP
		originalPort := socket.DestPort
		if c.connTracker.UpdateRealPeerAddress(socket) {
			connectLogger.Debugf("update the socket address from conntrack success, "+
				"connection ID: %d, randomID: %d, original remote: %s:%d, new remote: %s:%d",
				event.ConID, event.RandomID, originalIP, originalPort, socket.DestIP, socket.DestPort)
		}
	}
}
