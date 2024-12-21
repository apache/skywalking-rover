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
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/docker/go-units"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"golang.org/x/sys/unix"
)

var connectionLogger = logger.GetLogger("access_log", "collector", "connection")

var connectionCollectInstance = NewConnectionCollector()

type ConnectCollector struct {
	eventQueue *btf.EventQueue
}

func NewConnectionCollector() *ConnectCollector {
	return &ConnectCollector{}
}

func (c *ConnectCollector) Start(_ *module.Manager, ctx *common.AccessLogContext) error {
	perCPUBufferSize, err := units.RAMInBytes(ctx.Config.ConnectionAnalyze.PerCPUBufferSize)
	if err != nil {
		return err
	}
	if int(perCPUBufferSize) < os.Getpagesize() {
		return fmt.Errorf("the cpu buffer must bigger than %dB", os.Getpagesize())
	}
	if ctx.Config.ConnectionAnalyze.ParseParallels < 1 {
		return fmt.Errorf("the parallels cannot be small than 1")
	}
	if ctx.Config.ConnectionAnalyze.AnalyzeParallels < 1 {
		return fmt.Errorf("the parallels cannot be small than 1")
	}
	if ctx.Config.ConnectionAnalyze.QueueSize < 1 {
		return fmt.Errorf("the queue size be small than 1")
	}
	track, err := ip.NewConnTrack()
	if err != nil {
		connectionLogger.Warnf("cannot create the connection tracker, %v", err)
	}
	c.eventQueue = btf.NewEventQueue("connection resolver", ctx.Config.ConnectionAnalyze.AnalyzeParallels,
		ctx.Config.ConnectionAnalyze.QueueSize, func(num int) btf.PartitionContext {
			return newConnectionPartitionContext(ctx, track)
		})
	c.eventQueue.RegisterReceiver(ctx.BPF.SocketConnectionEventQueue, int(perCPUBufferSize),
		ctx.Config.ConnectionAnalyze.ParseParallels, func() interface{} {
			return &events.SocketConnectEvent{}
		}, func(data interface{}) string {
			return fmt.Sprintf("%d", data.(*events.SocketConnectEvent).ConID)
		})
	c.eventQueue.RegisterReceiver(ctx.BPF.SocketCloseEventQueue, int(perCPUBufferSize), ctx.Config.ConnectionAnalyze.ParseParallels, func() interface{} {
		return &events.SocketCloseEvent{}
	}, func(data interface{}) string {
		return fmt.Sprintf("%d", data.(*events.SocketCloseEvent).ConnectionID)
	})
	c.eventQueue.Start(ctx.RuntimeContext, ctx.BPF.Linker)

	ctx.BPF.AddTracePoint("syscalls", "sys_enter_connect", ctx.BPF.TracepointEnterConnect)
	ctx.BPF.AddTracePoint("syscalls", "sys_exit_connect", ctx.BPF.TracepointExitConnect)
	ctx.BPF.AddTracePoint("syscalls", "sys_enter_accept", ctx.BPF.TracepointEnterAccept)
	ctx.BPF.AddTracePoint("syscalls", "sys_exit_accept", ctx.BPF.TracepointExitAccept)
	ctx.BPF.AddTracePoint("syscalls", "sys_enter_accept4", ctx.BPF.TracepointEnterAccept)
	ctx.BPF.AddTracePoint("syscalls", "sys_exit_accept4", ctx.BPF.TracepointExitAccept)
	ctx.BPF.AddTracePoint("syscalls", "sys_enter_close", ctx.BPF.TracepointEnterClose)
	ctx.BPF.AddTracePoint("syscalls", "sys_exit_close", ctx.BPF.TracepointExitClose)

	ctx.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{
		"tcp_connect": ctx.BPF.TcpConnect,
	})
	ctx.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{
		"sock_alloc": ctx.BPF.SockAllocRet,
	})
	ctx.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{
		"ip4_datagram_connect": ctx.BPF.Ip4UdpDatagramConnect,
	})

	_ = ctx.BPF.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{
		"__nf_conntrack_hash_insert": ctx.BPF.NfConntrackHashInsert,
	})
	_ = ctx.BPF.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{
		"nf_confirm": ctx.BPF.NfConfirm,
	})
	_ = ctx.BPF.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{
		"ctnetlink_fill_info": ctx.BPF.NfCtnetlinkFillInfo,
	})
	return nil
}

func (c *ConnectCollector) Stop() {
}

type ConnectionPartitionContext struct {
	context     *common.AccessLogContext
	connTracker *ip.ConnTrack
}

func newConnectionPartitionContext(ctx *common.AccessLogContext, connTracker *ip.ConnTrack) *ConnectionPartitionContext {
	return &ConnectionPartitionContext{
		context:     ctx,
		connTracker: connTracker,
	}
}

func (c *ConnectionPartitionContext) Start(ctx context.Context) {

}

func (c *ConnectionPartitionContext) Consume(data interface{}) {
	switch event := data.(type) {
	case *events.SocketConnectEvent:
		connectionLogger.Debugf("receive connect event, connection ID: %d, randomID: %d, "+
			"pid: %d, fd: %d, role: %s: func: %s, family: %d, success: %d, conntrack exist: %t",
			event.ConID, event.RandomID, event.PID, event.SocketFD, enums.ConnectionRole(event.Role), enums.SocketFunctionName(event.FuncName),
			event.SocketFamily, event.ConnectSuccess, event.ConnTrackUpstreamPort != 0)
		socketPair := c.buildSocketFromConnectEvent(event)
		if socketPair == nil {
			connectionLogger.Debugf("cannot found the socket paire from connect event, connection ID: %d, randomID: %d",
				event.ConID, event.RandomID)
			return
		}
		connectionLogger.Debugf("build socket pair success, connection ID: %d, randomID: %d, role: %s, local: %s:%d, remote: %s:%d",
			event.ConID, event.RandomID, socketPair.Role, socketPair.SrcIP, socketPair.SrcPort, socketPair.DestIP, socketPair.DestPort)
		c.context.ConnectionMgr.OnConnectEvent(event, socketPair)
		forwarder.SendConnectEvent(c.context, event, socketPair)
	case *events.SocketCloseEvent:
		connectionLogger.Debugf("receive close event, connection ID: %d, randomID: %d, pid: %d, fd: %d",
			event.ConnectionID, event.RandomID, event.PID, event.SocketFD)
		wapperedEvent := c.context.ConnectionMgr.OnConnectionClose(event)
		forwarder.SendCloseEvent(c.context, wapperedEvent)
	}
}

func (c *ConnectionPartitionContext) fixSocketFamilyIfNeed(event *events.SocketConnectEvent, result *ip.SocketPair) {
	if result == nil {
		return
	}
	if parseIP := net.ParseIP(result.SrcIP); parseIP != nil {
		var actual uint32
		if parseIP.To4() != nil {
			actual = unix.AF_INET
		} else {
			actual = unix.AF_INET6
		}

		if result.Family != actual {
			connectionLogger.Debugf("fix the socket family from %d to %d, connection ID: %d, randomID: %d",
				result.Family, actual, event.ConID, event.RandomID)
			result.Family = actual
		}
	}
}

func (c *ConnectionPartitionContext) buildSocketFromConnectEvent(event *events.SocketConnectEvent) *ip.SocketPair {
	if event.SocketFamily != unix.AF_INET && event.SocketFamily != unix.AF_INET6 && event.SocketFamily != enums.SocketFamilyUnknown {
		// if not ipv4, ipv6 or unknown, ignore
		return nil
	}
	socketPair := c.buildSocketPair(event)
	if socketPair != nil && socketPair.IsValid() {
		connectionLogger.Debugf("found the connection from the connect event is valid, connection ID: %d, randomID: %d",
			event.ConID, event.RandomID)
		return socketPair
	}
	// if only the local port not success, maybe the upstream port is not open, so it could be continued
	if c.isOnlyLocalPortEmpty(socketPair) {
		event.ConnectSuccess = 0
		connectionLogger.Debugf("the connection from the connect event is only the local port is empty, connection ID: %d, randomID: %d",
			event.ConID, event.RandomID)
		return socketPair
	}

	pair, err := ip.ParseSocket(event.PID, event.SocketFD)
	if err != nil {
		connectionLogger.Debugf("cannot found the socket, pid: %d, socket FD: %d", event.PID, event.SocketFD)
		return nil
	}
	connectionLogger.Debugf("found the connection from the socket, connection ID: %d, randomID: %d",
		event.ConID, event.RandomID)
	pair.Role = enums.ConnectionRole(event.Role)
	c.fixSocketFamilyIfNeed(event, pair)
	c.tryToUpdateSocketFromConntrack(event, pair)
	return pair
}

func (c *ConnectionPartitionContext) isOnlyLocalPortEmpty(socketPair *ip.SocketPair) bool {
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

func (c *ConnectionPartitionContext) buildSocketPair(event *events.SocketConnectEvent) *ip.SocketPair {
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

			if connectionLogger.Enable(logrus.DebugLevel) {
				connectionLogger.Debugf("found the connection from the conntrack, connection ID: %d, randomID: %d, original: %s:%d, conntrack: %s:%d",
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
			if connectionLogger.Enable(logrus.DebugLevel) {
				connectionLogger.Debugf("found the connection from the conntrack, connection ID: %d, randomID: %d, original: %s:%d, conntrack: %s:%d",
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

	c.fixSocketFamilyIfNeed(event, result)
	c.tryToUpdateSocketFromConntrack(event, result)
	return result
}

func (c *ConnectionPartitionContext) tryToUpdateSocketFromConntrack(event *events.SocketConnectEvent, socket *ip.SocketPair) {
	if socket != nil && socket.IsValid() && c.connTracker != nil && !tools.IsLocalHostAddress(socket.DestIP) &&
		event.FuncName != enums.SocketFunctionNameAccept { // accept event don't need to update the remote address
		// if no contract and socket data is valid, then trying to get the remote address from the socket
		// to encase the remote address is not the real remote address
		originalIP := socket.DestIP
		originalPort := socket.DestPort
		if c.connTracker.UpdateRealPeerAddress(socket) {
			connectionLogger.Debugf("update the socket address from conntrack success, "+
				"connection ID: %d, randomID: %d, original remote: %s:%d, new remote: %s:%d",
				event.ConID, event.RandomID, originalIP, originalPort, socket.DestIP, socket.DestPort)
		}
	}
}
