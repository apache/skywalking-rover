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
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

	"github.com/shirou/gopsutil/process"
)

func rawIPRemoteConnection() *common.ConnectionInfo {
	return &common.ConnectionInfo{
		Socket: &ip.SocketPair{Role: enums.ConnectionRoleClient},
		RPCConnection: &v3.AccessLogConnection{
			Remote: &v3.ConnectionAddress{
				Address: &v3.ConnectionAddress_Ip{
					Ip: &v3.IPAddress{Host: "10.96.0.10", Port: 9080},
				},
			},
		},
	}
}

func TestIsResolutionPending(t *testing.T) {
	// a collector with no ztunnel process being collected never reports pending
	t.Run("no ztunnel process is not pending", func(t *testing.T) {
		z := NewZTunnelCollector(time.Minute)
		if z.IsResolutionPending(rawIPRemoteConnection()) {
			t.Fatal("should not be pending when no ztunnel process is collecting")
		}
	})

	// arm a collecting process for the remaining cases
	armed := func() *ZTunnelCollector {
		z := NewZTunnelCollector(time.Minute)
		z.collectingProcess.Store(&process.Process{Pid: 4242})
		return z
	}

	t.Run("raw IP client leg without attachment is pending", func(t *testing.T) {
		if !armed().IsResolutionPending(rawIPRemoteConnection()) {
			t.Fatal("an unresolved raw-IP client leg should be pending while ztunnel is active")
		}
	})

	t.Run("nil connection is not pending", func(t *testing.T) {
		if armed().IsResolutionPending(nil) {
			t.Fatal("nil connection should not be pending")
		}
	})

	t.Run("already attached is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.RPCConnection.Attachment = &v3.ConnectionAttachment{}
		if armed().IsResolutionPending(conn) {
			t.Fatal("an already-attached connection should not be pending")
		}
	})

	t.Run("server leg is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.Socket.Role = enums.ConnectionRoleServer
		if armed().IsResolutionPending(conn) {
			t.Fatal("the server(inbound) leg does not go through the outbound lb mapping")
		}
	})

	t.Run("conntrack-resolved is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.Socket.ConnTrackResolved = true
		if armed().IsResolutionPending(conn) {
			t.Fatal("a conntrack-resolved connection needs no ztunnel wait")
		}
	})

	t.Run("kubernetes-resolved remote is not pending", func(t *testing.T) {
		conn := rawIPRemoteConnection()
		conn.RPCConnection.Remote = &v3.ConnectionAddress{
			Address: &v3.ConnectionAddress_Kubernetes{
				Kubernetes: &v3.KubernetesProcessAddress{ServiceName: "reviews"},
			},
		}
		if armed().IsResolutionPending(conn) {
			t.Fatal("a remote already resolved to a local pod is not a raw service IP")
		}
	})
}
