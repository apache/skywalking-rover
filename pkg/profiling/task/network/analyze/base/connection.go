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

import "github.com/apache/skywalking-rover/pkg/process/api"

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

	// metrics
	Metrics *ConnectionMetricsContext

	// Flush the data content to the oap count
	FlushDataCount int
}

func (c *AnalyzerContext) NewConnectionContext(conID, randomID uint64, pid, fd uint32, processes []api.ProcessInterface,
	conClosed bool) *ConnectionContext {
	connection := &ConnectionContext{
		// metadata
		ConnectionID:     conID,
		RandomID:         randomID,
		LocalPid:         pid,
		SocketFD:         fd,
		LocalProcesses:   processes,
		ConnectionClosed: conClosed,

		Metrics: c.NewConnectionMetrics(),
	}
	return connection
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

	// protocol of connection
	Protocol ConnectionProtocol
	// the connect event is already sent
	ConnectEventIsSent uint8
	IsSSL              uint8
}
