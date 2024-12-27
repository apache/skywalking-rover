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

package events

import (
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

type SocketConnectEvent struct {
	ConID                 uint64
	RandomID              uint64
	StartTime             uint64
	EndTime               uint64
	PID                   uint32
	SocketFD              uint32
	FuncName              uint8
	Role                  uint8
	SocketFamily          uint8
	ConnectSuccess        uint8
	Pad0                  uint32
	RemoteAddrV4          uint32
	RemoteAddrPort        uint32
	RemoteAddrV6          [16]uint8
	LocalAddrV4           uint32
	LocalAddrPort         uint32
	LocalAddrV6           [16]uint8
	ConnTrackUpstreamIPl  uint64
	ConnTrackUpstreamIPh  uint64
	ConnTrackUpstreamPort uint32
}

func (c *SocketConnectEvent) ReadFrom(r btf.Reader) {
	c.ConID = r.ReadUint64()
	c.RandomID = r.ReadUint64()
	c.StartTime = r.ReadUint64()
	c.EndTime = r.ReadUint64()
	c.PID = r.ReadUint32()
	c.SocketFD = r.ReadUint32()
	c.FuncName = r.ReadUint8()
	c.Role = r.ReadUint8()
	c.SocketFamily = r.ReadUint8()
	c.ConnectSuccess = r.ReadUint8()
	c.Pad0 = r.ReadUint32()
	c.RemoteAddrV4 = r.ReadUint32()
	c.RemoteAddrPort = r.ReadUint32()
	r.ReadUint8Array(c.RemoteAddrV6[:], 16)
	c.LocalAddrV4 = r.ReadUint32()
	c.LocalAddrPort = r.ReadUint32()
	r.ReadUint8Array(c.LocalAddrV6[:], 16)
	c.ConnTrackUpstreamIPl = r.ReadUint64()
	c.ConnTrackUpstreamIPh = r.ReadUint64()
	c.ConnTrackUpstreamPort = r.ReadUint32()
}

func (c *SocketConnectEvent) GetConnectionID() uint64 {
	return c.ConID
}

func (c *SocketConnectEvent) GetRandomID() uint64 {
	return c.RandomID
}

func (c *SocketConnectEvent) Timestamp() time.Time {
	return host.Time(c.StartTime)
}
