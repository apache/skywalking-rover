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

type SocketCloseEvent struct {
	ConnectionID uint64
	RandomID     uint64

	StartTime uint64
	EndTime   uint64
	PID       uint32
	SocketFD  uint32
	Success   uint32
}

func (c *SocketCloseEvent) ReadFrom(r btf.Reader) {
	c.ConnectionID = r.ReadUint64()
	c.RandomID = r.ReadUint64()
	c.StartTime = r.ReadUint64()
	c.EndTime = r.ReadUint64()
	c.PID = r.ReadUint32()
	c.SocketFD = r.ReadUint32()
	c.Success = r.ReadUint32()
}

func (c *SocketCloseEvent) GetConnectionID() uint64 {
	return c.ConnectionID
}

func (c *SocketCloseEvent) GetRandomID() uint64 {
	return c.RandomID
}

func (c *SocketCloseEvent) Timestamp() time.Time {
	return host.Time(c.StartTime)
}
