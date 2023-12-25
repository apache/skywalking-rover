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

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

type SocketDetailEvent struct {
	ConnectionID uint64
	RandomID     uint64
	DataID0      uint64

	StartTime uint64
	EndTime   uint64

	L4Duration                    uint32
	L3Duration                    uint32
	L3LocalDuration               uint32
	L3OutputDuration              uint32
	L3ResolveMacDuration          uint32
	L3NetFilterDuration           uint32
	L2Duration                    uint32
	L2ReadySendDuration           uint32
	L2SendDuration                uint32
	L2PackageToQueueDuration      uint32
	L3TotalRcvDuration            uint32
	IfIndex                       uint32
	L4PackageRcvFromQueueDuration uint64
	L4TotalPackageSize            uint64
	L2EnterQueueCount             uint8
	L4PackageCount                uint8
	L4RetransmitPackageCount      uint8
	L3ResolveMacCount             uint8
	L3NetFilterCount              uint8
	FunctionName                  enums.SocketFunctionName
	Protocol                      enums.ConnectionProtocol
	SSL                           uint8
}

func (d *SocketDetailEvent) GetConnectionID() uint64 {
	return d.ConnectionID
}

func (d *SocketDetailEvent) GetRandomID() uint64 {
	return d.RandomID
}

func (d *SocketDetailEvent) Timestamp() time.Time {
	return host.Time(d.StartTime)
}

func (d *SocketDetailEvent) DataID() uint64 {
	return d.DataID0
}
