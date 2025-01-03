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
	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

type ZTunnelSocketMappingEvent struct {
	OriginalSrcIP        uint32
	OriginalDestIP       uint32
	OriginalSrcPort      uint16
	OriginalDestPort     uint16
	LoadBalancedDestIP   uint32
	LoadBalancedDestPort uint16
	Pad0                 uint16
	Pad1                 uint32
}

func (z *ZTunnelSocketMappingEvent) ReadFrom(r btf.Reader) {
	z.OriginalSrcIP = r.ReadUint32()
	z.OriginalDestIP = r.ReadUint32()
	z.OriginalSrcPort = r.ReadUint16()
	z.OriginalDestPort = r.ReadUint16()
	z.LoadBalancedDestIP = r.ReadUint32()
	z.LoadBalancedDestPort = r.ReadUint16()
	z.Pad0 = r.ReadUint16()
	z.Pad1 = r.ReadUint32()
}
