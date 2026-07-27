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

// ZTunnelConnectionResultWindow must equal ZTUNNEL_CONNECTION_RESULT_WINDOW in
// bpf/accesslog/ambient/ztunnel.h: it is the size of the raw ConnectionResult copy the
// identity uprobe emits, and a mismatch would silently misalign every field that follows.
const ZTunnelConnectionResultWindow = 512

// ZTunnelConnectionResultEvent is a raw snapshot of ztunnel's ConnectionResult, taken at the
// uprobe on ConnectionResult::record_internal - the function that writes the ztunnel access log.
// The probe copies the bytes without interpreting them because the field offsets differ per
// ztunnel build and may have to be discovered at runtime; Data is decoded in user space against
// the offsets resolved for this particular binary.
type ZTunnelConnectionResultEvent struct {
	PID    uint32
	Window uint32
	Data   [ZTunnelConnectionResultWindow]uint8
}

func (z *ZTunnelConnectionResultEvent) ReadFrom(r btf.Reader) {
	z.PID = r.ReadUint32()
	z.Window = r.ReadUint32()
	r.ReadUint8Array(z.Data[:], len(z.Data))
}

// ZTunnelConnectionResultCompactEvent is the lean form of ZTunnelConnectionResultEvent the identity
// uprobe emits once user space has resolved this ztunnel's field offsets and written them to the BPF
// offsets-config map: the peer addresses and direction are decoded in the probe, and the identity
// strings - which live behind pointers in refcounted heap buffers the probe cannot copy - are
// shipped as raw pointer values for user space to follow via /proc/<pid>/mem, exactly as it does
// from the full window. ~88 bytes instead of ~520, so a busy ztunnel loses far fewer samples.
//
// The field order and padding MUST match struct ztunnel_connection_result_compact_t in
// bpf/accesslog/ambient/ztunnel.h - ReadFrom decodes the bytes positionally.
type ZTunnelConnectionResultCompactEvent struct {
	PID            uint32
	SrcIP          uint32
	DstIP          uint32
	SrcPort        uint16
	DstPort        uint16
	Reporter       uint8
	SecurityPolicy uint8
	HasDirection   uint8
	Pad0           uint8
	Pad1           uint32

	SrcPrincipalNsPtr uint64
	SrcPrincipalSaPtr uint64
	DstPrincipalNsPtr uint64
	DstPrincipalSaPtr uint64
	SrcNamespacePtr   uint64
	DstNamespacePtr   uint64
	SrcClusterPtr     uint64
	DstClusterPtr     uint64
}

func (z *ZTunnelConnectionResultCompactEvent) ReadFrom(r btf.Reader) {
	z.PID = r.ReadUint32()
	z.SrcIP = r.ReadUint32()
	z.DstIP = r.ReadUint32()
	z.SrcPort = r.ReadUint16()
	z.DstPort = r.ReadUint16()
	z.Reporter = r.ReadUint8()
	z.SecurityPolicy = r.ReadUint8()
	z.HasDirection = r.ReadUint8()
	z.Pad0 = r.ReadUint8()
	z.Pad1 = r.ReadUint32()
	z.SrcPrincipalNsPtr = r.ReadUint64()
	z.SrcPrincipalSaPtr = r.ReadUint64()
	z.DstPrincipalNsPtr = r.ReadUint64()
	z.DstPrincipalSaPtr = r.ReadUint64()
	z.SrcNamespacePtr = r.ReadUint64()
	z.DstNamespacePtr = r.ReadUint64()
	z.SrcClusterPtr = r.ReadUint64()
	z.DstClusterPtr = r.ReadUint64()
}

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
