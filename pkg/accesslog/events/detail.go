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
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

type SocketDetail interface {
	Event
	buffer.SocketDataDetail

	GetStartTime() uint64
	GetEndTime() uint64

	GetL4PackageCount() uint32
	GetL4TotalPackageSize() uint64

	GetFunctionName() enums.SocketFunctionName
	GetProtocol() enums.ConnectionProtocol
	GetSSL() uint8
}

// MergeableDetail is a detail event that can absorb the detail of the next socket call of the same
// operation. It lets the agent report one record per operation of a message instead of one per
// syscall, which is what the volume of a large message is made of: the record is only metadata, but
// a body read with a 64KB buffer costs one of them per read.
//
// The copy is explicit because a socket call can carry the end of one message and the start of the
// next, so the same detail belongs to two protocol logs and must not be mutated in place.
type MergeableDetail interface {
	SocketDetail

	// CanMergeDetail reports whether other describes the same operation: the same syscall on the same
	// interface in the same minute, since the backend buckets a record by its own start time.
	CanMergeDetail(other SocketDetail) bool
	// CopyForMerge returns a copy that may be mutated by MergeDetail
	CopyForMerge() MergeableDetail
	// MergeDetail folds other into this copy: the latest end time and the sum of every counter and
	// duration, so the metrics the backend builds by summing stay correct
	MergeDetail(other SocketDetail)
}

// MergeDetails folds the consecutive details of one message that describe the same operation into a
// single record. The details themselves are not modified.
func MergeDetails(details []SocketDetail) []SocketDetail {
	if len(details) < 2 {
		return details
	}
	result := make([]SocketDetail, 0, len(details))
	ownsLast := false
	for _, detail := range details {
		if len(result) > 0 {
			if last, ok := result[len(result)-1].(MergeableDetail); ok && last.CanMergeDetail(detail) {
				if !ownsLast {
					last = last.CopyForMerge()
					result[len(result)-1] = last
					ownsLast = true
				}
				last.MergeDetail(detail)
				continue
			}
		}
		result = append(result, detail)
		ownsLast = false
	}
	return result
}

type SocketDetailEvent struct {
	ConnectionID uint64
	RandomID     uint64
	DataID0      uint64

	StartTime uint64
	EndTime   uint64

	L4Duration                    uint64
	L3Duration                    uint64
	L3LocalDuration               uint64
	L3OutputDuration              uint64
	L3ResolveMacDuration          uint64
	L3NetFilterDuration           uint64
	L2Duration                    uint64
	L2ReadySendDuration           uint64
	L2SendDuration                uint64
	L2PackageToQueueDuration      uint64
	L3TotalRcvDuration            uint64
	IfIndex                       uint32
	L4PackageRcvFromQueueDuration uint64
	L4TotalPackageSize            uint64
	L2EnterQueueCount             uint32
	L4PackageCount                uint32
	L4RetransmitPackageCount      uint32
	L3ResolveMacCount             uint32
	L3NetFilterCount              uint32
	FunctionName                  enums.SocketFunctionName
	Protocol                      enums.ConnectionProtocol
	SSL                           uint8
}

func (d *SocketDetailEvent) ReadFrom(r btf.Reader) {
	d.ConnectionID = r.ReadUint64()
	d.RandomID = r.ReadUint64()
	d.DataID0 = r.ReadUint64()
	d.StartTime = r.ReadUint64()
	d.EndTime = r.ReadUint64()
	d.L4Duration = uint64(r.ReadUint32())
	d.L3Duration = uint64(r.ReadUint32())
	d.L3LocalDuration = uint64(r.ReadUint32())
	d.L3OutputDuration = uint64(r.ReadUint32())
	d.L3ResolveMacDuration = uint64(r.ReadUint32())
	d.L3NetFilterDuration = uint64(r.ReadUint32())
	d.L2Duration = uint64(r.ReadUint32())
	d.L2ReadySendDuration = uint64(r.ReadUint32())
	d.L2SendDuration = uint64(r.ReadUint32())
	d.L2PackageToQueueDuration = uint64(r.ReadUint32())
	d.L3TotalRcvDuration = uint64(r.ReadUint32())
	d.IfIndex = r.ReadUint32()
	d.L4PackageRcvFromQueueDuration = r.ReadUint64()
	d.L4TotalPackageSize = r.ReadUint64()
	d.L2EnterQueueCount = uint32(r.ReadUint8())
	d.L4PackageCount = uint32(r.ReadUint8())
	d.L4RetransmitPackageCount = uint32(r.ReadUint8())
	d.L3ResolveMacCount = uint32(r.ReadUint8())
	d.L3NetFilterCount = uint32(r.ReadUint8())
	d.FunctionName = enums.SocketFunctionName(r.ReadUint8())
	d.Protocol = enums.ConnectionProtocol(r.ReadUint8())
	d.SSL = r.ReadUint8()
}

func (d *SocketDetailEvent) Time() uint64 {
	return d.StartTime
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

func (d *SocketDetailEvent) GetStartTime() uint64 {
	return d.StartTime
}

func (d *SocketDetailEvent) GetEndTime() uint64 {
	return d.EndTime
}

func (d *SocketDetailEvent) GetL4PackageCount() uint32 {
	return d.L4PackageCount
}

func (d *SocketDetailEvent) GetL4TotalPackageSize() uint64 {
	return d.L4TotalPackageSize
}

func (d *SocketDetailEvent) GetFunctionName() enums.SocketFunctionName {
	return d.FunctionName
}

func (d *SocketDetailEvent) GetProtocol() enums.ConnectionProtocol {
	return d.Protocol
}

func (d *SocketDetailEvent) GetSSL() uint8 {
	return d.SSL
}

func (d *SocketDetailEvent) CanMergeDetail(other SocketDetail) bool {
	next, ok := other.(*SocketDetailEvent)
	return ok && next.FunctionName == d.FunctionName && next.IfIndex == d.IfIndex &&
		host.SameMinute(d.StartTime, next.StartTime)
}

func (d *SocketDetailEvent) CopyForMerge() MergeableDetail {
	copied := *d
	return &copied
}

func (d *SocketDetailEvent) MergeDetail(other SocketDetail) {
	next, ok := other.(*SocketDetailEvent)
	if !ok {
		return
	}
	if next.EndTime > d.EndTime {
		d.EndTime = next.EndTime
	}
	d.L4Duration += next.L4Duration
	d.L3Duration += next.L3Duration
	d.L3LocalDuration += next.L3LocalDuration
	d.L3OutputDuration += next.L3OutputDuration
	d.L3ResolveMacDuration += next.L3ResolveMacDuration
	d.L3NetFilterDuration += next.L3NetFilterDuration
	d.L2Duration += next.L2Duration
	d.L2ReadySendDuration += next.L2ReadySendDuration
	d.L2SendDuration += next.L2SendDuration
	d.L2PackageToQueueDuration += next.L2PackageToQueueDuration
	d.L3TotalRcvDuration += next.L3TotalRcvDuration
	d.L4PackageRcvFromQueueDuration += next.L4PackageRcvFromQueueDuration
	d.L4TotalPackageSize += next.L4TotalPackageSize
	d.L2EnterQueueCount += next.L2EnterQueueCount
	d.L4PackageCount += next.L4PackageCount
	d.L4RetransmitPackageCount += next.L4RetransmitPackageCount
	// the backend reads these durations only when their count is positive: they must stay together
	d.L3ResolveMacCount += next.L3ResolveMacCount
	d.L3NetFilterCount += next.L3NetFilterCount
}
