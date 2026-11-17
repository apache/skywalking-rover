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
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
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
