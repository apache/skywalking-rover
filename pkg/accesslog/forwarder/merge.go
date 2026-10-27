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

package forwarder

import (
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// Merging kernel transfer logs
//
// One kernel log describes one socket syscall. A message carried by many syscalls therefore costs
// one log per syscall, and that is what makes the access log of large messages expensive: a 256KB
// body read with a 64KB buffer is a handful of syscalls per hop, while a 1KB body is one. The
// records themselves are only metadata, but at a few thousand messages per second they dominate
// both the bytes on the wire and the memory the agent holds until they are sent.
//
// Merging folds the consecutive logs of one message that describe the same operation into a single
// record: the start time of the first, the end time of the last, and the sum of every counter and
// duration. It trades the per syscall timing for the volume, which is why it is opt-in.
//
// What the backend does with the result (the receiver expands every record into service, instance
// and relation metrics):
//   - metrics that are a true sum (package counts, package sizes upstream, netfilter and MAC
//     resolution counts and durations) are unchanged;
//   - metrics that count records (the read and write cpm family) are divided by the merge factor;
//   - metrics that average per record (the *_time family) are inflated by it, because the numerator
//     is summed while the denominator counts records.
//
// Two rules keep the first group correct and are not negotiable:
//   - records are never merged across a minute, because the backend takes the minute bucket of a
//     record from its own start time, so a merge across the boundary would move the counters of the
//     later syscalls into the earlier minute;
//   - records are never merged across a network interface, and a counter is never summed without the
//     count that guards it on the backend side.

// MergeKernelLogs folds consecutive kernel logs of the same operation into one record. The input
// slice is reused for the result, so the caller must not keep the original.
func MergeKernelLogs(logs []*v3.AccessLogKernelLog) []*v3.AccessLogKernelLog {
	if len(logs) < 2 {
		return logs
	}
	result := logs[:1]
	for _, current := range logs[1:] {
		if TryMergeKernelLog(result[len(result)-1], current) {
			continue
		}
		result = append(result, current)
	}
	return result
}

// TryMergeKernelLog folds src into dst and reports whether it did. Only the read and write
// operations of the same syscall, interface and minute can be folded; connect, accept and close
// describe one point in time each and are always kept.
func TryMergeKernelLog(dst, src *v3.AccessLogKernelLog) bool {
	if dst == nil || src == nil {
		return false
	}
	switch dstOperation := dst.Operation.(type) {
	case *v3.AccessLogKernelLog_Read:
		srcOperation, ok := src.Operation.(*v3.AccessLogKernelLog_Read)
		if !ok {
			return false
		}
		return mergeReadOperation(dstOperation.Read, srcOperation.Read)
	case *v3.AccessLogKernelLog_Write:
		srcOperation, ok := src.Operation.(*v3.AccessLogKernelLog_Write)
		if !ok {
			return false
		}
		return mergeWriteOperation(dstOperation.Write, srcOperation.Write)
	}
	return false
}

func mergeReadOperation(dst, src *v3.AccessLogKernelReadOperation) bool {
	if dst == nil || src == nil || dst.Syscall != src.Syscall ||
		!sameMinute(dst.GetStartTime(), src.GetStartTime()) ||
		dst.GetL2Metrics().GetIfindex() != src.GetL2Metrics().GetIfindex() {
		return false
	}
	dst.EndTime = laterTimestamp(dst.GetEndTime(), src.GetEndTime())
	if src.L2Metrics != nil {
		if dst.L2Metrics == nil {
			dst.L2Metrics = src.L2Metrics
		} else {
			dst.L2Metrics.TotalPackageCount += src.L2Metrics.TotalPackageCount
			dst.L2Metrics.TotalPackageSize += src.L2Metrics.TotalPackageSize
			dst.L2Metrics.TotalPackageToQueueDuration += src.L2Metrics.TotalPackageToQueueDuration
			dst.L2Metrics.TotalRcvPackageFromQueueDuration += src.L2Metrics.TotalRcvPackageFromQueueDuration
		}
	}
	if src.L3Metrics != nil {
		if dst.L3Metrics == nil {
			dst.L3Metrics = src.L3Metrics
		} else {
			dst.L3Metrics.TotalDuration += src.L3Metrics.TotalDuration
			dst.L3Metrics.TotalRecvDuration += src.L3Metrics.TotalRecvDuration
			dst.L3Metrics.TotalLocalDuration += src.L3Metrics.TotalLocalDuration
			// the backend only reads the duration when the count is positive: they must stay together
			dst.L3Metrics.TotalNetFilterCount += src.L3Metrics.TotalNetFilterCount
			dst.L3Metrics.TotalNetFilterDuration += src.L3Metrics.TotalNetFilterDuration
		}
	}
	if src.L4Metrics != nil {
		if dst.L4Metrics == nil {
			dst.L4Metrics = src.L4Metrics
		} else {
			dst.L4Metrics.TotalDuration += src.L4Metrics.TotalDuration
		}
	}
	return true
}

func mergeWriteOperation(dst, src *v3.AccessLogKernelWriteOperation) bool {
	if dst == nil || src == nil || dst.Syscall != src.Syscall ||
		!sameMinute(dst.GetStartTime(), src.GetStartTime()) ||
		dst.GetL2Metrics().GetIfindex() != src.GetL2Metrics().GetIfindex() {
		return false
	}
	dst.EndTime = laterTimestamp(dst.GetEndTime(), src.GetEndTime())
	if src.L4Metrics != nil {
		if dst.L4Metrics == nil {
			dst.L4Metrics = src.L4Metrics
		} else {
			dst.L4Metrics.TotalDuration += src.L4Metrics.TotalDuration
			dst.L4Metrics.TotalTransmitPackageCount += src.L4Metrics.TotalTransmitPackageCount
			dst.L4Metrics.TotalRetransmitPackageCount += src.L4Metrics.TotalRetransmitPackageCount
			dst.L4Metrics.TotalPackageSize += src.L4Metrics.TotalPackageSize
			dst.L4Metrics.LossPackageMetrics = mergeLossPackages(dst.L4Metrics.LossPackageMetrics, src.L4Metrics.LossPackageMetrics)
		}
	}
	if src.L3Metrics != nil {
		if dst.L3Metrics == nil {
			dst.L3Metrics = src.L3Metrics
		} else {
			dst.L3Metrics.TotalDuration += src.L3Metrics.TotalDuration
			dst.L3Metrics.TotalLocalDuration += src.L3Metrics.TotalLocalDuration
			dst.L3Metrics.TotalOutputDuration += src.L3Metrics.TotalOutputDuration
			dst.L3Metrics.TotalResolveMACCount += src.L3Metrics.TotalResolveMACCount
			dst.L3Metrics.TotalResolveMACDuration += src.L3Metrics.TotalResolveMACDuration
			dst.L3Metrics.TotalNetFilterCount += src.L3Metrics.TotalNetFilterCount
			dst.L3Metrics.TotalNetFilterDuration += src.L3Metrics.TotalNetFilterDuration
		}
	}
	if src.L2Metrics != nil {
		if dst.L2Metrics == nil {
			dst.L2Metrics = src.L2Metrics
		} else {
			dst.L2Metrics.TotalDuration += src.L2Metrics.TotalDuration
			dst.L2Metrics.TotalEnterQueueBufferCount += src.L2Metrics.TotalEnterQueueBufferCount
			dst.L2Metrics.TotalReadySendDuration += src.L2Metrics.TotalReadySendDuration
			dst.L2Metrics.TotalNetDeviceSendDuration += src.L2Metrics.TotalNetDeviceSendDuration
		}
	}
	return true
}

// mergeLossPackages keeps one entry per location with the counts added up
func mergeLossPackages(dst, src []*v3.AccessLogLossPackageMetrics) []*v3.AccessLogLossPackageMetrics {
	for _, current := range src {
		merged := false
		for _, exist := range dst {
			if exist.GetLocation() == current.GetLocation() {
				exist.Count += current.GetCount()
				merged = true
				break
			}
		}
		if !merged {
			dst = append(dst, current)
		}
	}
	return dst
}

// sameMinute reports whether both timestamps fall into the same minute of the backend, which derives
// the bucket of a record from the boot time of the node plus the offset the agent reports. A
// timestamp that is not an offset (or is missing) cannot be placed, so it never merges.
func sameMinute(first, second *v3.EBPFTimestamp) bool {
	firstOffset, ok := offsetOf(first)
	if !ok {
		return false
	}
	secondOffset, ok := offsetOf(second)
	if !ok {
		return false
	}
	return host.Time(firstOffset).Truncate(time.Minute).Equal(host.Time(secondOffset).Truncate(time.Minute))
}

func laterTimestamp(first, second *v3.EBPFTimestamp) *v3.EBPFTimestamp {
	firstOffset, firstOK := offsetOf(first)
	secondOffset, secondOK := offsetOf(second)
	if !secondOK {
		return first
	}
	if !firstOK || secondOffset > firstOffset {
		return second
	}
	return first
}

func offsetOf(timestamp *v3.EBPFTimestamp) (uint64, bool) {
	offset, ok := timestamp.GetTimestamp().(*v3.EBPFTimestamp_Offset)
	if !ok || offset.Offset == nil {
		return 0, false
	}
	return offset.Offset.GetOffset(), true
}
