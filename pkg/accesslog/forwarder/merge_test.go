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
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

func readLog(start, end uint64, ifindex uint32, syscall v3.AccessLogKernelReadSyscall,
	packages uint32, size, queue uint64) *v3.AccessLogKernelLog {
	return &v3.AccessLogKernelLog{Operation: &v3.AccessLogKernelLog_Read{Read: &v3.AccessLogKernelReadOperation{
		StartTime: BuildOffsetTimestamp(start),
		EndTime:   BuildOffsetTimestamp(end),
		Syscall:   syscall,
		L2Metrics: &v3.AccessLogKernelReadL2Metrics{
			Ifindex: ifindex, TotalPackageCount: packages, TotalPackageSize: size, TotalPackageToQueueDuration: queue,
		},
		L3Metrics: &v3.AccessLogKernelReadL3Metrics{TotalDuration: 10, TotalNetFilterCount: 1, TotalNetFilterDuration: 7},
		L4Metrics: &v3.AccessLogKernelReadL4Metrics{TotalDuration: end - start},
	}}}
}

func writeLog(start, end uint64, syscall v3.AccessLogKernelWriteSyscall, packages, size int64,
	loss []*v3.AccessLogLossPackageMetrics) *v3.AccessLogKernelLog {
	return &v3.AccessLogKernelLog{Operation: &v3.AccessLogKernelLog_Write{Write: &v3.AccessLogKernelWriteOperation{
		StartTime: BuildOffsetTimestamp(start),
		EndTime:   BuildOffsetTimestamp(end),
		Syscall:   syscall,
		L4Metrics: &v3.AccessLogKernelWriteL4Metrics{
			TotalDuration: end - start, TotalTransmitPackageCount: packages, TotalPackageSize: size,
			TotalRetransmitPackageCount: 1, LossPackageMetrics: loss,
		},
		L3Metrics: &v3.AccessLogKernelWriteL3Metrics{TotalDuration: 20, TotalResolveMACCount: 2, TotalResolveMACDuration: 9},
		L2Metrics: &v3.AccessLogKernelWriteL2Metrics{TotalDuration: 30, TotalEnterQueueBufferCount: 3, TotalReadySendDuration: 4},
	}}}
}

// TestMergeReadsOfOneMessage is the case the option exists for: a large body read in several
// syscalls collapses to one record whose counters are the sum of all of them.
func TestMergeReadsOfOneMessage(t *testing.T) {
	logs := []*v3.AccessLogKernelLog{
		readLog(1000, 2000, 3, v3.AccessLogKernelReadSyscall_Read, 10, 20480, 100),
		readLog(3000, 4000, 3, v3.AccessLogKernelReadSyscall_Read, 11, 20480, 110),
		readLog(5000, 6000, 3, v3.AccessLogKernelReadSyscall_Read, 12, 10240, 120),
	}
	merged := MergeKernelLogs(logs)
	if len(merged) != 1 {
		t.Fatalf("expected one record, got %d", len(merged))
	}
	read := merged[0].GetRead()
	if got, _ := offsetOf(read.GetStartTime()); got != 1000 {
		t.Errorf("start time = %d, want the start of the first record 1000", got)
	}
	if got, _ := offsetOf(read.GetEndTime()); got != 6000 {
		t.Errorf("end time = %d, want the end of the last record 6000", got)
	}
	if got := read.GetL2Metrics().GetTotalPackageCount(); got != 33 {
		t.Errorf("package count = %d, want 33", got)
	}
	if got := read.GetL2Metrics().GetTotalPackageSize(); got != 51200 {
		t.Errorf("package size = %d, want 51200", got)
	}
	if got := read.GetL2Metrics().GetTotalPackageToQueueDuration(); got != 330 {
		t.Errorf("queue duration = %d, want 330", got)
	}
	if got := read.GetL3Metrics().GetTotalNetFilterCount(); got != 3 {
		t.Errorf("net filter count = %d, want 3", got)
	}
	// the backend reads the duration only when the count is positive, so they must be summed together
	if got := read.GetL3Metrics().GetTotalNetFilterDuration(); got != 21 {
		t.Errorf("net filter duration = %d, want 21", got)
	}
	if got := read.GetL4Metrics().GetTotalDuration(); got != 3000 {
		t.Errorf("l4 duration = %d, want the sum 3000", got)
	}
}

func TestMergeKeepsGroupsApart(t *testing.T) {
	// the backend places a record by the boot time of the node plus the offset, so an offset only
	// crosses a minute when the wall clock does: take the first boundary after the boot time
	bootTime := host.Time(0)
	minute := uint64(bootTime.Truncate(time.Minute).Add(time.Minute).Sub(bootTime))
	tests := []struct {
		name string
		logs []*v3.AccessLogKernelLog
		want int
	}{
		{"direction change", []*v3.AccessLogKernelLog{
			readLog(1000, 2000, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
			writeLog(3000, 4000, v3.AccessLogKernelWriteSyscall_Write, 1, 10, nil),
			readLog(5000, 6000, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
		}, 3},
		{"syscall change", []*v3.AccessLogKernelLog{
			readLog(1000, 2000, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
			readLog(3000, 4000, 1, v3.AccessLogKernelReadSyscall_RecvMsg, 1, 10, 1),
		}, 2},
		{"interface change", []*v3.AccessLogKernelLog{
			readLog(1000, 2000, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
			readLog(3000, 4000, 2, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
		}, 2},
		{"minute boundary", []*v3.AccessLogKernelLog{
			readLog(minute-1000, minute-500, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
			readLog(minute+1000, minute+2000, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
		}, 2},
		{"same minute", []*v3.AccessLogKernelLog{
			readLog(minute+1000, minute+2000, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
			readLog(minute+3000, minute+4000, 1, v3.AccessLogKernelReadSyscall_Read, 1, 10, 1),
		}, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := len(MergeKernelLogs(test.logs)); got != test.want {
				t.Fatalf("merged into %d records, want %d", got, test.want)
			}
		})
	}
}

func TestMergeWriteSumsAndLossPackages(t *testing.T) {
	logs := []*v3.AccessLogKernelLog{
		writeLog(1000, 2000, v3.AccessLogKernelWriteSyscall_Write, 5, 20480,
			[]*v3.AccessLogLossPackageMetrics{{Location: "queue", Count: 2}}),
		writeLog(3000, 5000, v3.AccessLogKernelWriteSyscall_Write, 6, 10240,
			[]*v3.AccessLogLossPackageMetrics{{Location: "queue", Count: 3}, {Location: "device", Count: 1}}),
	}
	merged := MergeKernelLogs(logs)
	if len(merged) != 1 {
		t.Fatalf("expected one record, got %d", len(merged))
	}
	write := merged[0].GetWrite()
	if got := write.GetL4Metrics().GetTotalTransmitPackageCount(); got != 11 {
		t.Errorf("transmit package count = %d, want 11", got)
	}
	if got := write.GetL4Metrics().GetTotalPackageSize(); got != 30720 {
		t.Errorf("package size = %d, want 30720", got)
	}
	if got := write.GetL4Metrics().GetTotalRetransmitPackageCount(); got != 2 {
		t.Errorf("retransmit package count = %d, want 2", got)
	}
	if got := write.GetL3Metrics().GetTotalResolveMACCount(); got != 4 {
		t.Errorf("resolve mac count = %d, want 4", got)
	}
	if got := write.GetL2Metrics().GetTotalEnterQueueBufferCount(); got != 6 {
		t.Errorf("enter queue count = %d, want 6", got)
	}
	loss := write.GetL4Metrics().GetLossPackageMetrics()
	if len(loss) != 2 {
		t.Fatalf("expected two loss locations, got %d", len(loss))
	}
	for _, metric := range loss {
		want := int32(1)
		if metric.GetLocation() == "queue" {
			want = 5
		}
		if metric.GetCount() != want {
			t.Errorf("loss count of %s = %d, want %d", metric.GetLocation(), metric.GetCount(), want)
		}
	}
}

// TestMergeKeepsTotalsOfTheMessage guards the property the backend sum metrics rely on
func TestMergeKeepsTotalsOfTheMessage(t *testing.T) {
	logs := make([]*v3.AccessLogKernelLog, 0, 16)
	var wantPackages uint32
	var wantSize uint64
	for i := uint64(0); i < 16; i++ {
		logs = append(logs, readLog(1000*i, 1000*i+500, 7, v3.AccessLogKernelReadSyscall_Readv, uint32(i), 20480, i))
		wantPackages += uint32(i)
		wantSize += 20480
	}
	var gotPackages uint32
	var gotSize uint64
	for _, merged := range MergeKernelLogs(logs) {
		gotPackages += merged.GetRead().GetL2Metrics().GetTotalPackageCount()
		gotSize += merged.GetRead().GetL2Metrics().GetTotalPackageSize()
	}
	if gotPackages != wantPackages || gotSize != wantSize {
		t.Fatalf("after merging: packages %d size %d, want %d and %d", gotPackages, gotSize, wantPackages, wantSize)
	}
}

func TestMergeKeepsOtherOperations(t *testing.T) {
	connect := &v3.AccessLogKernelLog{Operation: &v3.AccessLogKernelLog_Connect{
		Connect: &v3.AccessLogKernelConnectOperation{StartTime: BuildOffsetTimestamp(1000)}}}
	closed := &v3.AccessLogKernelLog{Operation: &v3.AccessLogKernelLog_Close{
		Close: &v3.AccessLogKernelCloseOperation{StartTime: BuildOffsetTimestamp(2000)}}}
	merged := MergeKernelLogs([]*v3.AccessLogKernelLog{connect, connect, closed})
	if len(merged) != 3 {
		t.Fatalf("connect and close must never merge, got %d records", len(merged))
	}
	if len(MergeKernelLogs(nil)) != 0 {
		t.Fatal("merging nothing must return nothing")
	}
}
