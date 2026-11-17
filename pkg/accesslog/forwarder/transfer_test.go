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
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// legacyOffsetTimestamp and legacyKernelTransferLogBuilder are the constructions before the
// messages were bundled into one allocation, the result must stay the same message
func legacyOffsetTimestamp(t uint64) *v3.EBPFTimestamp {
	return &v3.EBPFTimestamp{
		Timestamp: &v3.EBPFTimestamp_Offset{
			Offset: &v3.EBPFOffsetTimestamp{
				Offset: t,
			},
		},
	}
}

// legacyKernelTransferLogBuilder is the construction before the messages were bundled into one
// allocation, the result must stay the same message
func legacyKernelTransferLogBuilder(event events.Event) *v3.AccessLogKernelLog {
	transferEvent := event.(*events.SocketDataUploadEvent)
	switch enums.SocketFunctionName(transferEvent.FunctionName).GetSocketOperationType() {
	case enums.SocketOperationTypeWrite:
		return &v3.AccessLogKernelLog{
			Operation: &v3.AccessLogKernelLog_Write{
				Write: &v3.AccessLogKernelWriteOperation{
					StartTime: legacyOffsetTimestamp(transferEvent.StartTime()),
					EndTime:   legacyOffsetTimestamp(transferEvent.EndTime()),
					Syscall:   parseWriteSyscall(enums.SocketFunctionName(transferEvent.FunctionName)),
					L4Metrics: &v3.AccessLogKernelWriteL4Metrics{
						TotalTransmitPackageCount: int64(transferEvent.L4PackageCount),
						TotalPackageSize:          int64(transferEvent.L4TotalPackageSize),
					},
				},
			},
		}
	case enums.SocketOperationTypeRead:
		return &v3.AccessLogKernelLog{
			Operation: &v3.AccessLogKernelLog_Read{
				Read: &v3.AccessLogKernelReadOperation{
					StartTime: legacyOffsetTimestamp(transferEvent.StartTime()),
					EndTime:   legacyOffsetTimestamp(transferEvent.EndTime()),
					Syscall:   parseReadSyscall(enums.SocketFunctionName(transferEvent.FunctionName)),
					L2Metrics: &v3.AccessLogKernelReadL2Metrics{
						TotalPackageCount: uint32(transferEvent.L4PackageCount),
						TotalPackageSize:  transferEvent.L4TotalPackageSize,
					},
				},
			},
		}
	}
	return nil
}

func filledUploadEvent(function uint32) *events.SocketDataUploadEvent {
	event := &events.SocketDataUploadEvent{}
	v := reflect.ValueOf(event).Elem()
	for i := 0; i < v.NumField(); i++ {
		switch f := v.Field(i); f.Kind() {
		case reflect.Uint64, reflect.Uint32, reflect.Uint16:
			f.SetUint(uint64(1000 + i*7))
		case reflect.Uint8:
			f.SetUint(uint64(i))
		}
	}
	event.FunctionName = function
	return event
}

func assertSameMessage(t *testing.T, expected, actual proto.Message) {
	t.Helper()
	if !proto.Equal(expected, actual) {
		t.Fatalf("messages differ:\nexpected: %v\nactual:   %v", expected, actual)
	}
	options := proto.MarshalOptions{Deterministic: true}
	expectedBytes, err := options.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	actualBytes, err := options.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if string(expectedBytes) != string(actualBytes) {
		t.Fatalf("encoded messages differ")
	}
}

func TestBuildOffsetTimestampSameAsNestedMessages(t *testing.T) {
	for _, offset := range []uint64{0, 1, 1 << 40, ^uint64(0)} {
		assertSameMessage(t, legacyOffsetTimestamp(offset), BuildOffsetTimestamp(offset))
	}
}

func TestKernelTransferLogBuilderSameAsNestedMessages(t *testing.T) {
	built := 0
	for function := uint32(0); function < 256; function++ {
		event := filledUploadEvent(function)
		expected := legacyKernelTransferLogBuilder(event)
		actual := kernelTransferLogBuilder(event)
		if expected == nil || actual == nil {
			if expected != nil || actual != nil {
				t.Fatalf("function %d: expected %v, actual %v", function, expected, actual)
			}
			continue
		}
		assertSameMessage(t, expected, actual)
		built++
	}
	if built == 0 {
		t.Fatal("no read or write function was built")
	}
}

// TestKernelTransferLogsMergeSameAsNestedMessages: the merge folds the logs in place, which must not
// be visible through the bundled messages of another log
func TestKernelTransferLogsMergeSameAsNestedMessages(t *testing.T) {
	for _, function := range []uint32{uint32(enums.SocketFunctionNameRead), uint32(enums.SocketFunctionNameWrite)} {
		build := func(builder KernelLogBuilder) []*v3.AccessLogKernelLog {
			logs := make([]*v3.AccessLogKernelLog, 0, 3)
			for i := uint64(0); i < 3; i++ {
				event := filledUploadEvent(function)
				event.StartTime0 += i * 10
				event.EndTime0 += i * 10
				logs = append(logs, builder(event))
			}
			return MergeKernelLogs(logs)
		}
		expected, actual := build(legacyKernelTransferLogBuilder), build(kernelTransferLogBuilder)
		if len(expected) != 1 || len(actual) != 1 {
			t.Fatalf("expected one merged log, got %d and %d", len(expected), len(actual))
		}
		assertSameMessage(t, expected[0], actual[0])
		// the end time of the last log was copied into the merged log, not referenced
		end := filledUploadEvent(function).EndTime0 + 20
		if got := kernelLogEndTime(actual[0]); got.GetOffset().GetOffset() != end {
			t.Fatalf("merged end time %v, expected offset %d", got, end)
		}
	}
}

func kernelLogEndTime(log *v3.AccessLogKernelLog) *v3.EBPFTimestamp {
	if read := log.GetRead(); read != nil {
		return read.GetEndTime()
	}
	return log.GetWrite().GetEndTime()
}

// TestMergeEndTimeSameAsLaterTimestamp: copying the later offset gives the message the pointer swap
// to the later timestamp gave, and keeps the end time of dst its own when both are offsets
func TestMergeEndTimeSameAsLaterTimestamp(t *testing.T) {
	timestamps := func() []*v3.EBPFTimestamp {
		return []*v3.EBPFTimestamp{nil, {}, {Timestamp: &v3.EBPFTimestamp_Offset{}},
			legacyOffsetTimestamp(0), legacyOffsetTimestamp(5), legacyOffsetTimestamp(7)}
	}
	for i := range timestamps() {
		for j := range timestamps() {
			dst, src := timestamps()[i], timestamps()[j]
			expected := laterTimestamp(timestamps()[i], timestamps()[j])
			actual := mergeEndTime(dst, src)
			if (expected == nil) != (actual == nil) {
				t.Fatalf("%d/%d: expected %v, actual %v", i, j, expected, actual)
			}
			if actual == nil {
				continue
			}
			assertSameMessage(t, expected, actual)
			if _, dstOK := offsetOf(dst); dstOK && actual != dst {
				t.Fatalf("%d/%d: the offset end time of dst was replaced", i, j)
			}
		}
	}
}

// messageTransferLog is the TransferLog of a kernel transfer log message of this builder: the write L4 and
// the read L2 metrics, by field number
func messageTransferLog(m *v3.AccessLogKernelLog) TransferLog {
	var t TransferLog
	if w := m.GetWrite(); w != nil {
		t.Write, t.Syscall = true, int32(w.Syscall)
		t.StartTime, t.EndTime = w.GetStartTime().GetOffset().GetOffset(), w.GetEndTime().GetOffset().GetOffset()
		if l4 := w.L4Metrics; l4 != nil {
			t.HasMetrics[0] = true
			t.Metrics[0][1], t.Metrics[0][2] = l4.TotalDuration, uint64(l4.TotalTransmitPackageCount)
			t.Metrics[0][3], t.Metrics[0][5] = uint64(l4.TotalRetransmitPackageCount), uint64(l4.TotalPackageSize)
		}
		return t
	}
	r := m.GetRead()
	t.Syscall = int32(r.Syscall)
	t.StartTime, t.EndTime = r.GetStartTime().GetOffset().GetOffset(), r.GetEndTime().GetOffset().GetOffset()
	if l2 := r.L2Metrics; l2 != nil {
		t.HasMetrics[0] = true
		t.Metrics[0][1], t.Metrics[0][2], t.Metrics[0][3] = uint64(l2.Ifindex), uint64(l2.TotalPackageCount), l2.TotalPackageSize
		t.Metrics[0][4], t.Metrics[0][5] = l2.TotalPackageToQueueDuration, l2.TotalRcvPackageFromQueueDuration
	}
	return t
}

// TestTransferLogMergeSameAsMessages: the sender merges the kernel transfer logs of the events as their
// TransferLog values (TryMergeTransferLog); the result is the log merging their messages gives
func TestTransferLogMergeSameAsMessages(t *testing.T) {
	functions := []uint32{uint32(enums.SocketFunctionNameRead), uint32(enums.SocketFunctionNameRecvfrom),
		uint32(enums.SocketFunctionNameWrite), uint32(enums.SocketFunctionNameSendMsg)}
	for i := 0; i < 1000; i++ {
		var messages []*v3.AccessLogKernelLog
		var values []TransferLog
		for j := 0; j < 2+i%5; j++ {
			event := filledUploadEvent(functions[(i+j*(i%3))%len(functions)])
			event.StartTime0 = uint64(59_000_000_000 + (i*7+j*500_000_000)%2_000_000_000)
			event.EndTime0 = event.StartTime0 + uint64((i*13+j*31)%1000)
			event.L4PackageCount = uint32(i * j * 977)
			if (i+j)%7 == 0 {
				event.L4PackageCount = ^uint32(0)
			}
			messages = append(messages, kernelTransferLogBuilder(event))
			v, ok := fillTransferLog(event)
			if !ok {
				t.Fatal("no TransferLog of a read or write")
			}
			values = append(values, v)
		}
		merged := MergeKernelLogs(messages)
		var mergedValues []TransferLog
		for _, v := range values {
			if n := len(mergedValues); n > 0 && TryMergeTransferLog(&mergedValues[n-1], &v) {
				continue
			}
			mergedValues = append(mergedValues, v)
		}
		if len(merged) != len(mergedValues) {
			t.Fatalf("case %d: %d merged messages, %d merged values", i, len(merged), len(mergedValues))
		}
		for k := range merged {
			if want := messageTransferLog(merged[k]); want != mergedValues[k] {
				t.Fatalf("case %d log %d:\nmessage %+v\nvalue   %+v", i, k, want, mergedValues[k])
			}
		}
	}
}

// TestTransferLogOfAnEventWithoutDetail: an event that carries no transfer detail builds no transfer log, instead
// of a panic
func TestTransferLogOfAnEventWithoutDetail(t *testing.T) {
	event := &events.SocketCloseEvent{}
	if l := kernelTransferLogBuilder(event); l != nil {
		t.Fatalf("a log is built: %v", l)
	}
	if _, ok := fillTransferLog(event); ok {
		t.Fatal("a transfer log is filled")
	}
}
