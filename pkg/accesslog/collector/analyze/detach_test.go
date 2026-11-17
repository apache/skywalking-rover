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

package analyze

import (
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"reflect"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"

	"google.golang.org/protobuf/proto"
)

type detachNoopConsumer struct{}

func (detachNoopConsumer) Consume(chan common.KernelLog, chan common.ProtocolLog) {}

func detachTestEvents(n int) []buffer.SocketDataBuffer {
	result := make([]buffer.SocketDataBuffer, 0, n)
	for i := 0; i < n; i++ {
		e := &events.SocketDataUploadEvent{DataID0: uint64(i + 1), ConnectionID: 1, RandomID: 2, FunctionName: 3,
			L4PackageCount: uint32(i), StartTime0: uint64(i * 10), EndTime0: uint64(i*10 + 5), DataLen: 4}
		e.Buffer = []byte("abcd")
		result = append(result, e)
	}
	// a slice of an event goes the same way
	result = append(result, &buffer.SocketDataEventLimited{SocketDataBuffer: result[0], Size: 2})
	return result
}

func drainKernelLogs(q *common.Queue) []common.KernelLog {
	kernels, _ := h2cDrainQueue(q)
	return kernels
}

// TestSendDetachedNoProtocolEventsLikeDetach: the batched copies queue what a Detach per event queues
func TestSendDetachedNoProtocolEventsLikeDetach(t *testing.T) {
	evs := detachTestEvents(9)
	legacy := &common.AccessLogContext{Queue: common.NewQueue(1000, time.Hour, detachNoopConsumer{})}
	batched := &common.AccessLogContext{Queue: common.NewQueue(1000, time.Hour, detachNoopConsumer{})}
	for _, b := range evs {
		if event := ToNativeEvent(b); event != nil {
			forwarder.SendTransferNoProtocolEvent(legacy, event.Detach())
		}
	}
	sendDetachedNoProtocolEvents(batched, evs)
	want, got := drainKernelLogs(legacy.Queue), drainKernelLogs(batched.Queue)
	if len(want) != len(got) || len(got) != len(evs) {
		t.Fatalf("%d kernel logs, %d expected", len(got), len(want))
	}
	for i := range want {
		w, g := want[i].Event().(*events.SocketDataUploadEvent), got[i].Event().(*events.SocketDataUploadEvent)
		if want[i].Type() != got[i].Type() || !reflect.DeepEqual(w, g) || g.Buffer != nil {
			t.Fatalf("log %d: %+v, expected %+v", i, g, w)
		}
	}
}

// TestNoProtocolEventIsOwnedByTheFlush: an event of a call without protocol goes to the flush queue as an
// owned kernel log, with its buffer released; the events of a protocol break do not
func TestNoProtocolEventIsOwnedByTheFlush(t *testing.T) {
	alc := &common.AccessLogContext{Queue: common.NewQueue(1000, time.Hour, detachNoopConsumer{})}
	p := NewPartitionContext(alc, nil)
	event := events.AcquireUploadEvent()
	event.ConnectionID, event.DataID0, event.Protocol0 = 1, 9, 0
	event.Buffer = buffer.TakeBuffer(100)
	p.Consume(event)
	sendDetachedNoProtocolEvents(alc, detachTestEvents(2))
	logs := drainKernelLogs(alc.Queue)
	if len(logs) != 4 || !logs[0].Owned() || logs[0].Event() != event || event.Buffer != nil {
		t.Fatalf("%d logs, the first owned %t", len(logs), len(logs) > 0 && logs[0].Owned())
	}
	for _, k := range logs[1:] {
		if k.Owned() {
			t.Fatalf("a copy of a protocol break is owned by the flush")
		}
	}
}

// TestOnDropEventQueuesTheSameLogs: a dropped event without a buffer goes to the queue as it is, one with a
// buffer as a copy without it; the kernel logs built of them are what the Detach copies give
func TestOnDropEventQueuesTheSameLogs(t *testing.T) {
	withBuffer := detachTestEvents(3)[:3]
	noBuffer := detachTestEvents(3)[:3]
	for _, b := range noBuffer {
		b.(*events.SocketDataUploadEvent).Buffer = nil
		b.(*events.SocketDataUploadEvent).PayloadSkipped0 = 1
	}
	evs := append(append([]buffer.SocketDataBuffer{}, withBuffer...), noBuffer...)
	evs = append(evs, &buffer.SocketDataEventLimited{SocketDataBuffer: noBuffer[0], Size: 0})
	legacy := &common.AccessLogContext{Queue: common.NewQueue(1000, time.Hour, detachNoopConsumer{})}
	current := &common.AccessLogContext{Queue: common.NewQueue(1000, time.Hour, detachNoopConsumer{})}
	analyze := NewHTTP2Analyze(current).(protocols.HTTP2DropEventListener)
	for _, b := range evs {
		forwarder.SendTransferNoProtocolEvent(legacy, ToNativeEvent(b).Detach())
		analyze.OnDropEvent(nil, b)
	}
	want, got := drainKernelLogs(legacy.Queue), drainKernelLogs(current.Queue)
	if len(want) != len(evs) || len(got) != len(want) {
		t.Fatalf("%d kernel logs, %d expected", len(got), len(want))
	}
	for i := range want {
		w, g := want[i].Event().(*events.SocketDataUploadEvent), got[i].Event().(*events.SocketDataUploadEvent)
		if want[i].Type() != got[i].Type() || want[i].Owned() != got[i].Owned() || !reflect.DeepEqual(w, g) || g.Buffer != nil {
			t.Fatalf("log %d: %+v, expected %+v", i, g, w)
		}
		wl := forwarder.BuildKernelLogFromEvent(want[i].Type(), w)
		gl := forwarder.BuildKernelLogFromEvent(got[i].Type(), g)
		if !proto.Equal(wl, gl) {
			t.Fatalf("log %d: kernel log %v, expected %v", i, gl, wl)
		}
		// an event without a buffer is not copied, one with a buffer is
		if orig := ToNativeEvent(evs[i]); (orig.Buffer == nil) != (g == orig) {
			t.Fatalf("log %d: copied %t with a buffer %t", i, g != orig, orig.Buffer != nil)
		}
	}
}
