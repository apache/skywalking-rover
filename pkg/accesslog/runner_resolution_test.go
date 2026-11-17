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

package accesslog

import (
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/sender"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// pendingLookup finds every event's connection, whose destination is still being resolved
type pendingLookup struct {
	connection *common.ConnectionInfo
	asked      int
}

func (l *pendingLookup) Find(events.Event) *common.ConnectionInfo { return l.connection }
func (l *pendingLookup) ProcessIsMonitor(uint32) bool             { return true }
func (l *pendingLookup) ShouldDeferForResolution(*common.ConnectionInfo) bool {
	l.asked++
	return true
}

// TestResolutionDefer: the kernel and the protocol logs of a connection whose destination is not resolved yet are
// held for the next flush, unless Options.DisableResolutionDefer
func TestResolutionDefer(t *testing.T) {
	event := &events.SocketDataUploadEvent{ConnectionID: 1, RandomID: 2}
	for _, disabled := range []bool{false, true} {
		lookup := &pendingLookup{connection: &common.ConnectionInfo{ConnectionID: 1, RandomID: 2}}
		r := &Runner{connections: lookup, options: Options{DisableResolutionDefer: disabled}}

		connection, delay := r.kernelLogConnection(common.NewKernelLogEvent(common.LogTypeKernelTransfer, event))
		if disabled != (connection != nil) || disabled == delay {
			t.Fatalf("disabled %t: kernel log connection %v, delay %t", disabled, connection, delay)
		}
		protocolLog := common.NewProtocolLogEvent([]events.SocketDetail{event}, &v3.AccessLogProtocolLogs{})
		connection, _, _, delay = r.buildProtocolLog(protocolLog)
		if disabled != (connection != nil) || disabled == delay {
			t.Fatalf("disabled %t: protocol log connection %v, delay %t", disabled, connection, delay)
		}
		if disabled == (lookup.asked > 0) {
			t.Fatalf("disabled %t: the resolver is asked %d times", disabled, lookup.asked)
		}
	}
}

// foundLookup finds every event's connection, resolved
type foundLookup struct{ connection *common.ConnectionInfo }

func (l *foundLookup) Find(events.Event) *common.ConnectionInfo             { return l.connection }
func (l *foundLookup) ProcessIsMonitor(uint32) bool                         { return true }
func (l *foundLookup) ShouldDeferForResolution(*common.ConnectionInfo) bool { return false }

// TestDisableSendMultipleProtocols: with Options.DisableSendMultipleProtocols a protocol log goes without the
// kernel logs of its message, also when none of its details makes one, and OnProtocolLog is told of it; without, a
// protocol log goes with its kernel logs, and not at all when none of its details makes one
func TestDisableSendMultipleProtocols(t *testing.T) {
	write := &events.SocketDataUploadEvent{ConnectionID: 1, RandomID: 2, FunctionName: uint32(enums.SocketFunctionNameWrite),
		StartTime0: 10, EndTime0: 20, DataID0: 1}
	closing := &events.SocketDataUploadEvent{ConnectionID: 1, RandomID: 2, FunctionName: uint32(enums.SocketFunctionNameClose)}
	for _, disabled := range []bool{false, true} {
		for name, detail := range map[string]*events.SocketDataUploadEvent{"write": write, "close": closing} {
			told := 0
			r := &Runner{
				connections: &foundLookup{connection: &common.ConnectionInfo{ConnectionID: 1, RandomID: 2}},
				options: Options{DisableResolutionDefer: true,
					OnProtocolLog: func(*common.ConnectionInfo, common.ProtocolLog) { told++ }},
				disableFlushMultipleProtocols: disabled,
			}
			protocols := make(chan common.ProtocolLog, 1)
			protocols <- common.NewProtocolLogEvent([]events.SocketDetail{detail}, &v3.AccessLogProtocolLogs{})
			batch := (&sender.GRPCSender{}).NewBatch()
			count := r.buildProtocolLogs(protocols, batch)
			expect := 1
			if !disabled && name == "close" {
				expect = 0
			}
			if count != expect || told != expect || batch.LogCount() != expect {
				t.Fatalf("disabled %t, %s: %d logs built, told %d, %d in the batch", disabled, name, count, told, batch.LogCount())
			}
		}
	}
}
