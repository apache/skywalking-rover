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

package common

import (
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/shardmap"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

type countingFlusher struct {
	calls int
}

func (c *countingFlusher) ReadyToFlushConnection(*ConnectionInfo, events.Event) { c.calls++ }

func newKeyedTestManager(listeners ...FlusherListener) *ConnectionManager {
	return &ConnectionManager{
		connections:    shardmap.New[ConnectionKey, *ConnectionInfo](),
		flushListeners: listeners,
	}
}

func TestConnectionKey(t *testing.T) {
	if got := NewConnectionKey(12, 34).String(); got != "12_34" {
		t.Fatalf("the key must print as the former string key, got %s", got)
	}
	if NewConnectionKey(1, 2) == NewConnectionKey(2, 1) {
		t.Fatal("the connection ID and random ID must not be interchangeable")
	}
}

func TestFindByConnectionKey(t *testing.T) {
	flusher := &countingFlusher{}
	mgr := newKeyedTestManager(flusher)
	connection := &ConnectionInfo{ConnectionID: 10, RandomID: 20, RPCConnection: &v3.AccessLogConnection{
		TlsMode: v3.AccessLogConnectionTLSMode_Plain, Protocol: v3.AccessLogProtocolType_TCP}}
	mgr.connections.Set(NewConnectionKey(10, 20), connection)

	if found := mgr.Find(&events.SocketDataUploadEvent{ConnectionID: 10, RandomID: 20}); found != connection {
		t.Fatalf("the connection must be found by its IDs, got %v", found)
	}
	if found := mgr.Find(&events.SocketDataUploadEvent{ConnectionID: 10, RandomID: 21}); found != nil {
		t.Fatalf("another random ID is another connection, got %v", found)
	}
	if found := mgr.Find(&events.SocketDataUploadEvent{ConnectionID: 20, RandomID: 10}); found != nil {
		t.Fatalf("swapped IDs are another connection, got %v", found)
	}
	if flusher.calls != 1 {
		t.Fatalf("the flushers are notified for every found connection, calls: %d", flusher.calls)
	}
}

// TestConnectionMessageRebuiltOnlyOnChange: the connection message may be marshaled by the sender
// while the next events are handled, so it is replaced (never modified) when the TLS mode or the
// protocol changes, and kept as it is otherwise
func TestConnectionMessageRebuiltOnlyOnChange(t *testing.T) {
	mgr := newKeyedTestManager(&countingFlusher{})
	local, remote := &v3.ConnectionAddress{}, &v3.ConnectionAddress{}
	attachment := &v3.ConnectionAttachment{}
	connection := &ConnectionInfo{ConnectionID: 1, RandomID: 1, RPCConnection: &v3.AccessLogConnection{
		Local: local, Remote: remote, Attachment: attachment,
		TlsMode: v3.AccessLogConnectionTLSMode_Plain, Protocol: v3.AccessLogProtocolType_TCP}}
	mgr.connections.Set(NewConnectionKey(1, 1), connection)
	detail := func(ssl uint8, protocol enums.ConnectionProtocol) events.Event {
		return &events.SocketDataUploadEvent{ConnectionID: 1, RandomID: 1, SSL: uint32(ssl), Protocol0: protocol}
	}
	step := func(event events.Event, changed bool, tls v3.AccessLogConnectionTLSMode, protocol v3.AccessLogProtocolType) {
		t.Helper()
		before := connection.RPCConnection
		beforeTLS, beforeProtocol := before.TlsMode, before.Protocol
		mgr.Find(event)
		after := connection.RPCConnection
		if (after != before) != changed {
			t.Fatalf("message replaced: %t, expected: %t", after != before, changed)
		}
		if before.TlsMode != beforeTLS || before.Protocol != beforeProtocol {
			t.Fatal("the former message must never be modified")
		}
		if after.TlsMode != tls || after.Protocol != protocol {
			t.Fatalf("expected %s/%s, got %s/%s", tls, protocol, after.TlsMode, after.Protocol)
		}
		if after.Local != local || after.Remote != remote || after.Attachment != attachment {
			t.Fatal("the other fields must be carried over")
		}
	}

	step(detail(0, enums.ConnectionProtocolUnknown), false, v3.AccessLogConnectionTLSMode_Plain, v3.AccessLogProtocolType_TCP)
	step(detail(1, enums.ConnectionProtocolUnknown), true, v3.AccessLogConnectionTLSMode_TLS, v3.AccessLogProtocolType_TCP)
	step(detail(1, enums.ConnectionProtocolUnknown), false, v3.AccessLogConnectionTLSMode_TLS, v3.AccessLogProtocolType_TCP)
	step(detail(0, enums.ConnectionProtocolHTTP), true, v3.AccessLogConnectionTLSMode_TLS, v3.AccessLogProtocolType_HTTP_1)
	step(detail(0, enums.ConnectionProtocolHTTP2), false, v3.AccessLogConnectionTLSMode_TLS, v3.AccessLogProtocolType_HTTP_1)
	connection.ProtocolBreak = true
	step(detail(0, enums.ConnectionProtocolHTTP), true, v3.AccessLogConnectionTLSMode_TLS, v3.AccessLogProtocolType_TCP)
	step(detail(0, enums.ConnectionProtocolHTTP), false, v3.AccessLogConnectionTLSMode_TLS, v3.AccessLogProtocolType_TCP)
}

func TestReplaceAttachment(t *testing.T) {
	original := &v3.AccessLogConnection{Local: &v3.ConnectionAddress{}, Remote: &v3.ConnectionAddress{},
		TlsMode: v3.AccessLogConnectionTLSMode_TLS, Protocol: v3.AccessLogProtocolType_HTTP_2}
	connection := &ConnectionInfo{RPCConnection: original}
	attachment := &v3.ConnectionAttachment{}
	connection.ReplaceAttachment(attachment)
	replaced := connection.RPCConnection
	if replaced == original || original.Attachment != nil {
		t.Fatal("the attachment must be set on a copy, the former message must not be modified")
	}
	if replaced.Attachment != attachment || replaced.Local != original.Local || replaced.Remote != original.Remote ||
		replaced.Role != original.Role || replaced.TlsMode != original.TlsMode || replaced.Protocol != original.Protocol {
		t.Fatalf("the copy must carry every field, got %v", replaced)
	}
}
