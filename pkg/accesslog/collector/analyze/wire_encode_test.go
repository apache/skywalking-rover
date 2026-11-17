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
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/accesslog/sender"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"google.golang.org/protobuf/proto"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// The sender encodes the logs with its own protobuf encoder (skywalking-rover/pkg/accesslog/sender/encode.go).
// These tests take the logs the analyzers of the agent build, with the kernel log builders of the agent, and
// require the encoder to write the bytes of proto.Marshal for the messages that carry them.

// http1AnalyzeExchanges runs the agent's HTTP/1 analyzer over request and response calls, one exchange after the other
func http1AnalyzeExchanges(t *testing.T, exchanges [][2]string) *h2cResult {
	t.Helper()
	ctx := &common.AccessLogContext{
		Queue:         common.NewQueue(100000, time.Hour, h2cNoopConsumer{}),
		ConnectionMgr: h2cTestConnectionManager(),
		Config:        testAccessLogConfig(),
	}
	proto := protocols.NewHTTP1Analyzer(ctx, NewHTTP1Analyze(nil, ctx))
	partition := protocols.NewPartitionContext(ctx, 0, []protocols.Protocol{proto})
	conn := partition.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP, 1)
	base := bpfNow()
	var dataID uint64
	for _, exchange := range exchanges {
		for i, data := range exchange {
			direction := enums.SocketDataDirectionIngress
			if i == 1 {
				direction = enums.SocketDataDirectionEgress
			}
			dataID++
			event := h2cDataEvent(h2cCall{direction: direction, data: []byte(data), at: int(dataID)}, dataID, dataID-1, base)
			event.Protocol0 = enums.ConnectionProtocolHTTP
			conn.AppendData(event)
		}
		if err := proto.Analyze(conn, &protocols.AnalyzeHelper{}); err != nil {
			t.Fatalf("analyze: %v", err)
		}
	}
	result := &h2cResult{}
	kernels, protocolLogs := h2cDrainQueue(ctx.Queue)
	for _, p := range protocolLogs {
		result.protocolLogs = append(result.protocolLogs, p.ProtocolLog())
		logs := make([]*v3.AccessLogKernelLog, 0)
		for _, detail := range p.RelateKernelLogs() {
			logs = append(logs, forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, detail))
		}
		result.protocolKernels = append(result.protocolKernels, logs)
		result.protocolDetails = append(result.protocolDetails, p.RelateKernelLogs())
	}
	for _, k := range kernels {
		result.kernelLogs = append(result.kernelLogs, forwarder.BuildKernelLogFromEvent(k.Type(), k.Event()))
	}
	return result
}

func assertEncodedLikeProto(t *testing.T, what string, msg *v3.EBPFAccessLogMessage) {
	t.Helper()
	want, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	got, err := sender.EncodeAccessLogMessage(msg)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: encoded %x\nproto.Marshal %x", what, got, want)
	}
	decoded := &v3.EBPFAccessLogMessage{}
	if err := proto.Unmarshal(got, decoded); err != nil || !proto.Equal(decoded, msg) {
		t.Fatalf("%s: decoded %v (%v), sent %v", what, decoded, err, msg)
	}
}

// assertTransferEncodedLikeProto: the kernel logs the sender encodes straight from the details of a protocol log
// (sender.BatchLogs.AppendTransferProtocolLog) are the bytes of proto.Marshal of the logs the builder builds
func assertTransferEncodedLikeProto(t *testing.T, what string, details []events.SocketDetail, protocol *v3.AccessLogProtocolLogs) {
	t.Helper()
	var kernels []*v3.AccessLogKernelLog
	for _, d := range details {
		if k := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, d); k != nil {
			kernels = append(kernels, k)
		}
	}
	want, err := proto.MarshalOptions{Deterministic: true}.Marshal(&v3.EBPFAccessLogMessage{KernelLogs: kernels, ProtocolLog: protocol})
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	got, count, err := sender.EncodeTransferProtocolLog(details, protocol)
	if err != nil || count != len(kernels) || !bytes.Equal(got, want) {
		t.Fatalf("%s: encoded %d kernel logs %x (%v)\nproto.Marshal of %d %x", what, count, got, err, len(kernels), want)
	}
}

func assertResultEncodedLikeProto(t *testing.T, name string, result *h2cResult, connection *v3.AccessLogConnection) {
	t.Helper()
	if len(result.protocolLogs) == 0 {
		t.Fatalf("%s: no protocol log", name)
	}
	for i, p := range result.protocolLogs {
		if len(result.protocolKernels[i]) == 0 {
			t.Fatalf("%s: protocol log %d has no kernel log", name, i)
		}
		assertTransferEncodedLikeProto(t, fmt.Sprintf("%s protocol log %d", name, i), result.protocolDetails[i], p)
		msg := &v3.EBPFAccessLogMessage{KernelLogs: result.protocolKernels[i], ProtocolLog: p}
		if i == 0 {
			msg.Connection = connection
		}
		assertEncodedLikeProto(t, fmt.Sprintf("%s protocol log %d", name, i), msg)
	}
	if len(result.kernelLogs) > 0 {
		assertEncodedLikeProto(t, name+" kernel logs", &v3.EBPFAccessLogMessage{KernelLogs: result.kernelLogs, Connection: connection})
	}
}

func testRPCConnection() *v3.AccessLogConnection {
	return &v3.AccessLogConnection{
		Local: &v3.ConnectionAddress{Address: &v3.ConnectionAddress_Kubernetes{Kubernetes: &v3.KubernetesProcessAddress{
			ServiceName: "default::server", PodName: "server-0", ContainerName: "server", ProcessName: "server", Port: 8080}}},
		Remote:   &v3.ConnectionAddress{Address: &v3.ConnectionAddress_Ip{Ip: &v3.IPAddress{Host: "10.244.0.12", Port: 41234}}},
		Protocol: v3.AccessLogProtocolType_HTTP_1,
	}
}

// TestHTTP1LogsEncodedAsProtoMarshal: the HTTP/1 logs, with the kernel logs of the messages merged or not
func TestHTTP1LogsEncodedAsProtoMarshal(t *testing.T) {
	exchanges := [][2]string{
		{"GET /api/v1/orders?id=1 HTTP/1.1\r\nHost: orders:8080\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"},
		{"POST /caf%C3%A9/" + strings.Repeat("x", 300) + " HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
			"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"},
		{"DELETE / HTTP/1.1\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n"},
	}
	for _, merge := range []bool{false, true} {
		common.SetMergeKernelLogs(merge)
		result := http1AnalyzeExchanges(t, exchanges)
		if len(result.protocolLogs) != len(exchanges) {
			t.Fatalf("merge=%t: %d protocol logs", merge, len(result.protocolLogs))
		}
		assertResultEncodedLikeProto(t, fmt.Sprintf("http1 merge=%t", merge), result, testRPCConnection())
	}
	common.SetMergeKernelLogs(false)
}

// TestHTTP2LogsEncodedAsProtoMarshal: the HTTP/2 logs, with the kernel logs of the messages merged or not
func TestHTTP2LogsEncodedAsProtoMarshal(t *testing.T) {
	for _, merge := range []bool{false, true} {
		common.SetMergeKernelLogs(merge)
		result := h2cAnalyze(t, h2cServerScript().uploads(bpfNow(), false), 7)
		assertResultEncodedLikeProto(t, fmt.Sprintf("http2 merge=%t", merge), result, testRPCConnection())
	}
	common.SetMergeKernelLogs(false)
}

// TestKernelLogsEncodedAsProtoMarshal: the kernel logs of the agent's builder, read and write of every syscall
func TestKernelLogsEncodedAsProtoMarshal(t *testing.T) {
	base := bpfNow()
	var logs []*v3.AccessLogKernelLog
	var details []events.SocketDetail
	for i, f := range []enums.SocketFunctionName{enums.SocketFunctionNameRead, enums.SocketFunctionNameReadv,
		enums.SocketFunctionNameRecv, enums.SocketFunctionNameRecvfrom, enums.SocketFunctionNameRecvMsg,
		enums.SocketFunctionNameRecvMMsg, enums.SocketFunctionNameWrite, enums.SocketFunctionNameWritev,
		enums.SocketFunctionNameSend, enums.SocketFunctionNameSendto, enums.SocketFunctionNameSendMsg,
		enums.SocketFunctionNameSendMMSg, enums.SocketFunctionNameSendFile} {
		event := &events.SocketDataUploadEvent{FunctionName: uint32(f), StartTime0: base + uint64(i)*1000,
			EndTime0: base + uint64(i)*1000 + 500, L4PackageCount: uint32(i), L4TotalPackageSize: uint64(i) * 1514}
		logs = append(logs, forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, event))
		details = append(details, event)
	}
	assertEncodedLikeProto(t, "kernel logs", &v3.EBPFAccessLogMessage{KernelLogs: logs})
	assertTransferEncodedLikeProto(t, "kernel logs", details, nil)
}

// TestTransferLogsEncodedAsProtoMarshal: the kernel logs encoded straight from the events of the agent, of every
// function (the ones that are not a read or a write have no log), with every counter zero, set or at its maximum
func TestTransferLogsEncodedAsProtoMarshal(t *testing.T) {
	protocol := &v3.AccessLogProtocolLogs{Protocol: &v3.AccessLogProtocolLogs_Http{Http: &v3.AccessLogHTTPProtocol{
		Version: v3.AccessLogHTTPProtocolVersion_HTTP2, Request: &v3.AccessLogHTTPProtocolRequest{Path: "/p"}}}}
	var all []events.SocketDetail
	for f := 0; f <= 22; f++ {
		for i, event := range []*events.SocketDataUploadEvent{
			{FunctionName: uint32(f)},
			{FunctionName: uint32(f), StartTime0: bpfNow(), EndTime0: bpfNow() + 9, L4PackageCount: 3, L4TotalPackageSize: 4500},
			{FunctionName: uint32(f), StartTime0: ^uint64(0), EndTime0: 1 << 63, L4PackageCount: ^uint32(0), L4TotalPackageSize: ^uint64(0)},
		} {
			assertTransferEncodedLikeProto(t, fmt.Sprintf("function %d event %d", f, i), []events.SocketDetail{event}, nil)
			all = append(all, event)
		}
	}
	assertTransferEncodedLikeProto(t, "every event", all, protocol)
	assertTransferEncodedLikeProto(t, "no event", nil, protocol)
}
