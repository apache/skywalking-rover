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

package sender

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// testBootOffset is a timestamp offset of the kernel, in nanoseconds since the boot
const testBootOffset = uint64(3_600_000_000_000)

// transferEvent is a socket call with every counter set, different per call
func transferEvent(i int, funcName enums.SocketFunctionName) *events.SocketDataUploadEvent {
	n := uint64(i + 1)
	return &events.SocketDataUploadEvent{
		ConnectionID: 1, RandomID: 1, DataID0: n,
		StartTime0: testBootOffset + n*1000, EndTime0: testBootOffset + n*1000 + 300,
		L4TotalPackageSize: 1500 * n, L4PackageCount: uint32(n), FunctionName: uint32(funcName),
		Protocol0: enums.ConnectionProtocolHTTP,
	}
}

// corpusKernelLogs is a kernel log of every operation and syscall, built by the builders of the forwarder
func corpusKernelLogs() []*v3.AccessLogKernelLog {
	var result []*v3.AccessLogKernelLog
	funcs := []enums.SocketFunctionName{
		enums.SocketFunctionNameRead, enums.SocketFunctionNameReadv, enums.SocketFunctionNameRecv,
		enums.SocketFunctionNameRecvfrom, enums.SocketFunctionNameRecvMsg, enums.SocketFunctionNameRecvMMsg,
		enums.SocketFunctionNameWrite, enums.SocketFunctionNameWritev, enums.SocketFunctionNameSend,
		enums.SocketFunctionNameSendto, enums.SocketFunctionNameSendMsg, enums.SocketFunctionNameSendMMSg,
		enums.SocketFunctionNameSendFile,
	}
	for i, f := range funcs {
		result = append(result, forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, transferEvent(i, f)))
	}
	for i, f := range []enums.SocketFunctionName{enums.SocketFunctionNameConnect, enums.SocketFunctionNameAccept} {
		for _, success := range []uint8{0, 1} {
			result = append(result, forwarder.BuildKernelLogFromEvent(common.LogTypeConnect, &common.ConnectEventWithSocket{
				SocketConnectEvent: &events.SocketConnectEvent{StartTime: testBootOffset + uint64(i), EndTime: testBootOffset + 50,
					FuncName: uint8(f), ConnectSuccess: success},
			}))
		}
	}
	for _, success := range []uint32{0, 1} {
		result = append(result, forwarder.BuildKernelLogFromEvent(common.LogTypeClose, &common.CloseEventWithNotify{
			SocketCloseEvent: &events.SocketCloseEvent{StartTime: testBootOffset + 7, EndTime: testBootOffset + 9, Success: success},
		}))
	}
	// a write with lost packages and the counters of a merged record
	write := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, transferEvent(40, enums.SocketFunctionNameWrite))
	write.GetWrite().L4Metrics.LossPackageMetrics = []*v3.AccessLogLossPackageMetrics{
		{Location: "tcp_retransmit_skb", Count: 3}, {Location: "", Count: 0}, {Location: "kfree_skb", Count: -1}}
	result = append(result, write)
	// merged kernel logs: the consecutive calls of one operation folded into one
	var merging []*v3.AccessLogKernelLog
	for i := 0; i < 6; i++ {
		var f enums.SocketFunctionName = enums.SocketFunctionNameRead
		if i >= 3 {
			f = enums.SocketFunctionNameWrite
		}
		merging = append(merging, forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, transferEvent(100+i, f)))
	}
	merged := forwarder.MergeKernelLogs(merging)
	if len(merged) != 2 {
		panic(fmt.Sprintf("%d merged logs", len(merged)))
	}
	return append(result, merged...)
}

// httpProtocolLog is a protocol log the way the HTTP analyzers build it
func httpProtocolLog(version v3.AccessLogHTTPProtocolVersion, path, host string, status int32) *v3.AccessLogProtocolLogs {
	startTime, endTime := forwarder.BuildOffsetTimestamps(testBootOffset+1000, testBootOffset+987654)
	return &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: startTime,
				EndTime:   endTime,
				Version:   version,
				Request: &v3.AccessLogHTTPProtocolRequest{
					Method:             v3.AccessLogHTTPProtocolRequestMethod_Post,
					Path:               path,
					SizeOfHeadersBytes: 312,
					SizeOfBodyBytes:    1024,
					Host:               host,
				},
				Response: &v3.AccessLogHTTPProtocolResponse{
					StatusCode:         status,
					SizeOfHeadersBytes: 87,
					SizeOfBodyBytes:    256 * 1024,
				},
			},
		},
	}
}

func corpusProtocolLogs() []*v3.AccessLogProtocolLogs {
	traced := httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP1, "/traced", "svc", 200)
	traced.GetHttp().Request.Trace = &v3.AccessLogTraceInfo{Provider: v3.AccessLogTraceInfoProvider_SkyWalking,
		TraceId: "4bf92f3577b34da6a3ce929d0e0e4736", TraceSegmentId: "00f067aa0ba902b7", SpanId: "1"}
	return []*v3.AccessLogProtocolLogs{
		httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP1, "/api/v1/orders", "orders.default.svc.cluster.local:8080", 200),
		httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP2, "/grpc.health.v1.Health/Check", "upstream:8080", 0),
		httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP1, "", "", 503),
		// a path long enough for a length of two and of three bytes, the HTTP message and the protocol log
		httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP1, "/"+strings.Repeat("a", 200), "h", 404),
		httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP2, "/"+strings.Repeat("ü", 9000), "h", -1),
		traced,
		{},
		{Protocol: &v3.AccessLogProtocolLogs_Http{}},
		{Protocol: &v3.AccessLogProtocolLogs_Http{Http: &v3.AccessLogHTTPProtocol{Request: &v3.AccessLogHTTPProtocolRequest{},
			Response: &v3.AccessLogHTTPProtocolResponse{}, StartTime: &v3.EBPFTimestamp{},
			EndTime: &v3.EBPFTimestamp{Timestamp: &v3.EBPFTimestamp_Offset{}}}}},
	}
}

func corpusConnections() []*v3.AccessLogConnection {
	k8s := &v3.ConnectionAddress{Address: &v3.ConnectionAddress_Kubernetes{Kubernetes: &v3.KubernetesProcessAddress{
		ServiceName: "default::orders", PodName: "orders-7d4b9c6f5-x2x9z", ContainerName: "app", ProcessName: "java", Port: 8080}}}
	remote := &v3.ConnectionAddress{Address: &v3.ConnectionAddress_Ip{Ip: &v3.IPAddress{Host: "10.96.0.17", Port: 9090}}}
	return []*v3.AccessLogConnection{
		{Local: k8s, Remote: remote, Role: v32.DetectPoint_client, TlsMode: v3.AccessLogConnectionTLSMode_Plain,
			Protocol: v3.AccessLogProtocolType_TCP},
		{Local: k8s, Remote: remote, Role: v32.DetectPoint_server, TlsMode: v3.AccessLogConnectionTLSMode_TLS,
			Protocol: v3.AccessLogProtocolType_HTTP_2,
			Attachment: &v3.ConnectionAttachment{Environment: &v3.ConnectionAttachment_ZTunnel{ZTunnel: &v3.ZTunnelAttachmentEnvironment{
				RealDestinationIp: "10.244.1.9", By: v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_INBOUND_FUNC,
				SecurityPolicy: v3.ZTunnelAttachmentSecurityPolicy_MTLS,
				Addition:       []*v32.KeyStringValuePair{{Key: "DST_SERVICE", Value: "payments"}, {Key: "", Value: ""}, nil}}}}},
		{Local: &v3.ConnectionAddress{}, Remote: &v3.ConnectionAddress{Address: &v3.ConnectionAddress_Ip{}},
			Attachment: &v3.ConnectionAttachment{}},
		{},
	}
}

func corpusNode() *v3.EBPFAccessLogNodeInfo {
	return &v3.EBPFAccessLogNodeInfo{
		Name: "node-1",
		NetInterfaces: []*v3.EBPFAccessLogNodeNetInterface{{Index: 0, Mtu: 65536, Name: "lo"}, {Index: 1, Mtu: 1500, Name: "eth0"},
			{Index: -1}, nil},
		BootTime:    &v32.Instant{Seconds: 1_762_000_000, Nanos: 123456789},
		ClusterName: "stress",
		Policy:      &v3.EBPFAccessLogPolicy{ExcludeNamespaces: []string{"kube-system", "", "istio-system"}},
	}
}

// corpusMessages are the messages the sender sends, and some it never builds, around the edges of the encoding
func corpusMessages() []*v3.EBPFAccessLogMessage {
	kernels := corpusKernelLogs()
	protocolLogs := corpusProtocolLogs()
	connections := corpusConnections()
	result := []*v3.EBPFAccessLogMessage{
		{},
		{Node: corpusNode(), Connection: connections[0], KernelLogs: kernels},
		{Node: &v3.EBPFAccessLogNodeInfo{Policy: &v3.EBPFAccessLogPolicy{}}},
		{KernelLogs: []*v3.AccessLogKernelLog{nil, {}, {Operation: &v3.AccessLogKernelLog_Read{}},
			{Operation: &v3.AccessLogKernelLog_Write{Write: &v3.AccessLogKernelWriteOperation{}}},
			{Operation: &v3.AccessLogKernelLog_Close{}}, {Operation: &v3.AccessLogKernelLog_Connect{}},
			{Operation: &v3.AccessLogKernelLog_Accept{}}}},
	}
	for i, p := range protocolLogs {
		// a protocol log with its 2 kernel logs, the first of a connection or not
		msg := &v3.EBPFAccessLogMessage{KernelLogs: []*v3.AccessLogKernelLog{kernels[i%len(kernels)], kernels[(i+6)%len(kernels)]},
			ProtocolLog: p}
		if i%2 == 0 {
			msg.Connection = connections[i/2%len(connections)]
		}
		result = append(result, msg)
	}
	for _, c := range connections {
		result = append(result, &v3.EBPFAccessLogMessage{Connection: c, KernelLogs: kernels[:1]})
	}
	return result
}

func assertEncodedLikeProto(t *testing.T, msg *v3.EBPFAccessLogMessage) {
	t.Helper()
	want, err := deterministic.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeAccessLogMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded %x\nproto.Marshal %x\nof %v", got, want, msg)
	}
	decoded := &v3.EBPFAccessLogMessage{}
	if err := proto.Unmarshal(got, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(decoded, msg) {
		t.Fatalf("decoded %v\nencoded %v", decoded, msg)
	}
}

func TestEncoderCoversTheGeneratedMessages(t *testing.T) {
	if uncovered := uncoveredMessages(); uncovered != nil {
		t.Fatalf("the encoder is not written for the fields of: %v", uncovered)
	}
	if !wireEncodingCovered {
		t.Fatal("the encoder is off")
	}
}

// TestEncodedAsProtoMarshal: the encoder writes the bytes of proto.Marshal for every message of the corpus,
// and they decode to the same message
func TestEncodedAsProtoMarshal(t *testing.T) {
	for i, msg := range corpusMessages() {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assertEncodedLikeProto(t, msg)
		})
	}
}

// TestEncodedUnknownFields: the unknown fields of the header messages are written last, like proto.Marshal does
func TestEncodedUnknownFields(t *testing.T) {
	var unknown []byte
	unknown = protowire.AppendTag(unknown, 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 7)
	unknown = protowire.AppendTag(unknown, 100, protowire.BytesType)
	unknown = protowire.AppendString(unknown, "x")
	for i, msg := range corpusMessages() {
		// every message of the header gets unknown fields, the logs never have any (see kernelLog)
		decoded := proto.Clone(msg).(*v3.EBPFAccessLogMessage)
		decoded.ProtoReflect().SetUnknown(unknown)
		if decoded.Node != nil {
			addUnknown(decoded.Node, unknown)
		}
		if decoded.Connection != nil {
			addUnknown(decoded.Connection, unknown)
		}
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assertEncodedLikeProto(t, decoded)
		})
	}
}

// unknownFieldSources are the calls that give a message unknown fields
var unknownFieldSources = regexp.MustCompile(`\b(proto|protojson|prototext)\.(Unmarshal|Merge)\b|\bUnmarshalOptions\b|\.SetUnknown\(`)

// TestNoUnknownFieldsInTheLogs: no source of the rover and of the agent (cmd, internal, pkg) that uses the access log messages gives one unknown
// fields, but the reply of the stream (codec.go), which the encoder of the logs relies on (see kernelLog)
func TestNoUnknownFieldsInTheLogs(t *testing.T) {
	modules := []string{"../../.."}
	// the agent the rover is a module of, when it is
	if mod, err := os.ReadFile("../../../../go.mod"); err == nil && bytes.Contains(mod, []byte("github.com/apache/skywalking-rover => ./skywalking-rover")) {
		modules = append(modules, "../../../..")
	}
	var roots []string
	for _, m := range modules {
		for _, dir := range []string{"cmd", "internal", "pkg"} {
			if _, err := os.Stat(filepath.Join(m, dir)); err == nil {
				roots = append(roots, filepath.Join(m, dir))
			}
		}
	}
	codec, _ := filepath.Abs("codec.go")
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			abs, _ := filepath.Abs(path)
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || abs == codec {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(source, []byte(`"skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"`)) {
				return err
			}
			for n, line := range strings.Split(string(source), "\n") {
				if code, _, _ := strings.Cut(line, "//"); unknownFieldSources.MatchString(code) {
					t.Errorf("%s:%d may give the access log messages unknown fields, which the encoder does not write: %s",
						abs, n+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func addUnknown(m proto.Message, unknown []byte) {
	r := m.ProtoReflect()
	r.SetUnknown(append(r.GetUnknown(), unknown...))
	r.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.Message() == nil:
		case fd.IsList():
			for i := 0; i < v.List().Len(); i++ {
				if v.List().Get(i).Message().IsValid() {
					addUnknown(v.List().Get(i).Message().Interface(), unknown)
				}
			}
		case v.Message().IsValid():
			addUnknown(v.Message().Interface(), unknown)
		}
		return true
	})
}

// TestEncodingFailsOnInvalidUTF8 like proto.Marshal does, for every string
func TestEncodingFailsOnInvalidUTF8(t *testing.T) {
	bad := "/\xff"
	messages := []*v3.EBPFAccessLogMessage{
		{ProtocolLog: httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP1, bad, "h", 200)},
		{ProtocolLog: httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP1, "/", bad, 200)},
		{Connection: &v3.AccessLogConnection{Local: &v3.ConnectionAddress{Address: &v3.ConnectionAddress_Ip{Ip: &v3.IPAddress{Host: bad}}}}},
		{Node: &v3.EBPFAccessLogNodeInfo{Policy: &v3.EBPFAccessLogPolicy{ExcludeNamespaces: []string{bad}}}},
	}
	for i, msg := range messages {
		if _, err := deterministic.Marshal(msg); err == nil {
			t.Fatalf("%d: proto.Marshal takes it", i)
		}
		if _, err := EncodeAccessLogMessage(msg); err == nil {
			t.Fatalf("%d: encoded", i)
		}
	}
}

// TestEncodingFallsBackToProto: with messages the encoder is not written for, every log goes through proto.Marshal
func TestEncodingFallsBackToProto(t *testing.T) {
	wireEncodingCovered = false
	defer func() { wireEncodingCovered = true }()
	for _, msg := range corpusMessages() {
		assertEncodedLikeProto(t, msg)
		e := &wireEncoder{}
		e.encodeHeader(msg.Node, msg.Connection)
		e.encodeProtocolLog(msg.KernelLogs, msg.ProtocolLog)
		want, _ := deterministic.Marshal(msg)
		if e.err != nil || !bytes.Equal(e.buf, want) {
			t.Fatalf("encoded %x, expected %x", e.buf, want)
		}
	}
}

// TestBatchEncodesLikeTheMessages: the messages put together from the encoded logs of a batch are the bytes of
// the messages the sender built from the logs before, with the kernel logs merged or not
func TestBatchEncodesLikeTheMessages(t *testing.T) {
	for _, merge := range []bool{false, true} {
		batch := newBatchLogs()
		if merge {
			batch.EnableKernelLogMerge()
		}
		conn := testConnection(1)
		conn.RPCConnection = corpusConnections()[1]
		// the legacy messages are built from copies: merging changes the logs
		var kernels []*v3.AccessLogKernelLog
		for _, k := range corpusKernelLogs() {
			kernels = append(kernels, proto.Clone(k).(*v3.AccessLogKernelLog))
			batch.AppendKernelLog(conn, k)
		}
		if merge {
			kernels = forwarder.MergeKernelLogs(kernels)
		}
		var protocolMessages []*v3.EBPFAccessLogMessage
		for i, p := range corpusProtocolLogs() {
			pk := []*v3.AccessLogKernelLog{corpusKernelLogs()[i], corpusKernelLogs()[i+1]}
			batch.AppendProtocolLog(conn, pk, p)
			protocolMessages = append(protocolMessages, &v3.EBPFAccessLogMessage{KernelLogs: pk, ProtocolLog: p})
		}
		batch.seal()
		logs := batch.logs[conn]
		if len(logs.kernels) != len(kernels) || len(logs.protocols) != len(protocolMessages) {
			t.Fatalf("merge=%t: %d kernel logs, %d expected", merge, len(logs.kernels), len(kernels))
		}
		want, _ := deterministic.Marshal(&v3.EBPFAccessLogMessage{KernelLogs: kernels})
		if got := bytes.Join(logs.kernels, nil); !bytes.Equal(got, want) {
			t.Fatalf("merge=%t: kernel logs %x, expected %x", merge, got, want)
		}
		for i, m := range protocolMessages {
			want, _ := deterministic.Marshal(m)
			if !bytes.Equal(logs.protocols[i], want) {
				t.Fatalf("merge=%t: protocol log %d %x, expected %x", merge, i, logs.protocols[i], want)
			}
		}
	}
}

// transferDetails is a kernel transfer event of every function, with every counter set or zero or at its maximum:
// the functions that are not a read or a write have no kernel log
func transferDetails() []events.SocketDetail {
	var result []events.SocketDetail
	funcs := []enums.SocketFunctionName{
		enums.SocketFunctionNameRead, enums.SocketFunctionNameReadv, enums.SocketFunctionNameRecv,
		enums.SocketFunctionNameRecvfrom, enums.SocketFunctionNameRecvMsg, enums.SocketFunctionNameRecvMMsg,
		enums.SocketFunctionNameWrite, enums.SocketFunctionNameWritev, enums.SocketFunctionNameSend,
		enums.SocketFunctionNameSendto, enums.SocketFunctionNameSendMsg, enums.SocketFunctionNameSendMMSg,
		enums.SocketFunctionNameSendFile, enums.SocketFunctionNameResent, enums.SocketFunctionNameSslWrite,
		enums.SocketFunctionNameSslRead, enums.SocketFunctionNameGoTLSWrite, enums.SocketFunctionNameGoTLSRead,
		// no kernel transfer log
		enums.SocketFunctionNameConnect, enums.SocketFunctionNameAccept, enums.SocketFunctionNameClose, 0, 200,
	}
	for i, f := range funcs {
		result = append(result, transferEvent(i, f), &events.SocketDataUploadEvent{FunctionName: uint32(f)})
		big := transferEvent(i*1000, f)
		big.StartTime0, big.EndTime0 = ^uint64(0), 1<<63
		big.L4TotalPackageSize, big.L4PackageCount = ^uint64(0), ^uint32(0)
		result = append(result, big)
	}
	return result
}

// builtKernelLogs is the kernel logs BuildKernelLogFromEvent builds of the details, without the nil ones
func builtKernelLogs(details []events.SocketDetail) []*v3.AccessLogKernelLog {
	var result []*v3.AccessLogKernelLog
	for _, d := range details {
		if k := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, d); k != nil {
			result = append(result, k)
		}
	}
	return result
}

// assertTransferEncodedLikeTheBuiltLogs: the kernel logs written straight from the details are the bytes of the
// message of the logs the builder builds
func assertTransferEncodedLikeTheBuiltLogs(t *testing.T, what string, details []events.SocketDetail, protocol *v3.AccessLogProtocolLogs) {
	t.Helper()
	kernels := builtKernelLogs(details)
	want, err := deterministic.Marshal(&v3.EBPFAccessLogMessage{KernelLogs: kernels, ProtocolLog: protocol})
	if err != nil {
		t.Fatal(err)
	}
	got, count, err := EncodeTransferProtocolLog(details, protocol)
	if err != nil || count != len(kernels) || !bytes.Equal(got, want) {
		t.Fatalf("%s: encoded %d logs %x (%v), the built %d logs %x", what, count, got, err, len(kernels), want)
	}
}

// TestTransferLogsEncodedAsTheBuiltLogs: every kernel transfer log, alone and together, with a protocol log or not,
// and through proto.Marshal when the encoder is not written for the messages
func TestTransferLogsEncodedAsTheBuiltLogs(t *testing.T) {
	details := transferDetails()
	for _, covered := range []bool{true, false} {
		wireEncodingCovered = covered
		for i, d := range details {
			assertTransferEncodedLikeTheBuiltLogs(t, fmt.Sprintf("covered=%t detail %d", covered, i), []events.SocketDetail{d}, nil)
		}
		for i, p := range corpusProtocolLogs() {
			assertTransferEncodedLikeTheBuiltLogs(t, fmt.Sprintf("covered=%t protocol log %d", covered, i), details, p)
		}
		assertTransferEncodedLikeTheBuiltLogs(t, fmt.Sprintf("covered=%t no detail", covered), nil, corpusProtocolLogs()[0])
	}
	wireEncodingCovered = true
}

// TestBatchAppendsTransferLogsLikeTheBuiltLogs: AppendTransferProtocolLog adds what AppendProtocolLog adds for the built
// kernel logs, and nothing when there is no kernel log
func TestBatchAppendsTransferLogsLikeTheBuiltLogs(t *testing.T) {
	built, direct := newBatchLogs(), newBatchLogs()
	conn := testConnection(1)
	details := transferDetails()
	for i, p := range corpusProtocolLogs() {
		pd := details[i : i+3]
		built.AppendProtocolLog(conn, builtKernelLogs(pd), p)
		if count := direct.AppendTransferProtocolLog(conn, pd, p); count != len(builtKernelLogs(pd)) {
			t.Fatalf("protocol log %d: %d kernel logs", i, count)
		}
	}
	noLog := []events.SocketDetail{&events.SocketDataUploadEvent{FunctionName: uint32(enums.SocketFunctionNameClose)}}
	if direct.AppendTransferProtocolLog(conn, noLog, corpusProtocolLogs()[0]) != 0 ||
		direct.AppendTransferProtocolLog(testConnection(2), nil, corpusProtocolLogs()[0]) != 0 {
		t.Fatalf("a protocol log without kernel log is added")
	}
	// a log that cannot be encoded is not added, and its kernel logs are not counted
	bad := &v3.AccessLogProtocolLogs{Protocol: &v3.AccessLogProtocolLogs_Http{Http: &v3.AccessLogHTTPProtocol{
		Request: &v3.AccessLogHTTPProtocolRequest{Path: "\xff\xfe"}}}}
	if count := direct.AppendTransferProtocolLog(conn, details[:3], bad); count != 0 {
		t.Fatalf("a log that cannot be encoded counts %d kernel logs", count)
	}
	if built.AppendProtocolLog(testConnection(3), nil, bad) {
		t.Fatalf("a log that cannot be encoded is added")
	}
	built.seal()
	direct.seal()
	if direct.ConnectionCount() != 1 || len(direct.logs[conn].protocols) != len(built.logs[conn].protocols) {
		t.Fatalf("%d connections, %d protocol logs", direct.ConnectionCount(), len(direct.logs[conn].protocols))
	}
	for i, b := range built.logs[conn].protocols {
		if !bytes.Equal(direct.logs[conn].protocols[i], b) {
			t.Fatalf("protocol log %d: %x, built %x", i, direct.logs[conn].protocols[i], b)
		}
	}
}

// TestBatchDropsWhatCannotBeEncoded: a protocol log proto.Marshal rejects is dropped alone and counted
func TestBatchDropsWhatCannotBeEncoded(t *testing.T) {
	before := encodeErrors.Load()
	batch := newBatchLogs()
	conn := testConnection(1)
	batch.AppendProtocolLog(conn, nil, httpProtocolLog(v3.AccessLogHTTPProtocolVersion_HTTP1, "/\xff", "h", 200))
	batch.AppendProtocolLog(conn, nil, protocolLog("/fine"))
	if batch.LogCount() != 1 || encodeErrors.Load() != before+1 {
		t.Fatalf("%d logs, %d encoding errors", batch.LogCount(), encodeErrors.Load()-before)
	}
	if path := encodedProtocolPath(t, batch.logs[conn].protocols[0]); path != "/fine" {
		t.Fatalf("the log left is %s", path)
	}
}
