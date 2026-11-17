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
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
)

func testConnection(i int) *common.ConnectionInfo {
	return &common.ConnectionInfo{ConnectionID: uint64(i), RandomID: 1,
		RPCConnection: &v3.AccessLogConnection{Local: &v3.ConnectionAddress{Address: &v3.ConnectionAddress_Ip{
			Ip: &v3.IPAddress{Host: fmt.Sprintf("10.0.0.%d", i), Port: 80}}}}}
}

// protocolLog is identified by its path in the tests
func protocolLog(name string) *v3.AccessLogProtocolLogs {
	return &v3.AccessLogProtocolLogs{Protocol: &v3.AccessLogProtocolLogs_Http{Http: &v3.AccessLogHTTPProtocol{
		Request: &v3.AccessLogHTTPProtocolRequest{Path: name}}}}
}

func kernelLog() *v3.AccessLogKernelLog {
	return &v3.AccessLogKernelLog{Operation: &v3.AccessLogKernelLog_Close{Close: &v3.AccessLogKernelCloseOperation{}}}
}

// testBatch has, for every connection, kernel logs and protocol logs named "<connection>-p<n>"
func testBatch(connections, kernels, protocols int) (*BatchLogs, map[string][]string) {
	batch := newBatchLogs()
	expected := map[string][]string{}
	for c := 0; c < connections; c++ {
		conn := testConnection(c)
		key := conn.RPCConnection.String()
		for k := 0; k < kernels; k++ {
			batch.AppendKernelLog(conn, kernelLog())
			expected[key] = append(expected[key], "kernel")
		}
		for p := 0; p < protocols; p++ {
			name := fmt.Sprintf("%d-p%d", c, p)
			batch.AppendProtocolLog(conn, nil, protocolLog(name))
			expected[key] = append(expected[key], name)
		}
	}
	return batch, expected
}

// encodedProtocolPath is the path of the encoded protocol log
func encodedProtocolPath(t *testing.T, encoded []byte) string {
	t.Helper()
	msg := &v3.EBPFAccessLogMessage{}
	if err := proto.Unmarshal(encoded, msg); err != nil {
		t.Fatal(err)
	}
	return msg.GetProtocolLog().GetHttp().GetRequest().GetPath()
}

func TestSplitBatchLogsByLogCount(t *testing.T) {
	batch, _ := testBatch(3, 4, 5)
	if batch.LogCount() != 27 {
		t.Fatalf("log count %d", batch.LogCount())
	}
	parts := batch.splitBatchLogs(4)
	total := 0
	perConnection := map[*common.ConnectionInfo][]string{}
	for _, part := range parts {
		if part.LogCount() > 4 || part.LogCount() == 0 {
			t.Fatalf("a part carries %d logs", part.LogCount())
		}
		total += part.LogCount()
		for conn, logs := range part.logs {
			for range logs.kernels {
				perConnection[conn] = append(perConnection[conn], "kernel")
			}
			for _, p := range logs.protocols {
				perConnection[conn] = append(perConnection[conn], encodedProtocolPath(t, p))
			}
		}
	}
	if total != 27 || len(parts) != 7 {
		t.Fatalf("%d logs in %d parts", total, len(parts))
	}
	for conn, logs := range perConnection {
		want := []string{"kernel", "kernel", "kernel", "kernel"}
		for p := 0; p < 5; p++ {
			want = append(want, fmt.Sprintf("%d-p%d", conn.ConnectionID, p))
		}
		if !slices.Equal(logs, want) {
			t.Fatalf("connection %d: the logs are split out of order: %v", conn.ConnectionID, logs)
		}
	}
}

// fakeCollector records the messages of every stream and resolves them the way the backend does
// (AccessLogServiceHandler.collect): the node of the first message, the connection of the last message
// that has one
type fakeCollector struct {
	v3.UnimplementedEBPFAccessLogServiceServer
	mu      sync.Mutex
	streams [][]*v3.EBPFAccessLogMessage
	delay   time.Duration
	// failing rejects the streams while it is set, like a backend that is not there
	failing  bool
	rejected int
}

func (f *fakeCollector) Collect(stream v3.EBPFAccessLogService_CollectServer) error {
	f.mu.Lock()
	if f.failing {
		f.rejected++
		f.mu.Unlock()
		return status.Error(codes.Unavailable, "the backend is not there")
	}
	f.mu.Unlock()
	var messages []*v3.EBPFAccessLogMessage
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		time.Sleep(f.delay)
		messages = append(messages, msg)
	}
	f.mu.Lock()
	f.streams = append(f.streams, messages)
	f.mu.Unlock()
	return stream.SendAndClose(&v3.EBPFAccessLogDownstream{})
}

func (f *fakeCollector) logs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.streams {
		for _, m := range s {
			n += len(m.KernelLogs)
			if m.ProtocolLog != nil {
				n++
			}
		}
	}
	return n
}

func newTestSender(t *testing.T, collector *fakeCollector, config common.SenderConfig) *GRPCSender {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	v3.RegisterEBPFAccessLogServiceServer(server, collector)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	g := newGRPCSender(v3.NewEBPFAccessLogServiceClient(conn), config)
	g.nodeInfo = func() *v3.EBPFAccessLogNodeInfo { return &v3.EBPFAccessLogNodeInfo{Name: "node"} }
	return g
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 10*time.Second, 5*time.Millisecond, "waiting for %s", what)
}

// TestEveryStreamCarriesItsHeaders sends a batch split over several streams sent in parallel, with the
// logs of a connection split over streams, and resolves every stream like the backend: each one must name
// its node on its first message and each connection before its logs, and every log must arrive once and
// be attributed to its own connection.
func TestEveryStreamCarriesItsHeaders(t *testing.T) {
	collector := &fakeCollector{delay: time.Millisecond}
	sender := newTestSender(t, collector, common.SenderConfig{Parallelism: 4, MaxLogsPerSend: 7})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender.ctx = ctx
	sender.Start(ctx)

	batch, expected := testBatch(5, 3, 10)
	total := batch.LogCount()
	sender.AddBatch(batch)
	waitFor(t, "every log", func() bool { return collector.logs() == total })

	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(collector.streams) < 2 {
		t.Fatalf("the batch went over %d streams", len(collector.streams))
	}
	received := map[string][]string{}
	for i, stream := range collector.streams {
		var node *v3.EBPFAccessLogNodeInfo
		var connection *v3.AccessLogConnection
		for j, msg := range stream {
			if j == 0 {
				if msg.Node == nil || msg.Node.Name != "node" {
					t.Fatalf("stream %d does not name its node on its first message", i)
				}
				node = msg.Node
			}
			if msg.Connection != nil {
				connection = msg.Connection
			}
			if node == nil || connection == nil {
				t.Fatalf("stream %d: message %d cannot be attributed", i, j)
			}
			key := connection.String()
			for range msg.KernelLogs {
				received[key] = append(received[key], "kernel")
			}
			if msg.ProtocolLog != nil {
				received[key] = append(received[key], msg.ProtocolLog.GetHttp().GetRequest().GetPath())
			}
		}
	}
	for key, want := range expected {
		got := received[key]
		if len(got) != len(want) {
			t.Fatalf("connection %s: %d logs received, %d sent", key, len(got), len(want))
		}
		seen := map[string]int{}
		for _, g := range got {
			seen[g]++
		}
		for _, w := range want {
			if seen[w] == 0 {
				t.Fatalf("connection %s: log %s was not received or attributed to another connection", key, w)
			}
			seen[w]--
		}
	}
}

// TestLowTrafficUsesOneStream: a small batch goes out at once over a single stream, as before
func TestLowTrafficUsesOneStream(t *testing.T) {
	collector := &fakeCollector{}
	sender := newTestSender(t, collector, common.SenderConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender.ctx = ctx
	sender.Start(ctx)
	batch, _ := testBatch(2, 1, 2)
	start := time.Now()
	sender.AddBatch(batch)
	waitFor(t, "the logs", func() bool { return collector.logs() == 6 })
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the batch took %s", elapsed)
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(collector.streams) != 1 {
		t.Fatalf("a small batch went over %d streams", len(collector.streams))
	}
}

// TestBacklogDropsTheOldestBatches: with nothing sending and max_pending_logs set, the waiting logs stay
// within it, the oldest batches are dropped and counted; with the default 0 nothing is dropped
func TestBacklogDropsTheOldestBatches(t *testing.T) {
	unbounded := newGRPCSender(nil, common.SenderConfig{MaxLogsPerSend: 4})
	for i := 0; i < 50; i++ {
		batch, _ := testBatch(1, 0, 4)
		unbounded.AddBatch(batch)
	}
	if unbounded.pendingLogs != 200 || unbounded.droppedLogs.Load() != 0 {
		t.Fatalf("without a cap: %d logs waiting, %d dropped", unbounded.pendingLogs, unbounded.droppedLogs.Load())
	}

	sender := newGRPCSender(nil, common.SenderConfig{MaxLogsPerSend: 4, MaxPendingLogs: 10})
	for i := 0; i < 5; i++ {
		batch := newBatchLogs()
		for p := 0; p < 4; p++ {
			batch.AppendProtocolLog(testConnection(i), nil, protocolLog(fmt.Sprintf("%d-%d", i, p)))
		}
		sender.AddBatch(batch)
	}
	if sender.pendingLogs > 10 || sender.pendingLogs != 8 {
		t.Fatalf("%d logs waiting", sender.pendingLogs)
	}
	if sender.droppedLogs.Load() != 12 {
		t.Fatalf("%d logs dropped", sender.droppedLogs.Load())
	}
	// the newest two batches are left, in order
	for i, want := range []uint64{3, 4} {
		b := sender.popLogs()
		for conn := range b.logs.logs {
			if conn.ConnectionID != want {
				t.Fatalf("batch %d left is of connection %d, expected %d", i, conn.ConnectionID, want)
			}
		}
	}
	if sender.popLogs() != nil || sender.pendingLogs != 0 {
		t.Fatalf("logs left after popping everything")
	}
}

// TestBackendOutageKeepsTheBacklog: while the backend rejects the streams, a failed send stops the draining,
// so only the batches already in flight are lost and the backlog waits for the next batch, which sends it
func TestBackendOutageKeepsTheBacklog(t *testing.T) {
	collector := &fakeCollector{failing: true}
	sender := newTestSender(t, collector, common.SenderConfig{Parallelism: 4, MaxLogsPerSend: 2})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender.ctx = ctx
	sender.Start(ctx)

	batch, _ := testBatch(10, 0, 2) // 10 batches of 2 logs
	sender.AddBatch(batch)
	waitFor(t, "the failed sends", func() bool { return sender.sendErrors.Load() > 0 })
	time.Sleep(200 * time.Millisecond)
	sender.mutex.Lock()
	left, lost := sender.logs.Len(), int(sender.sendErrors.Load())
	sender.mutex.Unlock()
	if lost > 4 || left+lost != 10 {
		t.Fatalf("an outage lost %d batches, %d left: the workers drained the backlog into it", lost, left)
	}

	collector.mu.Lock()
	collector.failing = false
	collector.mu.Unlock()
	next, _ := testBatch(1, 0, 2)
	sender.AddBatch(next)
	waitFor(t, "the backlog", func() bool { return collector.logs() == 2*(left+1) })
	sender.mutex.Lock()
	defer sender.mutex.Unlock()
	if sender.logs.Len() != 0 || sender.pendingLogs != 0 {
		t.Fatalf("%d batches left after the backend is back", sender.logs.Len())
	}
}

// TestBackendOutageProbesWithOneBatch: once halted, every later batch makes one send to find out whether the
// backend is back, instead of every worker losing a batch to it
func TestBackendOutageProbesWithOneBatch(t *testing.T) {
	collector := &fakeCollector{failing: true}
	sender := newTestSender(t, collector, common.SenderConfig{Parallelism: 4, MaxLogsPerSend: 2})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender.ctx = ctx
	sender.Start(ctx)

	batch, _ := testBatch(10, 0, 2)
	sender.AddBatch(batch)
	waitFor(t, "the failed sends", func() bool { return sender.sendErrors.Load() > 0 })
	time.Sleep(100 * time.Millisecond)
	first := sender.sendErrors.Load()
	for i := 0; i < 3; i++ {
		next, _ := testBatch(1, 0, 2)
		sender.AddBatch(next)
		want := first + int64(i) + 1
		waitFor(t, "the probe", func() bool { return sender.sendErrors.Load() >= want })
		time.Sleep(100 * time.Millisecond)
		if got := sender.sendErrors.Load(); got != want {
			t.Fatalf("batch %d of the outage: %d failed sends, expected %d (one probe)", i, got, want)
		}
	}
	if lost := sender.lostLogs.Load(); lost != 2*sender.sendErrors.Load() {
		t.Fatalf("%d logs lost in %d failed sends of 2", lost, sender.sendErrors.Load())
	}

	// back: the probe succeeds and every batch left goes
	collector.mu.Lock()
	collector.failing = false
	collector.mu.Unlock()
	sender.mutex.Lock()
	left := sender.logs.Len()
	sender.mutex.Unlock()
	next, _ := testBatch(1, 0, 2)
	sender.AddBatch(next)
	waitFor(t, "the backlog", func() bool { return collector.logs() == 2*(left+1) })
}

// rawFrame is a message of the stream as its bytes, for rawCodec
type rawFrame struct {
	data []byte
}

// rawCodec lets the server see the bytes the agent sends
type rawCodec struct{}

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	return mem.BufferSlice{mem.SliceBuffer(v.(*rawFrame).data)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	v.(*rawFrame).data = data.Materialize()
	return nil
}

func (rawCodec) Name() string {
	return "raw"
}

// rawCollector records the bytes of every message of every stream, and the content type of the streams
type rawCollector struct {
	mu           sync.Mutex
	streams      [][][]byte
	contentTypes []string
}

func (r *rawCollector) handle(_ any, stream grpc.ServerStream) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	var messages [][]byte
	for {
		frame := &rawFrame{}
		err := stream.RecvMsg(frame)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		messages = append(messages, frame.data)
	}
	r.mu.Lock()
	r.streams = append(r.streams, messages)
	r.contentTypes = append(r.contentTypes, md.Get("content-type")...)
	r.mu.Unlock()
	// an empty EBPFAccessLogDownstream
	return stream.SendMsg(&rawFrame{})
}

// TestWireBytesAsTheMessages: the bytes the backend receives are, message by message, proto.Marshal of the
// messages the sender built before it sent pre-encoded logs: the node on the first message of the stream,
// the connection on the first message of every connection, the kernel logs of a connection together (merged),
// and a message per protocol log with its kernel logs, built or encoded straight from the events
func TestWireBytesAsTheMessages(t *testing.T) {
	collector := &rawCollector{}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ForceServerCodecV2(rawCodec{}), grpc.UnknownServiceHandler(collector.handle))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	sender := newGRPCSender(v3.NewEBPFAccessLogServiceClient(conn), common.SenderConfig{Parallelism: 1})
	sender.nodeInfo = corpusNode
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender.ctx = ctx
	sender.Start(ctx)

	// the messages the sender built before, by connection
	legacy := map[string]func(first bool) []*v3.EBPFAccessLogMessage{}
	batch := sender.NewBatch()
	batch.EnableKernelLogMerge()
	for c, rpc := range corpusConnections() {
		connection := testConnection(c)
		rpc.Local = connection.RPCConnection.Local
		connection.RPCConnection = rpc
		var kernels []*v3.AccessLogKernelLog
		// the last connection has only protocol logs
		kernelLogs := corpusKernelLogs()[c:]
		if c == 3 {
			kernelLogs = nil
		}
		for _, k := range kernelLogs {
			kernels = append(kernels, proto.Clone(k).(*v3.AccessLogKernelLog))
			batch.AppendKernelLog(connection, k)
		}
		kernels = forwarder.MergeKernelLogs(kernels)
		var protocolMessages []*v3.EBPFAccessLogMessage
		for i, p := range corpusProtocolLogs()[:4+c] {
			pk := []*v3.AccessLogKernelLog{corpusKernelLogs()[i], corpusKernelLogs()[i+2]}
			batch.AppendProtocolLog(connection, pk, p)
			protocolMessages = append(protocolMessages, &v3.EBPFAccessLogMessage{KernelLogs: pk, ProtocolLog: p})
		}
		// and protocol logs whose kernel logs are encoded straight from the events
		for i, p := range corpusProtocolLogs()[:2+c] {
			details := transferDetails()[3*i : 3*i+4]
			batch.AppendTransferProtocolLog(connection, details, p)
			protocolMessages = append(protocolMessages, &v3.EBPFAccessLogMessage{KernelLogs: builtKernelLogs(details), ProtocolLog: p})
		}
		legacy[rpc.Local.GetIp().GetHost()] = func(first bool) []*v3.EBPFAccessLogMessage {
			var result []*v3.EBPFAccessLogMessage
			if len(kernels) > 0 {
				result = append(result, &v3.EBPFAccessLogMessage{KernelLogs: kernels})
			}
			for _, m := range protocolMessages {
				result = append(result, proto.Clone(m).(*v3.EBPFAccessLogMessage))
			}
			result[0].Connection = rpc
			if first {
				result[0].Node = corpusNode()
			}
			return result
		}
	}
	total := batch.LogCount()
	sender.AddBatch(batch)
	waitFor(t, "the stream", func() bool {
		collector.mu.Lock()
		defer collector.mu.Unlock()
		return len(collector.streams) == 1
	})

	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(collector.contentTypes) != 1 || collector.contentTypes[0] != "application/grpc" {
		t.Fatalf("content type %v", collector.contentTypes)
	}
	received := collector.streams[0]
	logs := 0
	for i := 0; i < len(received); {
		msg := &v3.EBPFAccessLogMessage{}
		if err := proto.Unmarshal(received[i], msg); err != nil {
			t.Fatal(err)
		}
		expected := legacy[msg.GetConnection().GetLocal().GetIp().GetHost()]
		if expected == nil {
			t.Fatalf("message %d does not start a connection: %v", i, msg)
		}
		for _, m := range expected(i == 0) {
			want, err := proto.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if i >= len(received) || !bytes.Equal(received[i], want) {
				t.Fatalf("message %d differs from the message the sender built\nexpected %v", i, m)
			}
			logs += len(m.KernelLogs)
			if m.ProtocolLog != nil {
				// the kernel logs of a protocol log are a part of it
				logs += 1 - len(m.KernelLogs)
			}
			i++
		}
	}
	if logs != total {
		t.Fatalf("%d logs received, %d sent", logs, total)
	}
}

// TestPreEncodedParts: the codec sends the header and the logs of a message as buffers of their own, without
// copying them, and their concatenation is the message
func TestPreEncodedParts(t *testing.T) {
	codec := accessLogCodec{proto: encoding.GetCodecV2("proto")}
	header := []byte{0x12, 0x01, 0x18}
	logs := [][]byte{{0x1a, 0x00}, {0x1a, 0x01, 0x0a}, {0x22, 0x00}}
	for _, c := range []struct {
		header []byte
		logs   [][]byte
	}{{header, logs[:1]}, {nil, logs[:1]}, {header, logs}, {nil, logs}} {
		data, err := codec.Marshal(newPreEncoded(c.header, c.logs))
		if err != nil {
			t.Fatal(err)
		}
		parts := c.logs
		if c.header != nil {
			parts = append([][]byte{c.header}, parts...)
		}
		if len(data) != len(parts) {
			t.Fatalf("%d buffers for %d parts", len(data), len(parts))
		}
		for i, b := range data {
			if &b.ReadOnlyData()[0] != &parts[i][0] {
				t.Fatalf("part %d is copied", i)
			}
		}
		if got, want := data.Materialize(), bytes.Join(parts, nil); !bytes.Equal(got, want) {
			t.Fatalf("sent %x, expected %x", got, want)
		}
	}
}
