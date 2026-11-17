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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The tests below run real h2c traffic with access_log.protocol_analyze.skip_h2c_data_payload off and on.
// With it on, every socket call still sends exactly one event, in order:
// the uploaded calls byte for byte, the skipped ones without content, with the size of the call and the
// function name, L4 counters and ports of their own call, which the agent's kernel logs are built from.
// Which calls the cursor skips with many streams at once, forged frame headers inside a payload and the
// dropping on as well is in h2c_follower_kernel_test.go (TestH2CSkipManyStreams, TestH2CSkipForgedPayload,
// TestH2CSkipWithDropping). They need root and are skipped otherwise.

// uploadRecordHeader is offsetof(struct socket_data_upload_event, buffer) of bpf/accesslog/include
const uploadRecordHeader = 100

// h2cSkipConnStats is what checkSkippedCalls finds, per direction
type h2cSkipConnStats struct {
	skippable, skipped [3]int
	// the calls uploaded up to the DATA payload their end lies in, and those the oracle allows to cut
	cut, cuttable              [3]int
	uploadedBytes, recordBytes [3]int
}

// checkSkippedCalls matches the events of every direction one to one with the real socket calls: an
// uploaded call is its bytes, a skipped one an HTTP/2 event without content whose total size is the size
// of the call, inside the payload of a DATA frame without padding
func checkSkippedCalls(t *testing.T, conn *h2cKernelConn) (stats h2cSkipConnStats) {
	t.Helper()
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		script := &h2cScript{}
		start := 0
		for _, size := range conn.calls[d] {
			script.call(d, conn.real[d][start:start+size], false)
			start += size
		}
		skippable := h2cSkippable(script)
		tailSkippable := h2cTailSkippable(script)
		type call struct {
			data    []byte
			total   uint64
			skipped bool
			// the last chunk is marked as cut: the calls stay below the upload limit (recordingConn), so
			// only a cut DATA payload does that
			cut bool
		}
		var calls []call
		var lastID uint64
		for _, e := range conn.events[d] {
			stats.uploadedBytes[d] += int(e.DataLen)
			stats.recordBytes[d] += uploadRecordHeader + int(e.DataLen)
			if len(calls) > 0 && e.DataID0 == lastID {
				calls[len(calls)-1].data = append(calls[len(calls)-1].data, e.BufferData()...)
				calls[len(calls)-1].cut = e.Finished == 1 && e.HaveReduce == 1
				continue
			}
			skipped := e.PayloadSkipped0 == 1
			if skipped && (e.DataLen != 0 || e.Sequence0 != 0 || e.Finished != 1 || e.HaveReduce != 0 ||
				e.Protocol0 != enums.ConnectionProtocolHTTP2) {
				t.Fatalf("%s %s: the skipped call %d is not an HTTP/2 event without content: %+v", conn.name,
					directionName(d), e.DataID0, *e.Detach())
			}
			calls = append(calls, call{data: append([]byte(nil), e.BufferData()...), total: e.TotalSize0, skipped: skipped,
				cut: e.Finished == 1 && e.HaveReduce == 1})
			lastID = e.DataID0
		}
		if len(calls) != len(script.calls) {
			t.Fatalf("%s %s: %d calls sent events, %d calls were made", conn.name, directionName(d), len(calls), len(script.calls))
		}
		for i, c := range calls {
			realData := script.calls[i].data
			if skippable[i] {
				stats.skippable[d]++
			}
			if tailSkippable[i] > 0 {
				stats.cuttable[d]++
			}
			switch {
			case c.cut && (c.total != uint64(len(realData)) || len(c.data) != tailSkippable[i] || !bytes.Equal(c.data, realData[:len(c.data)])):
				t.Fatalf("%s %s: call %d (%d bytes) is cut behind %d bytes with the size %d, the oracle cuts it behind %d",
					conn.name, directionName(d), i, len(realData), len(c.data), c.total, tailSkippable[i])
			case c.cut:
				stats.cut[d]++
			case !c.skipped && !bytes.Equal(c.data, realData):
				t.Fatalf("%s %s: call %d is not uploaded as its bytes", conn.name, directionName(d), i)
			case c.skipped && (c.total != uint64(len(realData)) || !skippable[i]):
				t.Fatalf("%s %s: call %d (%d bytes) was skipped with the size %d, inside a plain DATA payload: %t",
					conn.name, directionName(d), i, len(realData), c.total, skippable[i])
			case c.skipped:
				stats.skipped[d]++
			}
		}
	}
	return stats
}

// h2cUnskipped is the connection with its skipped and cut calls uploaded with their bytes, in upload chunks:
// the same calls as the run without the skipping would have sent them
func h2cUnskipped(conn *h2cKernelConn) *h2cKernelConn {
	copied := &h2cKernelConn{name: conn.name, port: conn.port, remotePort: conn.remotePort, client: conn.client}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		cut := map[uint64]bool{}
		for _, e := range conn.events[d] {
			if e.Finished == 1 && e.HaveReduce == 1 {
				cut[e.DataID0] = true
			}
		}
		offset, call := 0, -1
		var lastID uint64
		for _, e := range conn.events[d] {
			if call < 0 || e.DataID0 != lastID {
				if call >= 0 {
					offset += conn.calls[d][call]
				}
				call++
				lastID = e.DataID0
			}
			if cut[e.DataID0] && e.Sequence0 != 0 {
				// the whole call is uploaded from its first chunk
				continue
			}
			if e.PayloadSkipped0 != 1 && !cut[e.DataID0] {
				copied.events[d] = append(copied.events[d], e)
				continue
			}
			realData := conn.real[d][offset : offset+conn.calls[d][call]]
			for sent, seq := 0, uint16(0); sent < len(realData); seq++ {
				chunk := min(len(realData)-sent, buffer.MaxEventBufferSize)
				c := e.Detach()
				c.PayloadSkipped0, c.Sequence0, c.DataLen, c.HaveReduce, c.Finished = 0, seq, uint16(chunk), 0, 0
				if len(realData)-sent > buffer.MaxEventBufferSize {
					c.HaveReduce = 1
				}
				if sent+chunk == len(realData) {
					c.Finished = 1
				}
				c.Buffer = append([]byte(nil), realData[sent:sent+chunk]...)
				copied.events[d] = append(copied.events[d], c)
				sent += chunk
			}
		}
	}
	return copied
}

// goH2CBodyTraffic is Go's h2c client and server exchanging bodies of the given sizes both ways on one
// connection, one request after the other. The flow control windows hold a whole body, and each side reads a
// body only once it has arrived, so the credit it returns while reading is never written while its peer's
// frames are still being read. A write made between two reads of one frame names the first of them as its
// previous upload, and the HTTP/2 analyzer then holds the write back until the frame is complete while the
// frame waits for the write: it stalls until the gap wait and loses the frame (see
// TestH2CControlFramesInsideAFrameOfTheOtherDirection). That is independent of the skipping.
func goH2CBodyTraffic(t *testing.T, run *h2cKernelRun, requests, requestBody, responseBody int) {
	const settle = 150 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	body := bytes.Repeat([]byte{'r'}, responseBody)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		//nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
		server := &http2.Server{MaxUploadBufferPerConnection: 4 << 20, MaxUploadBufferPerStream: 1 << 20}
		server.ServeConn(run.record(raw, "server", false), &http2.ServeConnOpts{ //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(settle)
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write(body)
			}),
		})
	}()
	transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) { //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return run.record(raw, "client", true), nil
	}}
	defer transport.CloseIdleConnections() //nolint:staticcheck // the x/net/http2 endpoints make the recorded h2c traffic this test checks
	httpClient := &http.Client{Transport: transport}
	for i := 0; i < requests; i++ {
		resp, err := httpClient.Post(fmt.Sprintf("http://%s/upload/%d", listener.Addr(), i), "application/octet-stream",
			bytes.NewReader(bytes.Repeat([]byte{'q'}, requestBody)))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		time.Sleep(settle)
		n, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if n != int64(responseBody) {
			t.Fatalf("response body %d bytes", n)
		}
	}
}

// TestH2CSkipDataPayload runs Go's h2c client and server with 256KB request and response bodies with
// the skipping off and on. With it on, the events of the skipped calls carry their own details, the
// agent's access logs and kernel logs over them are those of the same calls uploaded with their bytes,
// the access logs match the run without the skipping, and the server uploads next to nothing of the
// request bodies it reads.
func TestH2CSkipDataPayload(t *testing.T) { //nolint:funlen // one scenario whose steps share the loaded BPF and the state of the run
	withH2CSkipDataPayload(t)
	requireBPF(t)
	const requests, bodySize = 16, 256 * 1024
	var summaries [2][]string
	var data, records [2][3]int
	canCompare := true
	for i, skip := range []bool{false, true} {
		run := withAccessLogBPFModes(t, false, skip, func(run *h2cKernelRun) {
			goH2CBodyTraffic(t, run, requests, bodySize, bodySize)
		})
		if !skip {
			verifyKernelRun(t, run)
		}
		for _, conn := range run.conns {
			checkPrevDataIDs(t, conn)
			checkLayoutFields(t, conn)
			stats := checkSkippedCalls(t, conn)
			for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
				t.Logf("  skip=%t %s %s: %d calls, %d skippable, %d skipped, %d cuttable, %d cut; %d data bytes, %d record bytes",
					skip, conn.name, directionName(d), len(conn.calls[d]), stats.skippable[d], stats.skipped[d],
					stats.cuttable[d], stats.cut[d], stats.uploadedBytes[d], stats.recordBytes[d])
				data[i][d] += stats.uploadedBytes[d]
				records[i][d] += stats.recordBytes[d]
			}
			result := analyzeKernelConn(t, conn)
			if skip {
				full := analyzeKernelConn(t, h2cUnskipped(conn))
				assertSameProtos(t, conn.name+" protocol logs", full.protocolLogs, result.protocolLogs)
				if len(full.protocolKernels) != len(result.protocolKernels) {
					t.Fatalf("%s: kernel logs of protocol logs, %d and %d", conn.name, len(full.protocolKernels), len(result.protocolKernels))
				}
				for k := range full.protocolKernels {
					assertSameProtos(t, fmt.Sprintf("%s kernel logs of protocol log %d", conn.name, k), full.protocolKernels[k],
						result.protocolKernels[k])
				}
				assertSameProtos(t, conn.name+" kernel logs without a protocol", full.kernelLogs, result.kernelLogs)
				if full.l4Totals() != result.l4Totals() || fmt.Sprint(full.reportedIDs) != fmt.Sprint(result.reportedIDs) ||
					full.metrics.Gaps != result.metrics.Gaps || result.metrics.FramingErrors > full.metrics.FramingErrors {
					// after a resynchronization the skipped calls behind the dropped one go with it, while
					// their bytes uploaded each count as a framing error: those may only be fewer
					t.Fatalf("%s: the kernel logs differ: L4 %+v and %+v, metrics %+v and %+v", conn.name, full.l4Totals(),
						result.l4Totals(), full.metrics, result.metrics)
				}
				// the server reads every payload apart from its header
				in := enums.SocketDataDirectionIngress
				if !conn.client && stats.uploadedBytes[in]*20 > len(conn.real[in]) {
					t.Fatalf("%s: %d of the %d bytes the server read were still uploaded", conn.name, stats.uploadedBytes[in], len(conn.real[in]))
				}
			}
			// the runs are compared with each other only when both reported every request with its sizes:
			// an endpoint that writes between two reads of a frame of its peer after all stalls the
			// analyzer, which then gives the frame up, independent of the skipping (goH2CBodyTraffic);
			// the run with the skipping is compared exactly above either way
			m := result.metrics
			if m.DecodeErrors != 0 || m.DroppedStreams != 0 {
				t.Fatalf("skip=%t %s: %+v", skip, conn.name, m)
			}
			sizes := fmt.Sprintf("body=%d status=200 resp=%d", bodySize, bodySize)
			clean := m.FramingErrors == 0 && len(result.protocolLogs) == requests
			for _, line := range h2cLogSummary(result, false) {
				clean = clean && strings.HasSuffix(line, sizes)
				summaries[i] = append(summaries[i], line)
			}
			if !clean {
				canCompare = false
				t.Logf("skip=%t %s: %d access logs of %d, %d framing errors, %d gaps: not compared with the other run", skip,
					conn.name, len(result.protocolLogs), requests, m.FramingErrors, m.Gaps)
			}
		}
		sort.Strings(summaries[i])
	}
	if canCompare && fmt.Sprint(summaries[0]) != fmt.Sprint(summaries[1]) {
		t.Fatalf("the access logs differ:\noff %v\non  %v", summaries[0], summaries[1])
	}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		t.Logf("%s of both endpoints: %d data bytes (%d record bytes) without the skipping, %d (%d) with it", directionName(d),
			data[0][d], records[0][d], data[1][d], records[1][d])
	}
	total := func(v [3]int) int { return v[1] + v[2] }
	t.Logf("all: %d data bytes, %d record bytes without the skipping; %d, %d with it: %.1f%%, %.1f%%", total(data[0]),
		total(records[0]), total(data[1]), total(records[1]), 100*float64(total(data[1]))/float64(total(data[0])),
		100*float64(total(records[1]))/float64(total(records[0])))
}
