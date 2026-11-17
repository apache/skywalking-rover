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
	"encoding/binary"
	"fmt"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols"
	"github.com/apache/skywalking-rover/pkg/accesslog/collector/protocols/http1skip"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/accesslog/sender"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"google.golang.org/protobuf/proto"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// The equivalence tests decode the same synthetic HTTP/1 socket calls, as perf records, through the reader
// and the whole analysis of the agent twice, with skip_http1_body_payload off and on, and require the
// access logs to be the same bytes.

// h1Wire is the perf record header of a socket data event, see aclevents.SocketDataUploadEvent.ReadFrom
type h1Wire struct {
	Protocol0          enums.ConnectionProtocol
	HaveReduce         uint8
	L4PackageCount     uint8
	Finished           uint8
	Sequence0          uint16
	DataLen            uint16
	FunctionName       uint32
	SSL                uint8
	Pad0               uint8
	InFlight           uint16
	StartTime0         uint64
	EndTime0           uint64
	ConnectionID       uint64
	RandomID           uint64
	DataID0            uint64
	PrevDataID0        uint64
	TotalSize0         uint64
	L4TotalPackageSize uint64
	Direction0         enums.SocketDataDirection
	PayloadSkipped0    uint8
	LocalPort          uint16
	RemotePort         uint16
	DataIDSpan         uint16
	SumBefore          uint32
	SumStream          uint32
	SumFrames          uint16
	FirstFrameOff      uint16
}

// the upload limits of BPF: the chunk size and the chunks of one call
const (
	h1ChunkSize  = 20480
	h1ChunkLimit = 3
)

// h1Record is one perf record; dropped records are lost before the reader (perf loss or the memory
// protection), the reader then sees a loss
type h1Record struct {
	sample []byte
	// wire and payload make the sample once the data ids are known
	wire    h1Wire
	payload []byte
	conn    uint64
	dropped bool
	// a dropped record the reader can tell the connection of (memory protection), or not (perf loss)
	known bool
	// first is set on the first record of a call
	first bool
	// slot is the ordinal of the call in the traffic: the analysis runs after every few calls, at the same
	// calls whatever records BPF makes of them
	slot int
	// inFlightDirection and inFlightOther: the calls of its direction (itself included) and of the other one
	// in flight as the call returned (BPF loses the direction of a call that overlapped another one of it,
	// and uploads the run a direction holds only when no other call of it is in flight)
	inFlightDirection, inFlightOther int
	// body: the call lies wholly inside a Content-Length body, bodyEnd: it ends the body (what the BPF side
	// skips, see h1Conn.bpfSkip); splitHead: it holds a part of a head that ends in a later call (BPF loses
	// the direction)
	body, bodyEnd, splitHead bool
	// close: a call behind the head of a response delimited by the close
	close bool
}

type h1Expected struct {
	method              string
	status              int
	reqBody, respBody   int
	reqHeader, respHead int
}

type h1Traffic struct {
	records []h1Record
	// merge: the kernel logs of a message are merged (merge_kernel_logs)
	merge bool
	// disturbed are the connections that lost calls or had calls read out of order (lossy)
	disturbed map[uint64]bool
	// expected is the exchanges of every connection, for the traffic without anything unusual
	expected map[uint64][]h1Expected
}

type h1Options struct {
	connections, exchanges int
	// unusual: chunked bodies, HEAD/204/304, bodies holding start tokens or binary bytes, truncated
	// writes, a TLS connection
	unusual bool
	// tiny: heads split into small calls and 100-continue, which the analyzer does not read in step
	tiny bool
	// lossy: calls lost before the reader and calls read out of order
	lossy bool
	// gaps: calls that upload nothing (EAGAIN) take data ids between the calls
	gaps bool
	// overlap: calls that entered (took their data id) before calls that uploaded before them; with
	// overlapReads only reads do, before writes (a reader blocked in a read while the writes of a request go
	// out: a write sends its bytes as it is made, a read gets them as it returns)
	overlap, overlapReads bool
	// maxBody bounds the bodies
	maxBody int
	// bpf: the BPF side skips the calls inside the Content-Length bodies (skip_http1_body_payload_bpf), with
	// coalesce it uploads the consecutive skipped calls of a body as one event (merge_kernel_logs, which
	// the analysis then merges the kernel logs with, with or without bpf)
	bpf, coalesce bool
	// base is the BPF time of the traffic, now when 0
	base uint64
	// chunked: most bodies are chunked
	chunked bool
	// closing: every connection ends with a response delimited by the close (neither Content-Length nor
	// chunked), whose body comes in calls of their own
	closing bool
}

// h1Conn builds the calls of one connection as BPF numbers them
type h1Conn struct {
	id            uint64
	ssl, truncate bool
	calls         [][]h1Record
}

func h1Body(rnd *rand.Rand, n int, unusual bool) []byte {
	b := make([]byte, n)
	kind := 0
	if unusual {
		kind = rnd.Intn(6)
	}
	switch kind {
	case 1: // binary
		rnd.Read(b)
	case 2: // text with start tokens
		for i := range b {
			b[i] = "abcdefghij GET HTTP/1.1 POST xyz\r\n"[rnd.Intn(34)]
		}
	default:
		off := rnd.Intn(26)
		for i := range b {
			b[i] = 'a' + byte((i+off)%26)
		}
	}
	return b
}

// h1ChunkedBody frames the body in chunks of any size (some with an extension, now and then trailers), and
// returns where the data of the chunks is
func h1ChunkedBody(rnd *rand.Rand, body []byte) ([]byte, [][2]int) {
	var out bytes.Buffer
	var data [][2]int
	for len(body) > 0 {
		var n int
		switch rnd.Intn(4) {
		case 0:
			n = 1 + rnd.Intn(100)
		case 1:
			n = 1 + rnd.Intn(4000)
		default:
			n = 1 + rnd.Intn(30000)
		}
		n = min(len(body), n)
		fmt.Fprintf(&out, "%x", n)
		if rnd.Intn(8) == 0 {
			out.WriteString(";name=value")
		}
		out.WriteString("\r\n")
		data = append(data, [2]int{out.Len(), out.Len() + n})
		out.Write(body[:n])
		out.WriteString("\r\n")
		body = body[n:]
	}
	out.WriteString("0\r\n")
	if rnd.Intn(6) == 0 {
		out.WriteString("X-Checksum: 1234\r\n")
	}
	out.WriteString("\r\n")
	return out.Bytes(), data
}

// h1Shift moves byte ranges by off
func h1Shift(ranges [][2]int, off int) [][2]int {
	shifted := make([][2]int, len(ranges))
	for i, r := range ranges {
		shifted[i] = [2]int{r[0] + off, r[1] + off}
	}
	return shifted
}

func h1BodyLen(rnd *rand.Rand, maxBody int) int {
	switch rnd.Intn(10) {
	case 0:
		return 0
	case 1, 2, 3:
		return rnd.Intn(min(2000, maxBody) + 1)
	case 4, 5, 6, 7:
		return rnd.Intn(min(64<<10, maxBody) + 1)
	default:
		return rnd.Intn(maxBody + 1)
	}
}

// split cuts a message into the sizes of the socket calls that carry it: whole heads, or random cuts
// down to single bytes
func h1Split(rnd *rand.Rand, msg []byte, headLen int, tiny bool) []int {
	var sizes []int
	left := len(msg)
	if !tiny && headLen > 0 {
		// the head in one call, with or without the first body bytes
		first := headLen
		if rnd.Intn(3) == 0 {
			first += rnd.Intn(min(left-headLen, 4096) + 1)
		}
		sizes = append(sizes, first)
		left -= first
	}
	for left > 0 {
		var n int
		switch {
		case tiny && rnd.Intn(4) == 0:
			n = 1 + rnd.Intn(20)
		case rnd.Intn(3) == 0:
			n = 4096 + rnd.Intn(4097)
		default:
			n = 1 + rnd.Intn(h1ChunkSize)
		}
		n = min(n, left)
		sizes = append(sizes, n)
		left -= n
	}
	return sizes
}

// call adds one socket call of the bytes, uploaded as BPF does: up to h1ChunkLimit chunks, the bytes
// behind them not uploaded (truncated)
func (c *h1Conn) call(dir enums.SocketDataDirection, data []byte) {
	funcName := enums.SocketFunctionNameRead
	if dir == enums.SocketDataDirectionEgress {
		funcName = enums.SocketFunctionNameWrite
	}
	uploaded := data
	if len(uploaded) > h1ChunkSize*h1ChunkLimit {
		uploaded = uploaded[:h1ChunkSize*h1ChunkLimit]
	}
	var records []h1Record
	for seq := 0; len(uploaded) > 0 || seq == 0; seq++ {
		n := min(len(uploaded), h1ChunkSize)
		chunk := uploaded[:n]
		uploaded = uploaded[n:]
		finished := len(uploaded) == 0
		wire := h1Wire{Protocol0: enums.ConnectionProtocolHTTP, Sequence0: uint16(seq), DataLen: uint16(n),
			FunctionName: uint32(funcName), ConnectionID: c.id, RandomID: 1, TotalSize0: uint64(len(data)),
			L4PackageCount: uint8(1 + len(data)/1448%200), L4TotalPackageSize: uint64(len(data)) + 66, Direction0: dir}
		if c.ssl {
			wire.SSL = 1
		}
		if finished {
			wire.Finished = 1
			if len(data) > h1ChunkSize*h1ChunkLimit {
				wire.HaveReduce = 1
			}
		}
		records = append(records, h1Record{wire: wire, payload: chunk, conn: c.id, first: seq == 0})
		if finished {
			break
		}
	}
	c.calls = append(c.calls, records)
}

// number gives the calls their data ids, previous data ids and times as BPF does: the data id when a
// call enters, in the order of entry, the previous data id when it uploads, in the order of the calls. With
// overlap, some calls entered a few calls before they upload; with gaps, calls that upload nothing take
// data ids in between.
func (c *h1Conn) number(rnd *rand.Rand, base uint64, o h1Options) {
	entry := make([]int, len(c.calls)) // the calls in the order they entered
	for i := range entry {
		entry[i] = i
	}
	if o.overlap {
		for j := 1; j < len(entry); j++ {
			if rnd.Intn(25) != 0 {
				continue
			}
			k := min(j, 1+rnd.Intn(3))
			moved := entry[j]
			if o.overlapReads {
				// a read posted before writes: it jumps over writes only
				readOverWrites := c.calls[moved][0].wire.Direction0 == enums.SocketDataDirectionIngress
				for _, e := range entry[j-k : j] {
					readOverWrites = readOverWrites && c.calls[e][0].wire.Direction0 == enums.SocketDataDirectionEgress
				}
				if !readOverWrites {
					continue
				}
			}
			copy(entry[j-k+1:j+1], entry[j-k:j])
			entry[j-k] = moved
		}
	}
	ids := make([]uint64, len(c.calls))
	starts := make([]uint64, len(c.calls))
	gapBefore := make([]bool, len(c.calls))
	id := uint64(0)
	for at, i := range entry {
		id++
		if o.gaps {
			skipped := uint64(rnd.Intn(3))
			id += skipped
			gapBefore[i] = skipped > 0
		}
		ids[i], starts[i] = id, base+uint64(at+1)*1000+c.id
	}
	// the calls in flight as each one returns, as BPF counts them: a call enters right before the first
	// return that needs it to have entered (the entry order), and leaves when it returns (the upload order).
	// A call that uploads nothing (gaps) entered right before the next call, and now and then is still in
	// flight as that one returns.
	position := make([]int, len(c.calls))
	for at, i := range entry {
		position[i] = at
	}
	inFlight := make([]uint16, len(c.calls))
	entered := 0
	for i := range c.calls {
		for entered <= position[i] {
			entered++
		}
		inFlight[i] = uint16(entered - i)
		same := 0
		for _, j := range entry[:entered] {
			if j >= i && c.calls[j][0].wire.Direction0 == c.calls[i][0].wire.Direction0 {
				same++
			}
		}
		if gapBefore[i] && rnd.Intn(4) == 0 {
			inFlight[i]++
		}
		for r := range c.calls[i] {
			c.calls[i][r].inFlightDirection, c.calls[i][r].inFlightOther = same, int(inFlight[i])-same
		}
	}
	prev := uint64(0)
	for i, records := range c.calls {
		// a call returns in its turn (the upload order), after it entered
		end := base + uint64(i+1)*1000 + 600 + records[0].wire.TotalSize0%300 + c.id
		start := min(starts[i], end-100)
		for r := range records {
			w := &records[r].wire
			w.DataID0, w.PrevDataID0, w.StartTime0, w.EndTime0, w.InFlight = ids[i], prev, start, end, inFlight[i]
			records[r].sample = h1Sample(&records[r].wire, records[r].payload)
		}
		prev = ids[i]
	}
}

// bpfSkip makes of the numbered calls what the BPF side uploads with skip_http1_body_payload_bpf: a call
// wholly inside a Content-Length body that returned alone on its fd is uploaded without its content, while
// the direction is followed (now and then a direction is lost for good, as when the cursor cannot read a
// head); with coalesce the consecutive skipped calls of a body are held and uploaded as one event, when the
// body is complete, before any other call of the connection uploads (when no other call of the direction of
// the run is in flight), or at the close.
// The previous data ids are the ones BPF gives: the last upload, which a held call is not. Every call keeps
// its slot (the records uploaded at its return, maybe none), so the interleaving is the same as without.
func (c *h1Conn) bpfSkip(rnd *rand.Rand, o h1Options) {
	if c.ssl {
		// TLS: never followed
		return
	}
	var lost [3]bool
	var short [3]bool
	last := uint64(0)
	var run []h1Record // the first records of the held calls
	var runPrev uint64
	flush := func() []h1Record {
		if len(run) == 0 {
			return nil
		}
		w := run[0].wire
		for _, r := range run[1:] {
			w.TotalSize0 += r.wire.TotalSize0
			w.L4PackageCount += r.wire.L4PackageCount
			w.L4TotalPackageSize += r.wire.L4TotalPackageSize
		}
		end := run[len(run)-1].wire
		for _, r := range run {
			w.EndTime0 = max(w.EndTime0, r.wire.EndTime0)
		}
		w.DataID0, w.DataIDSpan, w.PrevDataID0 = end.DataID0, uint16(end.DataID0-w.DataID0), runPrev
		last = max(last, end.DataID0)
		run = nil
		return []h1Record{h1BPFSkipped(w, c.id)}
	}
	for i, records := range c.calls {
		first := records[0]
		w := first.wire
		alone := w.InFlight == 1
		dir := w.Direction0
		if rnd.Intn(3000) == 0 || first.inFlightDirection != 1 || first.splitHead {
			lost[dir] = true
		}
		if dir == enums.SocketDataDirectionIngress && w.DataID0 < last {
			// a read that uploads after a call with a larger data id: the connection is not followed anymore
			lost = [3]bool{true, true, true}
		}
		skip := first.body && alone && !lost[dir]
		if first.close {
			// the rest of a response delimited by the close: skipped where the analyzer does not look for a message
			// start in it (h1_follow, H1_CLOSE)
			startsMessage := false
			for _, m := range []string{"GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "CONNECT", "TRACE", "PATCH", "HTTP"} {
				startsMessage = startsMessage || bytes.HasPrefix(first.payload, []byte(m))
			}
			skip = alone && !lost[dir] && w.TotalSize0 >= 16 && !short[dir] && !startsMessage
			short[dir] = w.TotalSize0 < 16
		}
		var slot []h1Record
		mayFlush := first.inFlightOther == 0
		if len(run) > 0 && run[0].wire.Direction0 == dir {
			mayFlush = first.inFlightDirection == 1
		}
		if len(run) > 0 && mayFlush {
			head := run[0].wire
			packages := int(w.L4PackageCount)
			for _, r := range run {
				packages += int(r.wire.L4PackageCount)
			}
			// what h1_hold and upload_data_args_ext_coalesce require of a call that joins the run
			joins := skip && o.coalesce && dir == head.Direction0 && w.FunctionName == head.FunctionName && len(run) < 255 &&
				last == runPrev &&
				host.SameMinute(head.StartTime0, w.StartTime0) && w.DataID0-head.DataID0 <= 0xffff && packages <= 255
			if !joins {
				slot = append(slot, flush()...)
			}
		}
		switch {
		case skip && o.coalesce && !first.close:
			if len(run) == 0 {
				runPrev = last
			}
			run = append(run, first)
			if first.bodyEnd {
				slot = append(slot, flush()...)
			}
		case skip:
			if len(run) > 0 {
				last = max(last, run[len(run)-1].wire.DataID0) // h1_reserve_run
			}
			w.PrevDataID0 = last
			slot = append(slot, h1BPFSkipped(w, c.id))
			last = w.DataID0
		default:
			if len(run) > 0 {
				// a held run it may not upload: its previous data id names the run (h1_reserve_run)
				last = max(last, run[len(run)-1].wire.DataID0)
			}
			for _, r := range records {
				r.wire.PrevDataID0 = last
				r.sample = h1Sample(&r.wire, r.payload)
				slot = append(slot, r)
			}
			last = w.DataID0
		}
		if i == len(c.calls)-1 {
			// the close
			slot = append(slot, flush()...)
		}
		c.calls[i] = slot
	}
}

// h1BPFSkipped is the record of a call (or a run of calls) BPF uploaded without its content
func h1BPFSkipped(w h1Wire, conn uint64) h1Record {
	w.Sequence0, w.DataLen, w.Finished, w.HaveReduce, w.PayloadSkipped0 = 0, 0, 1, 0, 1
	return h1Record{wire: w, sample: h1Sample(&w, nil), conn: conn, first: true}
}

func h1Sample(wire *h1Wire, payload []byte) []byte {
	var sample bytes.Buffer
	if err := binary.Write(&sample, binary.LittleEndian, wire); err != nil {
		panic(err)
	}
	sample.Write(payload)
	return sample.Bytes()
}

// message adds the calls of a message whose head is the first headLen bytes; data is where the bytes of the
// body are that the analyzer counts without reading them (the Content-Length body, the data of the chunks)
func (c *h1Conn) message(rnd *rand.Rand, dir enums.SocketDataDirection, msg []byte, headLen int, tiny bool, data [][2]int) {
	off := 0
	for _, n := range h1Split(rnd, msg, headLen, tiny) {
		// a write of a big response goes out in one call, which BPF truncates
		if dir == enums.SocketDataDirectionEgress && c.truncate && rnd.Intn(20) == 0 {
			n = len(msg)
		}
		c.call(dir, msg[:n])
		records := c.calls[len(c.calls)-1]
		for r := range records {
			for _, d := range data {
				if off >= d[0] && off+n <= d[1] && n > 0 {
					records[r].body, records[r].bodyEnd = true, off+n == d[1]
				}
			}
			records[r].splitHead = off < headLen && off+n < headLen
		}
		off += n
		msg = msg[n:]
		if len(msg) == 0 {
			break
		}
	}
}

func h1GenerateTraffic(seed int64, o h1Options) *h1Traffic {
	rnd := rand.New(rand.NewSource(seed))
	base := o.base
	if base == 0 {
		base = bpfNow()
	}
	traffic := &h1Traffic{expected: make(map[uint64][]h1Expected), disturbed: map[uint64]bool{}}
	conns := make([]*h1Conn, o.connections)
	for i := range conns {
		conns[i] = &h1Conn{id: uint64(100 + i), truncate: o.unusual}
	}
	if o.unusual {
		conns[0].ssl = true
	}
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	for i := 0; i < o.exchanges; i++ {
		c := conns[rnd.Intn(len(conns))]
		tiny := o.tiny && rnd.Intn(4) == 0
		method, reqLen := "POST", h1BodyLen(rnd, o.maxBody)
		reqChunked, expect := false, false
		if o.unusual {
			switch rnd.Intn(8) {
			case 0:
				method, reqLen = "GET", -1
			case 1:
				method, reqLen = "HEAD", -1
			case 2:
				reqChunked = true
			case 3:
				expect = o.tiny
			}
		}
		if o.chunked && reqLen >= 0 && rnd.Intn(3) != 0 {
			reqChunked = true
		}
		reqBody := []byte(nil)
		var reqData, respData [][2]int // where the body data is (BPF skips calls wholly inside)
		head := fmt.Sprintf("%s /orders/%d HTTP/1.1\r\nHost: orders:8080\r\nUser-Agent: test\r\n", method, i)
		if reqLen >= 0 {
			reqBody = h1Body(rnd, reqLen, o.unusual)
			if reqChunked {
				head += "Transfer-Encoding: chunked\r\n"
				reqBody, reqData = h1ChunkedBody(rnd, reqBody)
			} else {
				head += fmt.Sprintf("Content-Length: %d\r\n", reqLen)
			}
			if expect {
				head += "Expect: 100-continue\r\n"
			}
		}
		head += "\r\n"
		if reqLen > 0 && !reqChunked {
			reqData = [][2]int{{0, len(reqBody)}}
		}
		if expect {
			c.message(rnd, in, []byte(head), len(head), tiny, nil)
			c.call(out, []byte("HTTP/1.1 100 Continue\r\n\r\n"))
			c.message(rnd, in, reqBody, 0, tiny, reqData)
		} else {
			c.message(rnd, in, append([]byte(head), reqBody...), len(head), tiny, h1Shift(reqData, len(head)))
		}

		status, respLen, respChunked := 200, h1BodyLen(rnd, o.maxBody), false
		if o.unusual {
			switch rnd.Intn(8) {
			case 0:
				status = []int{204, 304}[rnd.Intn(2)]
			case 1:
				respChunked = true
			}
		}
		if o.chunked && status == 200 && rnd.Intn(3) != 0 {
			respChunked = true
		}
		rhead := fmt.Sprintf("HTTP/1.1 %d X\r\nContent-Type: text/plain\r\n", status)
		respBody := h1Body(rnd, respLen, o.unusual)
		switch {
		case respChunked:
			rhead += "Transfer-Encoding: chunked\r\n"
			respBody, respData = h1ChunkedBody(rnd, respBody)
		case status != 200:
			respBody = nil
		default:
			rhead += fmt.Sprintf("Content-Length: %d\r\n", respLen)
		}
		if method == "HEAD" {
			respBody = nil
		}
		rhead += "Date: Mon, 09 Nov 2026 10:00:00 GMT\r\n\r\n"
		if !respChunked && len(respBody) > 0 {
			respData = [][2]int{{0, len(respBody)}}
		}
		if respBody == nil {
			respData = nil
		}
		c.message(rnd, out, append([]byte(rhead), respBody...), len(rhead), tiny, h1Shift(respData, len(rhead)))
		traffic.expected[c.id] = append(traffic.expected[c.id], h1Expected{method: method, status: status,
			reqBody: max(reqLen, 0), respBody: len(respBody), reqHeader: len(head), respHead: len(rhead)})
	}

	if o.closing {
		for i, c := range conns {
			c.message(rnd, in, []byte(fmt.Sprintf("GET /stream/%d HTTP/1.1\r\nHost: orders:8080\r\n\r\n", i)), 0, false, nil)
			rhead := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
			c.message(rnd, out, append([]byte(rhead), h1Body(rnd, 100+rnd.Intn(5000), o.unusual)...), len(rhead), false, nil)
			for k := 0; k < 3+rnd.Intn(20); k++ {
				size := []int{1, 9, 15, 16, 17, 100, 3000, 20000}[rnd.Intn(8)]
				c.call(out, h1Body(rnd, size, o.unusual))
				records := c.calls[len(c.calls)-1]
				for r := range records {
					records[r].close = true
				}
			}
		}
	}
	for _, c := range conns {
		c.number(rnd, base, o)
	}
	traffic.merge = o.coalesce
	if o.bpf {
		// what BPF does is drawn apart, so the traffic is the same as without
		bpfRnd := rand.New(rand.NewSource(seed * 7919))
		for _, c := range conns {
			c.bpfSkip(bpfRnd, o)
		}
	}
	// interleave the connections; with lossy, lose some calls and swap some neighbours of a connection
	slot := 0
	for {
		var pending []*h1Conn
		for _, c := range conns {
			if len(c.calls) > 0 {
				pending = append(pending, c)
			}
		}
		if len(pending) == 0 {
			break
		}
		c := pending[rnd.Intn(len(pending))]
		if o.lossy && len(c.calls) > 1 && rnd.Intn(150) == 0 {
			c.calls[0], c.calls[1] = c.calls[1], c.calls[0]
			traffic.disturbed[c.id] = true
		}
		// the records of a slot: one call, or what BPF uploads as it returns (none for a call it holds)
		calls := c.calls[0]
		c.calls = c.calls[1:]
		dropped, known := o.lossy && rnd.Intn(300) == 0, rnd.Intn(2) == 0
		if dropped {
			traffic.disturbed[c.id] = true
		}
		for _, r := range calls {
			r.dropped, r.known, r.slot = dropped, known, slot
			traffic.records = append(traffic.records, r)
		}
		slot++
	}
	return traffic
}

// h1Output is one message the analysis hands to the sender
type h1Output struct {
	encoded  []byte
	protocol *v3.AccessLogProtocolLogs
	conn     uint64
	// kernel describes the kernel logs of a protocol log, for the failure messages
	kernel string
}

type h1RunResult struct {
	outputs []h1Output
	// skipped: the records the reader decoded without their bytes, bpfSkipped: those BPF uploaded without
	// them (bpfBytes: the bytes of the calls these stand for)
	skipped, bpfSkipped, bpfBytes int
	records                       int
	conflicts                     int64
}

// h1SkipRun decodes the records with skip_http1_body_payload on or off and analyzes every connection
// after every `every` records, in a fixed order
func h1SkipRun(t *testing.T, traffic *h1Traffic, skip bool, every int) *h1RunResult {
	t.Helper()
	http1skip.ResetRegistry()
	ctx := &common.AccessLogContext{
		Queue:         common.NewQueue(1000000, time.Hour, h2cNoopConsumer{}),
		ConnectionMgr: h2cTestConnectionManager(),
		Config:        &common.Config{},
	}
	ctx.Config.ProtocolAnalyze.SkipHTTP1BodyPayload = skip
	common.SetMergeKernelLogs(traffic.merge)
	defer common.SetMergeKernelLogs(false)
	analyzer := protocols.NewHTTP1Analyzer(ctx, NewHTTP1Analyze(nil, ctx))
	partition := NewPartitionContext(ctx, protocols.NewPartitionContext(ctx, 0, []protocols.Protocol{analyzer}))
	var epoch uint64
	var dropped func([]byte)
	if skip {
		tracker := http1skip.NewTracker(aclevents.InlineDataSize + 1)
		tracker.LossEpoch = func() uint64 { return epoch }
		aclevents.SetHTTP1BodySkipper(tracker)
		defer aclevents.SetHTTP1BodySkipper(nil)
		dropped = aclevents.DroppedSampleObserver(tracker)
	}
	conflicts := buffer.BodySkipConflicts()
	result := &h1RunResult{}
	var order []uint64
	known := map[uint64]*protocols.PartitionConnection{}
	analyze := func() {
		for _, id := range order {
			if err := analyzer.Analyze(known[id], &protocols.AnalyzeHelper{}); err != nil {
				t.Fatalf("analyze: %v", err)
			}
		}
		h1Collect(t, ctx.Queue, result)
	}
	reader := &btf.BytesReader{}
	slot := 0
	for _, r := range traffic.records {
		// the slots before this record are complete
		for ; slot < r.slot; slot++ {
			if (slot+1)%every == 0 {
				analyze()
			}
		}
		if r.dropped {
			switch {
			case r.known && dropped != nil:
				dropped(r.sample)
			case r.first:
				epoch++
			}
			continue
		}
		event := &aclevents.SocketDataUploadEvent{}
		reader.Reset(r.sample)
		event.ReadFrom(reader)
		if err := reader.HasError(); err != nil {
			t.Fatalf("decode: %v", err)
		}
		result.records++
		if event.PayloadSkipped0 == 1 {
			result.bpfSkipped++
			result.bpfBytes += int(event.TotalSize0)
			if event.Buffer != nil || event.BufferLen() != 0 {
				t.Fatalf("an event BPF uploaded without its content holds data")
			}
		} else if event.PayloadSkipped() {
			result.skipped++
			if event.Buffer != nil || event.BufferLen() != int(event.DataLen) || !event.BodyPayloadSkipped() {
				t.Fatalf("a skipped event holds data or lost its length")
			}
		}
		partition.Consume(event)
		if _, ok := known[r.conn]; !ok {
			order = append(order, r.conn)
			known[r.conn] = partition.GetConnectionContext(event.ConnectionID, event.RandomID, event.Protocol0, event.DataID0)
		}
	}
	analyze()
	analyze()
	result.conflicts = buffer.BodySkipConflicts() - conflicts
	return result
}

func h1Collect(t *testing.T, q *common.Queue, result *h1RunResult) {
	t.Helper()
	kernels, protocolLogs := h2cDrainQueue(q)
	for _, p := range protocolLogs {
		details := p.RelateKernelLogs()
		encoded, _, err := sender.EncodeTransferProtocolLog(details, p.ProtocolLog())
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		conn := uint64(0)
		if len(details) > 0 {
			conn = details[0].GetConnectionID()
		}
		var kernel strings.Builder
		for _, d := range details {
			fmt.Fprintf(&kernel, "[%s %d-%d l4=%d/%d] ", d.GetFunctionName(), d.GetStartTime(), d.GetEndTime(),
				d.GetL4PackageCount(), d.GetL4TotalPackageSize())
		}
		result.outputs = append(result.outputs, h1Output{encoded: append([]byte("P"), encoded...), protocol: p.ProtocolLog(),
			conn: conn, kernel: kernel.String()})
	}
	for _, k := range kernels {
		log := forwarder.BuildKernelLogFromEvent(k.Type(), k.Event())
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(log)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		result.outputs = append(result.outputs, h1Output{encoded: append([]byte("K"), encoded...), conn: k.Event().GetConnectionID()})
	}
}

func h1AssertSameOutputs(t *testing.T, what string, off, on []h1Output) {
	t.Helper()
	for i := 0; i < min(len(off), len(on)); i++ {
		if !bytes.Equal(off[i].encoded, on[i].encoded) {
			t.Fatalf("%s: output %d differs\noff %v\n    %s\non  %v\n    %s", what, i, off[i].protocol, off[i].kernel,
				on[i].protocol, on[i].kernel)
		}
	}
	if len(off) != len(on) {
		t.Fatalf("%s: %d outputs off, %d on", what, len(off), len(on))
	}
}

// h1AssertExpected checks the protocol logs of traffic without anything unusual against the exchanges
func h1AssertExpected(t *testing.T, traffic *h1Traffic, outputs []h1Output) {
	t.Helper()
	got := map[uint64][]h1Expected{}
	for _, o := range outputs {
		if o.protocol == nil {
			t.Fatalf("a kernel log without protocol")
		}
		h := o.protocol.GetHttp()
		got[o.conn] = append(got[o.conn], h1Expected{method: strings.ToUpper(h.Request.Method.String()),
			status: int(h.Response.StatusCode), reqBody: int(h.Request.SizeOfBodyBytes), respBody: int(h.Response.SizeOfBodyBytes),
			reqHeader: int(h.Request.SizeOfHeadersBytes), respHead: int(h.Response.SizeOfHeadersBytes)})
	}
	for conn, want := range traffic.expected {
		if fmt.Sprint(got[conn]) != fmt.Sprint(want) {
			t.Fatalf("connection %d:\ngot  %v\nwant %v", conn, got[conn], want)
		}
	}
}

func TestHTTP1BodySkipKeepsTheAccessLogs(t *testing.T) {
	scenarios := []struct {
		name string
		seed int64
		o    h1Options
	}{
		{"keep-alive", 1, h1Options{connections: 5, exchanges: 120, maxBody: 1 << 20}},
		{"unusual", 2, h1Options{connections: 6, exchanges: 200, maxBody: 300 << 10, unusual: true}},
		{"unusual-lossy", 3, h1Options{connections: 4, exchanges: 200, maxBody: 300 << 10, unusual: true, lossy: true}},
		{"tiny", 4, h1Options{connections: 6, exchanges: 160, maxBody: 300 << 10, unusual: true, tiny: true}},
		{"tiny-lossy", 5, h1Options{connections: 3, exchanges: 160, maxBody: 100 << 10, unusual: true, tiny: true, lossy: true}},
		{"keep-alive-gaps", 6, h1Options{connections: 5, exchanges: 120, maxBody: 300 << 10, gaps: true}},
		{"overlap", 7, h1Options{connections: 4, exchanges: 160, maxBody: 300 << 10, overlap: true}},
		{"overlap-unusual-gaps", 8, h1Options{connections: 4, exchanges: 160, maxBody: 100 << 10, unusual: true, tiny: true, gaps: true, overlap: true}},
	}
	for _, s := range scenarios {
		traffic := h1GenerateTraffic(s.seed, s.o)
		for _, every := range []int{1, 5, 37, 1 << 30} {
			name := fmt.Sprintf("%s every %d", s.name, every)
			off := h1SkipRun(t, traffic, false, every)
			on := h1SkipRun(t, traffic, true, every)
			if off.skipped != 0 {
				t.Fatalf("%s: skipped with the switch off", name)
			}
			if on.conflicts != 0 {
				t.Fatalf("%s: %d reads wanted skipped bytes", name, on.conflicts)
			}
			h1AssertSameOutputs(t, name, off.outputs, on.outputs)
			if len(off.outputs) == 0 {
				t.Fatalf("%s: no output", name)
			}
			t.Logf("%s: %d records, %d skipped, %d outputs", name, on.records, on.skipped, len(on.outputs))
			switch {
			case s.o.gaps && !s.o.overlap && !s.o.unusual:
				// data ids that never come: the calls in flight prove them done
				if on.skipped*10 < on.records*5 {
					t.Fatalf("%s: only %d of %d records skipped", name, on.skipped, on.records)
				}
			case s.o.gaps:
			case !s.o.unusual && !s.o.overlap:
				h1AssertExpected(t, traffic, off.outputs)
				// everything but the heads and the short last calls of the bodies
				if on.skipped*10 < on.records*7 {
					t.Fatalf("%s: only %d of %d records skipped", name, on.skipped, on.records)
				}
			case on.skipped == 0:
				t.Fatalf("%s: nothing skipped", name)
			}
		}
	}
}

// TestHTTP1BodySkipRace decodes on one goroutine and analyzes on another, as the reader, the partition
// and the analysis do, and requires the logs of both runs to be the expected ones
func TestHTTP1BodySkipRace(t *testing.T) {
	traffic := h1GenerateTraffic(9, h1Options{connections: 8, exchanges: 120, maxBody: 300 << 10})
	var results [2][]string
	for i, skip := range []bool{false, true} {
		outputs := h1SkipRunConcurrently(t, traffic, skip)
		h1AssertExpected(t, traffic, outputs)
		for _, o := range outputs {
			results[i] = append(results[i], string(o.encoded))
		}
		sort.Strings(results[i])
	}
	if fmt.Sprint(results[0]) != fmt.Sprint(results[1]) {
		t.Fatalf("the logs differ")
	}
}

func h1SkipRunConcurrently(t *testing.T, traffic *h1Traffic, skip bool) []h1Output {
	http1skip.ResetRegistry()
	ctx := &common.AccessLogContext{
		Queue:         common.NewQueue(1000000, time.Hour, h2cNoopConsumer{}),
		ConnectionMgr: h2cTestConnectionManager(),
		Config:        &common.Config{},
	}
	ctx.Config.ProtocolAnalyze.SkipHTTP1BodyPayload = skip
	analyzer := protocols.NewHTTP1Analyzer(ctx, NewHTTP1Analyze(nil, ctx))
	partition := NewPartitionContext(ctx, protocols.NewPartitionContext(ctx, 0, []protocols.Protocol{analyzer}))
	if skip {
		aclevents.SetHTTP1BodySkipper(http1skip.NewTracker(aclevents.InlineDataSize + 1))
		defer aclevents.SetHTTP1BodySkipper(nil)
	}
	var mutex sync.Mutex
	var conns []*protocols.PartitionConnection
	events := make(chan *aclevents.SocketDataUploadEvent, 64)
	done := make(chan struct{})
	// the reader
	go func() {
		reader := &btf.BytesReader{}
		for _, r := range traffic.records {
			event := &aclevents.SocketDataUploadEvent{}
			reader.Reset(r.sample)
			event.ReadFrom(reader)
			events <- event
		}
		close(events)
	}()
	// the partition
	go func() {
		defer close(done)
		seen := map[uint64]bool{}
		for event := range events {
			partition.Consume(event)
			if !seen[event.ConnectionID] {
				seen[event.ConnectionID] = true
				mutex.Lock()
				conns = append(conns, partition.GetConnectionContext(event.ConnectionID, event.RandomID, event.Protocol0, event.DataID0))
				mutex.Unlock()
			}
		}
	}()
	result := &h1RunResult{}
	analyze := func() {
		mutex.Lock()
		current := append([]*protocols.PartitionConnection(nil), conns...)
		mutex.Unlock()
		for _, c := range current {
			if err := analyzer.Analyze(c, &protocols.AnalyzeHelper{}); err != nil {
				t.Errorf("analyze: %v", err)
			}
		}
		h1Collect(t, ctx.Queue, result)
	}
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			analyze()
		}
	}
	analyze()
	analyze()
	return result.outputs
}

// TestHTTP1BodySkipRandomTraffic runs random mixes of the traffic and analysis schedules
func TestHTTP1BodySkipRandomTraffic(t *testing.T) {
	seeds := 80
	if testing.Short() {
		seeds = 15
	}
	records, skipped := 0, 0
	for seed := int64(100); seed < int64(100+seeds); seed++ {
		rnd := rand.New(rand.NewSource(seed))
		o := h1Options{connections: 1 + rnd.Intn(6), exchanges: 20 + rnd.Intn(60), maxBody: []int{2000, 30000, 300 << 10}[rnd.Intn(3)],
			unusual: rnd.Intn(4) != 0, tiny: rnd.Intn(3) == 0, lossy: rnd.Intn(3) == 0, gaps: rnd.Intn(4) == 0, overlap: rnd.Intn(3) == 0}
		traffic := h1GenerateTraffic(seed, o)
		every := []int{1, 2, 3, 7, 19, 1 << 30}[rnd.Intn(6)]
		name := fmt.Sprintf("seed %d %+v every %d", seed, o, every)
		off := h1SkipRun(t, traffic, false, every)
		on := h1SkipRun(t, traffic, true, every)
		if on.conflicts != 0 {
			t.Fatalf("%s: %d reads wanted skipped bytes", name, on.conflicts)
		}
		h1AssertSameOutputs(t, name, off.outputs, on.outputs)
		if !o.gaps {
			records, skipped = records+on.records, skipped+on.skipped
		}
	}
	if skipped*5 < records {
		t.Fatalf("only %d of %d records skipped", skipped, records)
	}
}

// h1Call is one single chunk socket call of connection 500, uploaded in the order of the list
type h1Call struct {
	id, prev uint64
	dir      enums.SocketDataDirection
	data     string
}

func h1CallTraffic(calls []h1Call) *h1Traffic {
	return h1CallTrafficInFlight(calls, nil)
}

// h1CallTrafficInFlight is h1CallTraffic with the calls of the fd in flight as each call returned (none
// known without)
func h1CallTrafficInFlight(calls []h1Call, inFlight []uint16) *h1Traffic {
	base := bpfNow()
	traffic := &h1Traffic{expected: map[uint64][]h1Expected{}}
	for i, c := range calls {
		fn := enums.SocketFunctionNameRead
		if c.dir == enums.SocketDataDirectionEgress {
			fn = enums.SocketFunctionNameWrite
		}
		start := base + c.id*1000
		wire := h1Wire{Protocol0: enums.ConnectionProtocolHTTP, DataLen: uint16(len(c.data)), Finished: 1,
			FunctionName: uint32(fn), StartTime0: start, EndTime0: start + 300 + uint64(i),
			ConnectionID: 500, RandomID: 1, DataID0: c.id, PrevDataID0: c.prev, TotalSize0: uint64(len(c.data)),
			L4PackageCount: 1, L4TotalPackageSize: uint64(len(c.data)) + 66, Direction0: c.dir}
		if inFlight != nil {
			wire.InFlight = inFlight[i]
		}
		traffic.records = append(traffic.records, h1Record{sample: h1Sample(&wire, []byte(c.data)), conn: 500, first: true, slot: i})
	}
	return traffic
}

func h1AssertSameForSchedules(t *testing.T, name string, traffic *h1Traffic) (skipped int) {
	t.Helper()
	for _, every := range []int{1, 2, 3, 1 << 30} {
		what := fmt.Sprintf("%s every %d", name, every)
		off := h1SkipRun(t, traffic, false, every)
		on := h1SkipRun(t, traffic, true, every)
		if on.conflicts != 0 {
			t.Fatalf("%s: %d reads wanted skipped bytes", what, on.conflicts)
		}
		h1AssertSameOutputs(t, what, off.outputs, on.outputs)
		skipped += on.skipped
	}
	return skipped
}

// TestHTTP1BodySkipOverlappingReadPartialHead is a read that entered before the writes of a request body
// and returned a partial response head after two of them: its data id sorts it in front of them, and the
// analyzer reads the head on into the body writes
func TestHTTP1BodySkipOverlappingReadPartialHead(t *testing.T) {
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	body := strings.Repeat("abcdefghij", 100)
	traffic := h1CallTraffic([]h1Call{
		{1, 0, out, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3000\r\n\r\n"},
		{3, 1, out, body},
		{4, 3, out, body},
		{2, 4, in, "HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\n"},
		{5, 2, out, body},
		{6, 5, in, "Content-Length: 0\r\n\r\n"},
	})
	h1AssertSameForSchedules(t, "overlap", traffic)
}

// TestHTTP1BodySkipTokenAcrossCalls is a start token split between a body call too small to skip and the
// next one
func TestHTTP1BodySkipTokenAcrossCalls(t *testing.T) {
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	body := strings.Repeat("abcdefghij", 100)
	tail := "T /y HTTP/1.1\r\nHost: a\r\n\r\n"
	traffic := h1CallTraffic([]h1Call{
		{1, 0, in, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3000\r\n\r\n"},
		{2, 1, in, body},
		{3, 2, in, "xxGE"},
		{4, 3, in, tail + body[:996-len(tail)]},
		{5, 4, in, body},
		{6, 5, out, "HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n"},
		{7, 6, out, body},
		{8, 7, out, body},
	})
	if h1AssertSameForSchedules(t, "token across calls", traffic) == 0 {
		t.Fatalf("nothing skipped")
	}
}

// h1AdvCall is a call of h1AdversarialCalls before it is numbered
type h1AdvCall struct {
	dir  enums.SocketDataDirection
	data []byte
}

func h1AdvBody(rnd *rand.Rand, n int) []byte {
	b := make([]byte, n)
	switch rnd.Intn(4) {
	case 0:
		rnd.Read(b)
	case 1:
		for i := range b {
			b[i] = "abc GET HTTP/1.1 POST PUT HEAD OPTIONS\r\n"[rnd.Intn(40)]
		}
	default:
		for i := range b {
			b[i] = 'a' + byte(i%26)
		}
	}
	return b
}

func h1AdvSplit(rnd *rand.Rand, data []byte) [][]byte {
	var out [][]byte
	for len(data) > 0 {
		var n int
		switch rnd.Intn(5) {
		case 0:
			n = 1 + rnd.Intn(20)
		case 1:
			n = 20 + rnd.Intn(200)
		default:
			n = 30 + rnd.Intn(6000)
		}
		n = min(n, len(data))
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

func h1AdversarialCalls(seed int64) ([]h1Call, []uint16) {
	rnd := rand.New(rand.NewSource(seed))
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	if rnd.Intn(2) == 0 {
		in, out = out, in
	}
	var calls []h1AdvCall
	var respFirst []int
	for x := 0; x < 2+rnd.Intn(6); x++ {
		bl := []int{0, 10, 100, 2000, 30000}[rnd.Intn(5)]
		body := h1AdvBody(rnd, bl)
		head := fmt.Sprintf("POST /o/%d HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n", x, bl)
		if rnd.Intn(8) == 0 {
			head = fmt.Sprintf("GET /o/%d HTTP/1.1\r\nHost: a\r\n\r\n", x)
			body = nil
		}
		msg := append([]byte(head), body...)
		if rnd.Intn(2) == 0 {
			calls = append(calls, h1AdvCall{in, []byte(head)})
			for _, p := range h1AdvSplit(rnd, body) {
				calls = append(calls, h1AdvCall{in, p})
			}
		} else {
			for _, p := range h1AdvSplit(rnd, msg) {
				calls = append(calls, h1AdvCall{in, p})
			}
		}
		rl := []int{0, 10, 100, 2000, 30000}[rnd.Intn(5)]
		rhead := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n", rl)
		if rnd.Intn(10) == 0 {
			rhead = "HTTP/1.1 204 No Content\r\n\r\n"
			rl = 0
		}
		resp := append([]byte(rhead), h1AdvBody(rnd, rl)...)
		respFirst = append(respFirst, len(calls))
		if rnd.Intn(3) == 0 {
			// a partial head
			cut := 1 + rnd.Intn(len(rhead)-1)
			calls = append(calls, h1AdvCall{out, resp[:cut]})
			for _, p := range h1AdvSplit(rnd, resp[cut:]) {
				calls = append(calls, h1AdvCall{out, p})
			}
		} else if rnd.Intn(2) == 0 {
			calls = append(calls, h1AdvCall{out, []byte(rhead)})
			for _, p := range h1AdvSplit(rnd, resp[len(rhead):]) {
				calls = append(calls, h1AdvCall{out, p})
			}
		} else {
			for _, p := range h1AdvSplit(rnd, resp) {
				calls = append(calls, h1AdvCall{out, p})
			}
		}
	}
	// entry order: some calls entered up to 4 calls before they upload
	entry := make([]int, len(calls))
	for i := range entry {
		entry[i] = i
	}
	rate := []int{3, 6, 20, 1 << 30}[rnd.Intn(4)]
	for j := 1; j < len(entry); j++ {
		if rnd.Intn(rate) != 0 {
			continue
		}
		k := min(j, 1+rnd.Intn(4))
		moved := entry[j]
		copy(entry[j-k+1:j+1], entry[j-k:j])
		entry[j-k] = moved
	}
	for _, j := range respFirst {
		if j == 0 || rnd.Intn(2) == 0 {
			continue
		}
		pos := -1
		for p, e := range entry {
			if e == j {
				pos = p
			}
		}
		k := min(pos, 1+rnd.Intn(4))
		copy(entry[pos-k+1:pos+1], entry[pos-k:pos])
		entry[pos-k] = j
	}
	gaps := rnd.Intn(3) == 0
	ids := make([]uint64, len(calls))
	gapBefore := make([]bool, len(calls))
	id := uint64(0)
	for _, i := range entry {
		id++
		if gaps && rnd.Intn(3) == 0 {
			id++
			gapBefore[i] = true
		}
		ids[i] = id
	}
	// the calls in flight as each one returns, as h1Conn.number counts them; known for most seeds
	position := make([]int, len(calls))
	for at, i := range entry {
		position[i] = at
	}
	known := rnd.Intn(4) != 0
	var result []h1Call
	var inFlights []uint16
	prev := uint64(0)
	entered := 0
	for i, c := range calls {
		for entered <= position[i] {
			entered++
		}
		inFlight := uint16(entered - i)
		if gapBefore[i] && rnd.Intn(4) == 0 {
			inFlight++
		}
		if !known {
			inFlight = 0
		}
		result = append(result, h1Call{id: ids[i], prev: prev, dir: c.dir, data: string(c.data)})
		inFlights = append(inFlights, inFlight)
		prev = ids[i]
	}
	return result, inFlights
}

// TestHTTP1BodySkipAdversarialSweep runs one connection of random exchanges cut into calls of any size
// (partial heads, calls of a few bytes, bodies of start tokens or binary bytes), with calls that entered up
// to 4 calls before they upload (the first call of a response most often: a read posted before the writes
// of the request body) and calls that upload nothing in between. H1_SKIP_SWEEP_SEEDS and
// H1_SKIP_SWEEP_FROM run more or other seeds.
func TestHTTP1BodySkipAdversarialSweep(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("H1_SKIP_SWEEP_SEEDS"))
	if n == 0 {
		n = 60
		if testing.Short() {
			n = 20
		}
	}
	from, _ := strconv.Atoi(os.Getenv("H1_SKIP_SWEEP_FROM"))
	total, fails := 0, 0
	for seed := int64(from); seed < int64(from+n); seed++ {
		calls, inFlight := h1AdversarialCalls(seed)
		traffic := h1CallTrafficInFlight(calls, inFlight)
		for _, every := range []int{1, 2, 3, 5, 1 << 30} {
			off := h1SkipRun(t, traffic, false, every)
			on := h1SkipRun(t, traffic, true, every)
			total += on.skipped
			same := len(off.outputs) == len(on.outputs) && on.conflicts == 0
			for i := 0; same && i < len(off.outputs); i++ {
				same = string(off.outputs[i].encoded) == string(on.outputs[i].encoded)
			}
			if !same {
				fails++
				t.Errorf("seed %d every %d: differs (conflicts %d, outputs %d/%d)", seed, every, on.conflicts, len(off.outputs), len(on.outputs))
				break
			}
		}
	}
	t.Logf("%d seeds: %d records skipped, %d seeds differ", n, total, fails)
}

// h1AssertSameOutputsPerConnection is h1AssertSameOutputs for each connection on its own but the disturbed
// ones: the order of the outputs of different connections follows the schedule of the analysis
func h1AssertSameOutputsPerConnection(t *testing.T, what string, off, on []h1Output, disturbed map[uint64]bool) {
	t.Helper()
	group := func(outputs []h1Output) map[uint64][]h1Output {
		m := map[uint64][]h1Output{}
		for _, o := range outputs {
			m[o.conn] = append(m[o.conn], o)
		}
		return m
	}
	offs, ons := group(off), group(on)
	compared := 0
	for conn, o := range offs {
		if !disturbed[conn] {
			h1AssertSameOutputs(t, fmt.Sprintf("%s connection %d", what, conn), o, ons[conn])
			compared++
		}
	}
	for conn := range ons {
		if _, ok := offs[conn]; !ok && !disturbed[conn] {
			t.Fatalf("%s: outputs of connection %d only on", what, conn)
		}
	}
	if compared == 0 {
		t.Fatalf("%s: no connection to compare", what)
	}
}

// TestHTTP1BodySkipBPFKeepsTheAccessLogs decodes the calls as BPF uploads them with
// skip_http1_body_payload_bpf (h1Conn.bpfSkip: without the content of the calls inside the Content-Length
// bodies, coalesced with merge_kernel_logs) and requires the same access logs, kernel logs included, as
// with every call uploaded; also with the user space skipping on top
func TestHTTP1BodySkipBPFKeepsTheAccessLogs(t *testing.T) {
	scenarios := []struct {
		name string
		seed int64
		o    h1Options
	}{
		{"keep-alive", 11, h1Options{connections: 5, exchanges: 120, maxBody: 1 << 20}},
		{"gaps", 12, h1Options{connections: 5, exchanges: 120, maxBody: 300 << 10, gaps: true}},
		{"overlap", 13, h1Options{connections: 4, exchanges: 160, maxBody: 300 << 10, overlap: true, overlapReads: true}},
		{"unusual", 14, h1Options{connections: 6, exchanges: 200, maxBody: 300 << 10, unusual: true}},
		{"unusual-lossy", 15, h1Options{connections: 8, exchanges: 200, maxBody: 300 << 10, unusual: true, lossy: true}},
		// heads cut into small calls (BPF loses the direction). Not with the unusual exchanges: the analyzer
		// gives a request body up at a 100 Continue and reads the body calls as messages, which differs as
		// soon as a body holds start tokens
		{"tiny", 17, h1Options{connections: 6, exchanges: 160, maxBody: 300 << 10, tiny: true}},
		{"overlap-unusual-gaps", 16, h1Options{connections: 4, exchanges: 160, maxBody: 100 << 10, unusual: true, gaps: true, overlap: true, overlapReads: true}},
		{"chunked", 18, h1Options{connections: 5, exchanges: 160, maxBody: 300 << 10, chunked: true}},
		{"chunked-tiny", 19, h1Options{connections: 4, exchanges: 120, maxBody: 100 << 10, chunked: true, tiny: true}},
		{"chunked-gaps-overlap", 20, h1Options{connections: 4, exchanges: 160, maxBody: 300 << 10, chunked: true, gaps: true, overlap: true, overlapReads: true}},
		{"chunked-lossy", 21, h1Options{connections: 8, exchanges: 160, maxBody: 300 << 10, chunked: true, lossy: true}},
		{"closing", 22, h1Options{connections: 5, exchanges: 60, maxBody: 100 << 10, closing: true}},
		{"closing-unusual", 23, h1Options{connections: 5, exchanges: 60, maxBody: 100 << 10, closing: true, unusual: true}},
	}
	for _, s := range scenarios {
		for _, coalesce := range []bool{false, true} {
			o := s.o
			o.coalesce, o.base = coalesce, bpfNow()
			off := h1GenerateTraffic(s.seed, o)
			o.bpf = true
			on := h1GenerateTraffic(s.seed, o)
			for _, every := range []int{1, 5, 37, 1 << 30} {
				name := fmt.Sprintf("%s coalesce=%t every %d", s.name, coalesce, every)
				offRun := h1SkipRun(t, off, false, every)
				onRun := h1SkipRun(t, on, false, every)
				if offRun.bpfSkipped != 0 || onRun.bpfSkipped == 0 {
					t.Fatalf("%s: %d records skipped by BPF off, %d on", name, offRun.bpfSkipped, onRun.bpfSkipped)
				}
				// a call lost before the reader puts the analyzer out of step in both, but differently: it cannot
				// take a part of a call uploaded without its content, as it takes a part of its bytes
				h1AssertSameOutputsPerConnection(t, name, offRun.outputs, onRun.outputs, on.disturbed)
				both := h1SkipRun(t, on, true, every)
				if both.conflicts != 0 {
					t.Fatalf("%s: %d reads wanted skipped bytes", name, both.conflicts)
				}
				h1AssertSameOutputsPerConnection(t, name+" with the user space skipping", offRun.outputs, both.outputs, on.disturbed)
				if every == 1 {
					t.Logf("%s: %d records, %d uploaded by BPF without content (%d bytes), %d outputs; with the user space skipping %d more skipped",
						name, offRun.records, onRun.bpfSkipped, onRun.bpfBytes, len(onRun.outputs), both.skipped)
				}
				if !s.o.unusual && !s.o.overlap && !s.o.gaps && !s.o.tiny && !s.o.closing && !s.o.chunked {
					h1AssertExpected(t, on, onRun.outputs)
				}
			}
		}
	}
}

// h1WithoutInFlight is the traffic as an older BPF side uploads it: no calls in flight known
func h1WithoutInFlight(traffic *h1Traffic) *h1Traffic {
	stripped := *traffic
	stripped.records = make([]h1Record, len(traffic.records))
	for i, r := range traffic.records {
		r.wire.InFlight = 0
		r.sample = h1Sample(&r.wire, r.payload)
		stripped.records[i] = r
	}
	return &stripped
}

// TestHTTP1BodySkipInFlightClearsGaps: the calls that upload nothing (a Go connection polls: its reads
// return EAGAIN) take data ids in between, which kept the user space skipping waiting for them until the
// calls in flight proved them done (http1skip.Tracker, clearGaps)
func TestHTTP1BodySkipInFlightClearsGaps(t *testing.T) {
	for _, s := range []struct {
		name string
		o    h1Options
	}{
		{"gaps", h1Options{connections: 5, exchanges: 120, maxBody: 300 << 10, gaps: true}},
		{"gaps-overlap", h1Options{connections: 4, exchanges: 160, maxBody: 300 << 10, gaps: true, overlap: true}},
	} {
		traffic := h1GenerateTraffic(21, s.o)
		before := h1WithoutInFlight(traffic)
		off := h1SkipRun(t, traffic, false, 7)
		with := h1SkipRun(t, traffic, true, 7)
		without := h1SkipRun(t, before, true, 7)
		h1AssertSameOutputs(t, s.name, off.outputs, with.outputs)
		h1AssertSameOutputs(t, s.name+" without in flight", off.outputs, without.outputs)
		t.Logf("%s: %d records, skipped %d (%.1f%%) with the calls in flight, %d (%.1f%%) without", s.name, with.records,
			with.skipped, 100*float64(with.skipped)/float64(with.records), without.skipped,
			100*float64(without.skipped)/float64(without.records))
		// a call that overlaps another one still puts the tracker out of step until the analyzer is clean
		if with.skipped <= without.skipped || (!s.o.overlap && with.skipped*10 < with.records*6) {
			t.Fatalf("%s: %d skipped with the calls in flight, %d without", s.name, with.skipped, without.skipped)
		}
	}
}

// TestHTTP1BodySkipBPFRunPassedByTheOtherDirection: the request body calls 2 and 3 are held for a coalesced
// event; the response head 4 (an early 413) uploads while the body write 5 is in flight, so it cannot upload
// the run; then 5 returns alone and would join the run: the run is uploaded first, so its data ids never
// cover the response head, and the access logs are the same as with every call uploaded
func TestHTTP1BodySkipBPFRunPassedByTheOtherDirection(t *testing.T) {
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	head := []byte("POST /big HTTP/1.1\r\nHost: orders:8080\r\nContent-Length: 20000\r\n\r\n")
	body := bytes.Repeat([]byte{'b'}, 5000)
	resp := []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
	type call struct {
		dir                   enums.SocketDataDirection
		data                  []byte
		body, end             bool
		inFlight, same, other int
	}
	calls := []call{
		{in, head, false, false, 1, 1, 0},
		{in, body, true, false, 1, 1, 0},
		{in, body, true, false, 1, 1, 0},
		{out, resp, false, false, 2, 1, 1}, // the body write 5 is in flight
		{in, body, true, false, 1, 1, 0},   // returns alone: it would join the run
		{in, body, true, true, 1, 1, 0},
	}
	base := bpfNow()
	build := func(bpf bool) *h1Traffic {
		c := &h1Conn{id: 300}
		for i, x := range calls {
			c.call(x.dir, x.data)
			r := &c.calls[len(c.calls)-1][0]
			r.body, r.bodyEnd, r.inFlightDirection, r.inFlightOther = x.body, x.end, x.same, x.other
			r.wire.DataID0, r.wire.PrevDataID0, r.wire.InFlight = uint64(i+1), uint64(i), uint16(x.inFlight)
			r.wire.StartTime0, r.wire.EndTime0 = base+uint64(i)*1000, base+uint64(i)*1000+500
			r.sample = h1Sample(&r.wire, r.payload)
		}
		if bpf {
			c.bpfSkip(rand.New(rand.NewSource(1)), h1Options{coalesce: true})
		}
		traffic := &h1Traffic{merge: true, expected: map[uint64][]h1Expected{}, disturbed: map[uint64]bool{}}
		for slot, records := range c.calls {
			for _, r := range records {
				r.slot = slot
				traffic.records = append(traffic.records, r)
			}
		}
		return traffic
	}
	off, on := build(false), build(true)
	// the run of 2 and 3 goes before 4 by its data id, and 5 and 6 are a run of their own
	var spans []string
	for _, r := range on.records {
		if r.wire.PayloadSkipped0 == 1 {
			spans = append(spans, fmt.Sprintf("%d-%d", r.wire.DataID0-uint64(r.wire.DataIDSpan), r.wire.DataID0))
		}
	}
	if fmt.Sprint(spans) != "[2-3 5-6]" {
		t.Fatalf("the coalesced events stand for %v", spans)
	}
	for _, every := range []int{1, 2, 1 << 30} {
		offRun := h1SkipRun(t, off, false, every)
		onRun := h1SkipRun(t, on, false, every)
		h1AssertSameOutputs(t, fmt.Sprintf("every %d", every), offRun.outputs, onRun.outputs)
		if len(offRun.outputs) == 0 {
			t.Fatalf("no output")
		}
	}
}
