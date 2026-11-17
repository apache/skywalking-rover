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

package http1skip

import (
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

var testConnectionIDs atomic.Uint64

const (
	ingress = enums.SocketDataDirectionIngress
	egress  = enums.SocketDataDirectionEgress
)

// testConn feeds the calls of one connection to a tracker as the reader would decode them
type testConn struct {
	t       *testing.T
	tr      *Tracker
	id      uint64
	dataID  uint64
	lastID  uint64
	epoch   *uint64
	skipped int
	copied  int
	seqs    []uint64
	// idGaps: calls that upload nothing take data ids between the calls
	idGaps bool
}

func newTestConn(t *testing.T) *testConn {
	epoch := new(uint64)
	tr := NewTracker(33)
	tr.LossEpoch = func() uint64 { return *epoch }
	return &testConn{t: t, tr: tr, id: testConnectionIDs.Add(1) + 1000, epoch: epoch}
}

// another connection on the same tracker
func (c *testConn) other() *testConn {
	return &testConn{t: c.t, tr: c.tr, id: testConnectionIDs.Add(1) + 1000, epoch: c.epoch}
}

// callWith decodes one single chunk call; edit may change it before the tracker sees it
func (c *testConn) callWith(dir enums.SocketDataDirection, data string, edit func(*Call)) bool {
	c.dataID++
	if c.idGaps {
		c.dataID += uint64(len(data) % 3) // the calls that upload nothing (EAGAIN) take data ids too
	}
	call := Call{ConnectionID: c.id, RandomID: 7, Protocol: enums.ConnectionProtocolHTTP, Direction: dir,
		DataID: c.dataID, PrevDataID: c.lastID, Finished: true, DataLen: len(data), TotalSize: uint64(len(data))}
	if edit != nil {
		edit(&call)
	}
	seq, skip := c.tr.Decide(&call, []byte(data))
	c.lastID = call.DataID
	c.seqs = append(c.seqs, seq)
	if skip {
		c.skipped++
	} else {
		c.copied++
	}
	return skip
}

func (c *testConn) call(dir enums.SocketDataDirection, data string) bool {
	return c.callWith(dir, data, nil)
}

// send decodes the data as calls of the sizes, and returns which were skipped
func (c *testConn) send(dir enums.SocketDataDirection, data string, sizes ...int) []bool {
	var result []bool
	for data != "" {
		n := len(data)
		if len(sizes) > 0 {
			n = min(sizes[0], n)
			if len(sizes) > 1 {
				sizes = sizes[1:]
			}
		}
		result = append(result, c.call(dir, data[:n]))
		data = data[n:]
	}
	return result
}

func (c *testConn) expect(what string, got []bool, want ...bool) {
	c.t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		c.t.Fatalf("%s: skipped %v, want %v", what, got, want)
	}
}

// body is token free filler
func body(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte('a' + byte(i%26))
	}
	return b.String()
}

func request(method string, bodyLen int, extra ...string) string {
	head := method + " /orders HTTP/1.1\r\nHost: orders:8080\r\n"
	for _, e := range extra {
		head += e + "\r\n"
	}
	if bodyLen >= 0 {
		head += fmt.Sprintf("Content-Length: %d\r\n", bodyLen)
	}
	return head + "\r\n"
}

func response(code, bodyLen int, extra ...string) string {
	head := fmt.Sprintf("HTTP/1.1 %d X\r\n", code)
	for _, e := range extra {
		head += e + "\r\n"
	}
	if bodyLen >= 0 {
		head += fmt.Sprintf("Content-Length: %d\r\n", bodyLen)
	}
	return head + "Connection: keep-alive\r\n\r\n"
}

func repeat(v bool, n int) []bool {
	r := make([]bool, n)
	for i := range r {
		r[i] = v
	}
	return r
}

func TestSkipsContentLengthBodySplitAcrossCalls(t *testing.T) {
	c := newTestConn(t)
	c.expect("request head", c.send(ingress, request("POST", 40000)), false)
	c.expect("request body", c.send(ingress, body(40000), 8000), repeat(true, 5)...)
	c.expect("response head", c.send(egress, response(200, 20000)), false)
	// the last 32 bytes are as cheap to copy
	c.expect("response body", c.send(egress, body(20000), 4096, 4096, 4096, 4096, 3584, 32), true, true, true, true, true, false)
	c.expect("next request head", c.send(ingress, request("GET", -1)), false)
	c.expect("response head with the first body bytes", c.send(egress, response(200, 9000)+body(100)), false)
	c.expect("rest of the body", c.send(egress, body(8900), 4450), true, true)
}

// clean reports the analyzer clean behind the last call
func (c *testConn) clean() {
	s := lookup(connKey{id: c.id, random: 7})
	if s == nil {
		s = Register(c.id, 7)
		c.t.Cleanup(func() { Unregister(c.id, 7, s) })
	}
	s.MarkClean(c.seqs[len(c.seqs)-1])
}

// resync frames a complete exchange behind an unframed call, reports the analyzer clean at its end and
// checks the next one is skipped again
func (c *testConn) resync() {
	c.t.Helper()
	c.send(ingress, request("POST", 10000))
	c.expect("body while out of step", c.send(ingress, body(10000)), false)
	c.send(egress, response(200, 5000))
	c.send(egress, body(5000))
	c.clean()
	c.send(ingress, request("POST", 10000))
	c.expect("body once in step", c.send(ingress, body(10000), 5000), true, true)
}

func TestBodyEndingInsideCallIsCopied(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 10000))
	c.expect("body", c.send(ingress, body(6000)), true)
	before := giveUps[reasonOverrun].Load()
	// the body ends inside the call and the next request starts in it (pipelining)
	c.expect("end and next head", c.send(ingress, body(4000)+request("POST", 9000)+body(1000)), false)
	if giveUps[reasonOverrun].Load() != before+1 {
		t.Fatalf("no overrun give up")
	}
	c.expect("the message that started inside the call", c.send(ingress, body(8000)), false)
	c.resync()
}

func TestPipelinedHeadIsNotFollowed(t *testing.T) {
	c := newTestConn(t)
	c.expect("head, body and next head", c.send(ingress, request("POST", 100)+body(100)+request("POST", 9000)), false)
	c.expect("body of the second", c.send(ingress, body(9000)), false)
	c.resync()
	// a head with more body bytes than announced: the next message starts in its call
	c.expect("head", c.send(ingress, request("POST", 10)+body(50)), false)
	c.expect("after", c.send(ingress, body(5000)), false)
}

func TestChunkedBodyIsFollowedNotSkipped(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", -1, "Transfer-Encoding: chunked"))
	c.expect("chunks", c.send(ingress, "1000\r\n"+body(4096)+"\r\n0\r\n\r\n", 1000), repeat(false, 5)...)
	c.send(egress, response(200, -1, "Transfer-Encoding: chunked")+"10\r\n"+body(16)+"\r\n")
	c.expect("response chunks", c.send(egress, "2000\r\n"+body(8192)+"\r\n0\r\n\r\n", 3000), repeat(false, 3)...)
	// the framing went on through the chunked messages
	c.send(ingress, request("PUT", 10000))
	c.expect("body behind them", c.send(ingress, body(10000), 5000), true, true)
	// a chunked body that ends inside a call
	c.send(ingress, request("POST", -1, "Transfer-Encoding: chunked"))
	c.send(ingress, "5\r\nhello\r\n0\r\n\r\n"+request("POST", 10000))
	c.expect("behind it", c.send(ingress, body(10000), 5000), false, false)
	c.resync()
}

func TestAnalyzerStateBeforeTheTracker(t *testing.T) {
	c := newTestConn(t)
	// the analyzer holds data of the connection the tracker never saw
	s := Register(c.id, 7)
	defer Unregister(c.id, 7, s)
	c.send(ingress, request("POST", 10000))
	c.expect("body", c.send(ingress, body(10000), 5000), false, false)
	waits := skipWaits.Load()
	// clean in the middle of a message proves nothing
	s.MarkClean(c.seqs[len(c.seqs)-2])
	c.send(egress, response(200, 10000))
	c.expect("response body", c.send(egress, body(10000), 5000), false, false)
	if skipWaits.Load() == waits {
		t.Fatalf("no wait counted")
	}
	// clean behind the request: the response may answer a request the analyzer does not hold
	c.send(ingress, request("POST", 100))
	c.send(ingress, body(100))
	s.MarkClean(c.seqs[len(c.seqs)-1])
	c.send(egress, response(200, 10000))
	c.expect("response to a request read before", c.send(egress, body(10000), 5000), false, false)
	c.resync()
	c.send(egress, response(200, 10000))
	c.expect("response behind it", c.send(egress, body(10000), 5000), true, true)
}

func TestNoBodyResponses(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("HEAD", -1))
	c.send(egress, response(200, 50000))
	c.send(ingress, request("POST", 10000))
	c.expect("behind the HEAD response", c.send(ingress, body(10000)), true)
	for _, code := range []int{100, 204, 304} {
		c.send(egress, response(200, 0))
		c.send(ingress, request("GET", -1))
		c.send(egress, response(code, 50000))
		c.send(ingress, request("POST", 10000))
		c.expect(fmt.Sprintf("behind %d", code), c.send(ingress, body(10000)), true)
	}
	// bytes behind a response without body
	c.send(egress, response(200, 0))
	c.send(ingress, request("GET", -1))
	c.send(egress, response(204, 50000))
	c.expect("bytes between messages", c.send(egress, body(5000)), false)
	c.resync()

	for _, code := range []int{101, 200} {
		c := newTestConn(t)
		if code == 200 {
			// a response that does not follow a request directly is not followed
			c.send(ingress, request("GET", -1))
			c.send(ingress, body(100))
		} else {
			c.send(ingress, request("GET", -1, "Connection: Upgrade"))
		}
		c.send(egress, response(code, 50000))
		c.expect(fmt.Sprintf("after %d", code), c.send(egress, body(5000)), false)
		c.resync()
	}

	c = newTestConn(t)
	c.send(ingress, request("GET", -1))
	c.send(ingress, request("GET", -1))
	c.send(egress, response(200, 10000))
	c.expect("behind a later request", c.send(egress, body(5000)), true)
	// a response without length is read to the end of its call
	c.send(egress, body(5000))
	c.send(ingress, request("GET", -1))
	c.send(egress, response(200, -1)+body(1000))
	c.send(ingress, request("POST", 10000))
	c.expect("behind it", c.send(ingress, body(10000)), true)
}

func TestUpgradeAndConnectAreNotFollowed(t *testing.T) {
	for i, head := range []string{request("POST", 10000, "Upgrade: websocket", "Connection: Upgrade"),
		request("PUT", 10000, "upgrade: h2c"),
		"CONNECT orders:443 HTTP/1.1\r\nHost: orders:443\r\nContent-Length: 10000\r\n\r\n"} {
		c := newTestConn(t)
		c.call(ingress, head)
		c.expect(fmt.Sprint("head ", i), c.send(ingress, body(5000)), false)
		c.resync()
	}
}

func TestInvalidContentLengthIsNotFollowed(t *testing.T) {
	for _, extra := range []string{"Content-Length: +5000", "Content-Length: -1", "Content-Length: abc",
		"Content-Length: 5000, 5000", "Content-Length: 0x100", "Content-Length: 99999999999999999999",
		"Content-Length: 5000\r\nContent-Length: 5000", "Content-Length: 5000\r\nTransfer-Encoding: chunked",
		"Transfer-Encoding: gzip, chunked", "Transfer-Encoding: Chunked"} {
		c := newTestConn(t)
		c.call(ingress, "POST / HTTP/1.1\r\nHost: h\r\n"+extra+"\r\n\r\n")
		c.expect(extra, c.send(ingress, body(5000)), false)
		c.resync()
	}
}

func TestOutOfOrderCallsAreCopied(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 30000))
	c.expect("first", c.send(ingress, body(5000)), true)
	// a call in between was not seen
	c.expect("gap", []bool{c.callWith(ingress, body(5000), func(call *Call) { call.PrevDataID-- })}, false)
	c.expect("rest", c.send(ingress, body(20000), 5000), repeat(false, 4)...)
	c.resync()

	c = newTestConn(t)
	c.send(ingress, request("POST", 30000))
	c.expect("before", c.send(ingress, body(5000)), true)
	// a call took data id 3 and did not upload yet: the calls behind it are copied
	c.dataID++
	waits := holeWaits.Load()
	c.expect("behind the missing id", c.send(ingress, body(10000), 5000), false, false)
	if holeWaits.Load() != waits+2 {
		t.Fatalf("hole waits not counted")
	}
	// the call with the smaller data id comes: overlapping calls, out of order
	c.expect("older", []bool{c.callWith(ingress, body(5000), func(call *Call) { c.dataID--; call.DataID = 3 })}, false)
	c.dataID = c.lastID + 2
	c.lastID = 3
	c.expect("rest", c.send(ingress, body(10000), 5000), false, false)
	// every data id came: skipped again once the analyzer is in step
	c.resync()
}

// TestOverlappingReadIsNotSkippedAround is a read that entered before the writes of a request body and
// returns the start of the response behind them: its data id sorts it in front of the body writes, so the
// analyzer reads the partial response head on into them
func TestOverlappingReadIsNotSkippedAround(t *testing.T) {
	c := newTestConn(t)
	c.send(egress, request("POST", 3000))
	readID := c.dataID + 1
	c.dataID++ // the read entered
	c.expect("body writes behind the read", c.send(egress, body(2000), 1000), false, false)
	c.expect("the read", []bool{c.callWith(ingress, "HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\n",
		func(call *Call) { c.dataID--; call.DataID = readID })}, false)
	c.dataID = c.lastID + 2
	c.lastID = readID
	c.expect("rest of the body", c.send(egress, body(1000)), false)
	c.send(ingress, "Content-Length: 0\r\n\r\n")
	c.resync()
}

// TestDataIDGapsStopSkipping: calls that upload nothing (a read that returns EAGAIN) leave data ids that
// never come, the calls behind them are never skipped
func TestDataIDGapsStopSkipping(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 20000))
	c.expect("in order", c.send(ingress, body(10000), 5000), true, true)
	c.idGaps = true
	for i := 0; i < 5; i++ {
		c.send(ingress, body(1))
		c.send(egress, response(200, 0))
		c.send(ingress, request("POST", 20000))
		c.expect("behind gaps", c.send(ingress, body(20000), 5000), repeat(false, 4)...)
	}
	// more missing ids than kept, then the missing ones come: the connection stays copied
	d := newTestConn(t)
	d.send(ingress, request("POST", 20000))
	first := d.dataID
	d.dataID += maxGaps + 1
	d.expect("behind many gaps", d.send(ingress, body(20000), 5000), repeat(false, 4)...)
	for id := first + 1; id <= first+maxGaps+1; id++ {
		d.callWith(egress, body(10), func(call *Call) { d.dataID--; call.DataID = id })
	}
	d.dataID = d.lastID
	d.resync2(false)

	// a data id that comes twice: another call may share it
	e := newTestConn(t)
	e.send(ingress, request("POST", 20000))
	e.callWith(ingress, body(10), func(call *Call) { e.dataID--; call.DataID = 1 })
	e.resync2(false)
}

// resync2 is resync with the body of the next message skipped or not
func (c *testConn) resync2(skipped bool) {
	c.t.Helper()
	c.send(ingress, request("POST", 10000))
	c.send(ingress, body(10000))
	c.send(egress, response(200, 5000))
	c.send(egress, body(5000))
	c.clean()
	c.send(ingress, request("POST", 10000))
	c.expect("body once in step", c.send(ingress, body(10000), 5000), skipped, skipped)
}

// TestTokenAcrossCalls is a start token split between a body call too small to skip, or not checked, and
// the next one: a peek from the small call would read into it
func TestTokenAcrossCalls(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 60000))
	c.expect("plain", c.send(ingress, body(5000)), true)
	c.expect("small", c.send(ingress, "xxGE"), false)
	c.expect("the rest of the token", c.send(ingress, "T /x HTTP/1.1\r\n"+body(4984)), false)
	c.expect("plain again", c.send(ingress, body(5000)), true)
	// a whole token close to the end of small calls
	c.send(ingress, "PU")
	c.send(ingress, "T /")
	c.expect("behind a token in small calls", c.send(ingress, body(5000)), false)
	c.send(ingress, "HEAD /y")
	c.send(ingress, body(5))
	c.expect("behind a token beginning 12 bytes before", c.send(ingress, body(5000)), false)
	c.send(ingress, "HEAD /y")
	c.send(ingress, body(20))
	c.expect("behind a token beginning 27 bytes before", c.send(ingress, body(5000)), true)
	// a call that is not skipped for being truncated ends with a token
	c.expect("truncated", []bool{c.callWith(ingress, body(4990)+"OPTIONS", func(call *Call) { call.TotalSize = 5000; call.Reduced = true })}, false)
	c.expect("behind it", c.send(ingress, body(5000)), false)
	c.expect("then", c.send(ingress, body(5000)), true)
	// the body ends with the call (45047 bytes sent): the next head is followed
	c.expect("end of the body", c.send(ingress, body(60000-45047)), true)
	c.send(egress, response(200, 10000))
	c.expect("next message", c.send(egress, body(10000), 5000), true, true)
}

func TestTailTokenFree(t *testing.T) {
	for _, tc := range []struct {
		tail, data string
		free       bool
	}{
		{"", "GET /", true},
		{"abcdefg", "GET /", true},
		{"abcGE", "T /x", false},
		{"abcGE", "X /x", true},
		{"G", "ET", false},
		{"G", "E", false}, // data too short to tell
		{"PU", "T", false},
		{"xxHEAD /", body(30), false},
		{"xxHTT", "P/1.1", false},
		{"xxHTT", "Xx", true},
		{"OPTIONS", body(30), false},
		{"OPTION", "x", true},
	} {
		if got := tailTokenFree([]byte(tc.tail), []byte(tc.data)); got != tc.free {
			t.Fatalf("%q %q: %t", tc.tail, tc.data, got)
		}
	}
}

func TestFirstCallBehindAnUnseenOne(t *testing.T) {
	c := newTestConn(t)
	// a call was uploaded before the first one the tracker sees: lost, or still to come
	c.lastID = 3
	c.send(ingress, request("POST", 10000))
	c.expect("body", c.send(ingress, body(10000)), false)
	c.resync()
	// a head behind a call not seen
	c.lastID++
	c.send(ingress, request("POST", 10000))
	c.expect("body behind a gap", c.send(ingress, body(10000)), false)
	c.resync()
}

func TestLostEventsLeaveTheAnalyzerOpen(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 30000))
	c.expect("before", c.send(ingress, body(10000), 5000), true, true)
	*c.epoch++
	c.expect("after a loss", c.send(ingress, body(20000), 5000), repeat(false, 4)...)
	c.resync()
	// a lost event of the connection
	c.send(ingress, request("POST", 30000))
	c.tr.NoteDropped(c.id, 7)
	c.expect("after a drop", c.send(ingress, body(30000), 5000), repeat(false, 6)...)
	c.resync()
	// of another connection
	c.send(ingress, request("POST", 30000))
	c.tr.NoteDropped(c.id+1000000, 7)
	c.expect("after a drop elsewhere", c.send(ingress, body(30000), 5000), repeat(true, 6)...)
}

func TestTLSAndOtherProtocolsAreNeverSkipped(t *testing.T) {
	c := newTestConn(t)
	tls := func(call *Call) { call.SSL = true }
	c.callWith(ingress, request("POST", 10000), tls)
	c.expect("tls", []bool{c.callWith(ingress, body(5000), tls), c.call(ingress, body(5000))}, false, false)

	c = newTestConn(t)
	c.send(ingress, request("POST", 20000))
	c.expect("plain", c.send(ingress, body(5000)), true)
	c.callWith(ingress, body(5000), func(call *Call) { call.Protocol = enums.ConnectionProtocolHTTP2 })
	c.expect("after another protocol", c.send(ingress, body(10000)), false)

	// the events of an unknown protocol only go to the kernel logs and change nothing
	c = newTestConn(t)
	c.send(ingress, request("POST", 20000))
	lastID := c.lastID
	c.callWith(ingress, body(5000), func(call *Call) { call.Protocol = enums.ConnectionProtocolUnknown })
	c.lastID = lastID
	c.expect("behind an unknown event", c.send(ingress, body(20000), 5000), repeat(true, 4)...)
	// a data id missing until an unknown event of it comes
	c.send(ingress, request("POST", 20000))
	c.dataID++
	c.expect("behind the missing id", c.send(ingress, body(10000), 5000), false, false)
	lastID, dataID := c.lastID, c.dataID
	c.callWith(ingress, body(5000), func(call *Call) { call.Protocol = enums.ConnectionProtocolUnknown; call.DataID = dataID - 2 })
	c.lastID, c.dataID = lastID, dataID
	c.expect("once it came", c.send(ingress, body(10000), 5000), true, true)
}

func TestDirectionChangeLeavesTheAnalyzerOpen(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 20000, "Expect: 100-continue"))
	c.send(egress, "HTTP/1.1 100 Continue\r\n\r\n")
	c.expect("body after 100", c.send(ingress, body(20000), 5000), repeat(false, 4)...)
	c.resync()
}

func TestTokensInABodyAreCopied(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 40000))
	c.expect("plain", c.send(ingress, body(10000), 5000), true, true)
	c.expect("token at the start", c.send(ingress, "GET"+body(4997)), false)
	c.expect("token close to the end", c.send(ingress, body(4990)+"HTTP"+body(6)), false)
	c.expect("cut token", c.send(ingress, body(4999)+"P"), false)
	c.expect("token in the middle", c.send(ingress, body(2000)+"GET"+body(2997)), true)
	c.expect("rest", c.send(ingress, body(10000), 5000), true, true)
	// a token behind the head
	c.send(egress, response(200, 10000)+"HTTP")
	c.expect("body of a head with a token behind it", c.send(egress, body(9996), 5000), false, false)
	c.send(ingress, request("POST", 10000))
	c.expect("next message", c.send(ingress, body(10000), 5000), true, true)
	for _, data := range []string{body(100) + "HTTP" + body(100), body(200) + "PO", body(200) + "H", body(200) + "OPTIO"} {
		if tokenFree([]byte(data)) {
			t.Fatalf("token free: %q", data[190:])
		}
	}
}

func TestMessagesRunningTooLongAreCopied(t *testing.T) {
	c := newTestConn(t)
	at := func(ns uint64) func(*Call) { return func(call *Call) { call.StartTime = ns } }
	c.callWith(ingress, request("POST", 30000), at(1000))
	c.expect("early", []bool{c.callWith(ingress, body(10000), at(uint64(time.Second)))}, true)
	c.expect("late", []bool{c.callWith(ingress, body(10000), at(uint64(30*time.Second)))}, false)
	c.resync()
}

func TestMultiChunkCalls(t *testing.T) {
	c := newTestConn(t)
	// one call uploaded in two chunks: the head and the start of the body, then more of the body, and
	// 10000 bytes BPF did not upload
	head := request("POST", 60000)
	first, second := head+body(20480-len(head)), body(20480)
	total := uint64(40960 + 10000)
	c.dataID++
	id := c.dataID
	_, skip1 := c.tr.Decide(&Call{ConnectionID: c.id, RandomID: 7, Protocol: enums.ConnectionProtocolHTTP, Direction: ingress,
		DataID: id, PrevDataID: c.lastID, DataLen: len(first), TotalSize: total}, []byte(first))
	_, skip2 := c.tr.Decide(&Call{ConnectionID: c.id, RandomID: 7, Protocol: enums.ConnectionProtocolHTTP, Direction: ingress,
		DataID: id, PrevDataID: c.lastID, Sequence: 1, Finished: true, Reduced: true, DataLen: len(second), TotalSize: total},
		[]byte(second))
	c.lastID = id
	if skip1 || skip2 {
		t.Fatalf("chunks skipped")
	}
	rest := 60000 - int(total) + len(head)
	c.expect("rest of the body", c.send(ingress, body(rest), 5000), true, true)
	c.send(egress, response(200, 10000))
	c.expect("truncated", []bool{c.callWith(egress, body(5000), func(call *Call) { call.TotalSize = 7000; call.Reduced = true })}, false)
	c.expect("after", c.send(egress, body(3000)), true)
	// a chunk out of order
	c.send(ingress, request("POST", 10000))
	c.expect("chunk", []bool{c.callWith(ingress, body(5000), func(call *Call) { c.dataID--; call.Sequence = 1; call.DataID = c.lastID })}, false)
	c.expect("behind it", c.send(ingress, body(5000)), false)
	c.resync()
}

func TestKeepAliveManyMessages(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	c := newTestConn(t)
	other := c.other()
	for i := 0; i < 200; i++ {
		for _, conn := range []*testConn{c, other} {
			reqLen, respLen := rnd.Intn(100000), rnd.Intn(300000)
			conn.send(ingress, request("POST", reqLen))
			split := 1 + rnd.Intn(20000)
			for j, skip := range conn.send(ingress, body(reqLen), split) {
				last := j == reqLen/split && reqLen%split > 0
				if skip == (last && reqLen%split < 33) {
					t.Fatalf("message %d: request body call %d skipped %t", i, j, skip)
				}
			}
			conn.send(egress, response(200, respLen))
			for j, skip := range conn.send(egress, body(respLen), split) {
				last := j == respLen/split && respLen%split > 0
				if skip == (last && respLen%split < 33) {
					t.Fatalf("message %d: response body call %d skipped %t", i, j, skip)
				}
			}
		}
	}
	if c.skipped == 0 || other.skipped == 0 {
		t.Fatalf("nothing skipped")
	}
}

func TestSweepForgetsIdleConnections(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 10000))
	held := c.other()
	held.send(ingress, request("POST", 10000))
	s := Register(held.id, 7)
	defer Unregister(held.id, 7, s)
	now := time.Now()
	for i := 0; i < idleSweeps; i++ {
		now = now.Add(sweepPeriod)
		c.tr.sweep(now)
	}
	if _, ok := c.tr.conns[connKey{id: c.id, random: 7}]; ok {
		t.Fatalf("idle connection kept")
	}
	if _, ok := c.tr.conns[connKey{id: held.id, random: 7}]; !ok {
		t.Fatalf("connection the analyzer holds forgotten")
	}
	// a forgotten connection starts over behind calls the tracker does not know, which may still come
	c.send(ingress, request("POST", 10000))
	c.expect("body", c.send(ingress, body(10000)), false)
	c.resync2(false)
}

func TestTokenFree(t *testing.T) {
	for _, data := range []string{"", "a", body(5000), "get post http", "TGEX", "\r\n\r\n", "HTT Px", "GE Tx", "HEA Dx", "TRAC E"} {
		if !tokenFree([]byte(data)) {
			t.Fatalf("not token free: %q", data)
		}
	}
	for _, token := range startTokens {
		for _, data := range []string{token, "x" + token, token + "x", "abc" + token + "def"} {
			if tokenFree([]byte(data)) {
				t.Fatalf("token free: %q", data)
			}
		}
		for i := 1; i < len(token); i++ {
			if tokenFree([]byte(body(100) + token[:i])) {
				t.Fatalf("cut token free: %q", token[:i])
			}
		}
	}
}

func TestEdgesTokenFree(t *testing.T) {
	for _, data := range []string{body(100), body(50) + "GET" + body(50), "xGET" + body(50), body(50) + "HTTP" + body(20)} {
		if !edgesTokenFree([]byte(data)) {
			t.Fatalf("not free: %q", data)
		}
	}
	for _, data := range []string{"GET" + body(50), "G", "HT", "OPTIONS", body(50) + "GET" + body(5), body(50) + "T",
		body(50) + "PATC", body(40) + "HEAD" + body(11)} {
		if edgesTokenFree([]byte(data)) {
			t.Fatalf("free: %q", data)
		}
	}
}

// inFlight sets the calls of the fd in flight as the call returned
func inFlight(n uint16) func(*Call) {
	return func(call *Call) { call.InFlight = n }
}

// sendWith is send with every call edited
func (c *testConn) sendWith(dir enums.SocketDataDirection, data string, edit func(*Call), sizes ...int) []bool {
	var result []bool
	for data != "" {
		n := len(data)
		if len(sizes) > 0 {
			n = min(sizes[0], n)
			if len(sizes) > 1 {
				sizes = sizes[1:]
			}
		}
		result = append(result, c.callWith(dir, data[:n], edit))
		data = data[n:]
	}
	return result
}

// TestInFlightClearsDataIDGaps: the data ids of the calls that upload nothing are forgotten behind a call
// that returned alone on its fd, which proves them done
func TestInFlightClearsDataIDGaps(t *testing.T) {
	c := newTestConn(t)
	c.idGaps = true
	alone := inFlight(1)
	for i := 0; i < 5; i++ {
		c.sendWith(ingress, request("POST", 20000), alone)
		// the first body call proves the gaps below it done, and the ones behind it as they come
		c.expect("behind gaps", c.sendWith(ingress, body(20000), alone, 5000), repeat(true, 4)...)
		c.sendWith(egress, response(200, 10000), alone)
		c.expect("response behind gaps", c.sendWith(egress, body(10000), alone, 5000), true, true)
	}
	// a call that overlapped another one proves nothing
	d := newTestConn(t)
	d.idGaps = true
	d.sendWith(ingress, request("POST", 30000), alone)
	d.expect("overlapped", d.sendWith(ingress, body(20000), inFlight(2), 5000), repeat(false, 4)...)
	d.expect("then alone", d.sendWith(ingress, body(10000), alone, 5000), true, true)
	// unknown (an older BPF side) proves nothing either
	e := newTestConn(t)
	e.idGaps = true
	e.sendWith(ingress, request("POST", 20000), nil)
	e.expect("unknown", e.sendWith(ingress, body(20000), nil, 5000), repeat(false, 4)...)
}

// TestInFlightWaitsForTheChain: a call alone on its fd proves the calls before it done, not decoded: the
// call its previous data id names (uploaded, in the buffer of another CPU) still has to come
func TestInFlightWaitsForTheChain(t *testing.T) {
	c := newTestConn(t)
	alone := inFlight(1)
	c.sendWith(ingress, request("POST", 30000), alone)
	c.expect("in order", c.sendWith(ingress, body(10000), alone), true)
	// the call with data id +1 is read after the one with +3 (+2 uploaded nothing)
	late := c.dataID + 1
	c.dataID += 2
	c.expect("behind the late call", c.sendWith(ingress, body(10000), func(call *Call) {
		call.InFlight, call.PrevDataID = 1, late
	}), false)
	if len(c.tr.conns[connKey{id: c.id, random: 7}].awaited) != 1 {
		t.Fatalf("the late call is not awaited")
	}
	c.callWith(ingress, body(10000), func(call *Call) {
		c.dataID--
		call.DataID, call.PrevDataID, call.InFlight = late, late-1, 1
	})
	c.dataID = c.lastID + 2
	cn := c.tr.conns[connKey{id: c.id, random: 7}]
	if len(cn.awaited) != 0 || cn.awaitedLost {
		t.Fatalf("awaited %v (lost %t) once the late call came", cn.awaited, cn.awaitedLost)
	}
	// the late call was read out of order: the analyzer may be out of step until it is clean again
	c.resync2(false)
}

// TestCoalescedCallsCoverTheirDataIDs: an event BPF coalesced from the calls with data ids first to last
// leaves no gap among them
func TestCoalescedCallsCoverTheirDataIDs(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 40000))
	first := c.dataID + 1
	c.dataID += 9
	c.callWith(ingress, body(30000), func(call *Call) {
		call.FirstDataID, call.DataLen = first, 0
	})
	cn := c.tr.conns[connKey{id: c.id, random: 7}]
	if len(cn.gaps) != 0 || cn.gapsLost {
		t.Fatalf("gaps %v (lost %t) behind a coalesced event of %d to %d", cn.gaps, cn.gapsLost, first, c.dataID)
	}
	c.expect("rest of the body", c.send(ingress, body(10000), 5000), true, true)
}

// TestInFlightClearsLostGaps: more missing data ids than kept are forgotten behind the newest call when
// it returned alone on its fd
func TestInFlightClearsLostGaps(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", 30000))
	c.dataID += maxGaps + 5
	c.expect("behind many gaps", c.sendWith(ingress, body(10000), inFlight(2)), false)
	if cn := c.tr.conns[connKey{id: c.id, random: 7}]; !cn.gapsLost {
		t.Fatalf("the gaps are kept")
	}
	c.expect("alone", c.sendWith(ingress, body(10000), inFlight(1)), true)
	c.expect("behind", c.send(ingress, body(10000)), true)
}

// TestCoalescedRangeCoveringAnAwaitedID: a coalesced event whose data ids cover a previous data id named by
// another call (other than its last one) proves nothing: the gaps are kept
func TestCoalescedRangeCoveringAnAwaitedID(t *testing.T) {
	c := newTestConn(t)
	alone := inFlight(1)
	c.sendWith(ingress, request("POST", 40000), alone)
	first := c.dataID + 1
	// a call names data id first+1 as its previous one before the coalesced event of first to first+3 comes
	c.dataID = first + 4
	c.callWith(egress, response(413, 0), func(call *Call) { call.InFlight, call.PrevDataID = 1, first+1 })
	c.callWith(ingress, body(20000), func(call *Call) {
		c.dataID--
		call.DataID, call.FirstDataID, call.DataLen, call.InFlight = first+3, first, 0, 1
	})
	cn := c.tr.conns[connKey{id: c.id, random: 7}]
	if !cn.awaitedLost {
		t.Fatalf("a coalesced event over an awaited data id is taken as proof")
	}
}

// TestChunkDataSkippedByBPF: the calls of chunk data BPF uploaded without their content keep the framing of
// a chunked body in step, and the message behind it is skipped
func TestChunkDataSkippedByBPF(t *testing.T) {
	c := newTestConn(t)
	c.send(ingress, request("POST", -1, "Transfer-Encoding: chunked"))
	c.send(ingress, "1000\r\n")
	bpf := func(call *Call) { call.DataLen = 0 }
	c.callWith(ingress, body(4096), bpf)
	c.send(ingress, "\r\n0\r\n\r\n")
	c.send(egress, response(200, 0))
	c.send(ingress, request("PUT", 10000))
	c.expect("body behind it", c.send(ingress, body(10000), 5000), true, true)
	// more than the chunk holds: out of step until the analyzer is clean again
	d := newTestConn(t)
	d.send(ingress, request("POST", -1, "Transfer-Encoding: chunked"))
	d.send(ingress, "10\r\n")
	before := giveUps[reasonOverrun].Load()
	d.callWith(ingress, body(4096), bpf)
	if giveUps[reasonOverrun].Load() != before+1 {
		t.Fatalf("no give up")
	}
	d.resync2(true)
}
