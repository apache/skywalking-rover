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

package protocols

import (
	"testing"
	"time"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// http2Backlog stands for a backlog between the reader and the partitions: while it holds, everything read since
// it began waits in a partition channel (btf.DeliveredThrough stays at its start)
func http2Backlog(t *testing.T) (release func()) {
	t.Helper()
	since := linkClock()
	old := http2DeliveredThrough
	http2DeliveredThrough = func() int64 { return since }
	released := false
	release = func() {
		if !released {
			released = true
			http2DeliveredThrough = old
		}
	}
	t.Cleanup(release)
	return release
}

// http2SmallWaits scales the gap and arrival waits down for a test
func http2SmallWaits(t *testing.T, wait time.Duration) {
	t.Helper()
	oldArrival := http2ArrivalWaitDuration
	oldGap := SetHTTP2GapWaitDuration(wait)
	http2ArrivalWaitDuration = wait
	t.Cleanup(func() {
		http2ArrivalWaitDuration = oldArrival
		SetHTTP2GapWaitDuration(oldGap)
	})
}

// TestHTTP2BackloggedQueueNoLateSkip: the socket call a request header block is in has been read from the rings,
// but waits in a partition channel that runs behind (a backlog of the analysis) for five times the arrival wait,
// while the events after it keep arriving. The parser must not give it up as missing: no gap, no late skip, no
// desync, and every header block decodes once it arrives. Without the backlog (the call really did not come) the
// same wait gives it up.
func TestHTTP2BackloggedQueueNoLateSkip(t *testing.T) {
	const wait = 100 * time.Millisecond
	http2SmallWaits(t, wait)
	for _, backlog := range []bool{true, false} {
		c := newHTTP2TestConn(t)
		client, server := newHTTP2Peer(), newHTTP2Peer()
		client.preface()
		client.settings()
		client.headers(1, true, append(requestFields("/first"), hf("x-session", "shared-session-abcdefghij"))...)
		first := client.take()
		// the delayed call adds a dynamic table entry the next ones refer to
		client.headers(3, true, append(requestFields("/second"), hf("x-trace", "trace-0123456789abcdef"))...)
		second := client.take()
		client.headers(5, true, append(requestFields("/third"), hf("x-trace", "trace-0123456789abcdef"))...)
		third := client.take()

		c.feedWithID(enums.SocketDataDirectionIngress, first, 0, 1, 0, bpfNow())
		c.analyze()
		var release func()
		if backlog {
			// the second call is read now and waits in the queue
			release = http2Backlog(t)
		}
		c.feedWithID(enums.SocketDataDirectionIngress, third, 0, 3, 2, bpfNow())
		// the other events of the connection keep flowing behind it, for five times the arrival wait
		server.settings()
		c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, 4, 3, bpfNow())
		id := uint64(4)
		for end := time.Now().Add(5 * wait); time.Now().Before(end); {
			time.Sleep(wait / 5)
			server.data(1, false, []byte("still flowing"))
			id++
			c.feedWithID(enums.SocketDataDirectionEgress, server.take(), 0, id, id-1, bpfNow())
			c.analyze()
		}
		m := c.metrics()
		if !backlog {
			// the call really did not come: given up after the wait, and skipped as late when it comes after all
			c.feedWithID(enums.SocketDataDirectionIngress, second, 0, 2, 1, bpfNow())
			c.analyze()
			if m.Gaps == 0 || m.LateSkips == 0 {
				t.Fatalf("without a backlog: gaps %d, late %d", m.Gaps, m.LateSkips)
			}
			continue
		}
		if m.Gaps != 0 || m.LateSkips != 0 || len(c.blocks[enums.SocketDataDirectionIngress]) != 1 {
			t.Fatalf("gave the queued call up: gaps %d, late %d, blocks %d", m.Gaps, m.LateSkips,
				len(c.blocks[enums.SocketDataDirectionIngress]))
		}
		// the queue drains
		release()
		c.feedWithID(enums.SocketDataDirectionIngress, second, 0, 2, 1, bpfNow())
		c.analyze()
		if m.Gaps != 0 || m.LateSkips != 0 || m.DecodeErrors != 0 || m.headerDesync[enums.SocketDataDirectionIngress] {
			t.Fatalf("gaps %d, late %d, decode %d, desync %t", m.Gaps, m.LateSkips, m.DecodeErrors,
				m.headerDesync[enums.SocketDataDirectionIngress])
		}
		blocks := c.blocks[enums.SocketDataDirectionIngress]
		if len(blocks) != 3 || blocks[1][":path"] != "/second" || blocks[2][":path"] != "/third" ||
			blocks[2]["x-trace"] != "trace-0123456789abcdef" {
			t.Fatalf("the header blocks: %v", blocks)
		}
	}
}

// TestHTTP2BackloggedQueueChunkNotSkipped: the second chunk event of a socket call waits in a backlogged partition
// channel while the first one is already old (its kernel time is beyond the gap wait): the parser must wait for it
// instead of resynchronizing at the next call. Without the backlog it resynchronizes (the chunk is lost).
func TestHTTP2BackloggedQueueChunkNotSkipped(t *testing.T) {
	const wait = 100 * time.Millisecond
	http2SmallWaits(t, wait)
	for _, backlog := range []bool{true, false} {
		c := newHTTP2TestConn(t)
		client := newHTTP2Peer()
		client.preface()
		client.settings()
		client.headers(1, true, requestFields("/chunked")...)
		call := client.take()
		half := len(call) - 10
		old := bpfNow() - uint64(2*wait)
		// the first chunk of call 1, the second one is read but queued (or lost)
		c.feedChunk(enums.SocketDataDirectionIngress, call, 0, half, 0, 1, 0, old)
		var release func()
		if backlog {
			release = http2Backlog(t)
		}
		// the next call arrives
		client.headers(3, true, requestFields("/next")...)
		c.feedWithID(enums.SocketDataDirectionIngress, client.take(), 0, 2, 1, old)
		for i := 0; i < 5; i++ {
			c.analyze()
			time.Sleep(wait / 2)
		}
		m := c.metrics()
		if !backlog {
			if m.FramingErrors == 0 {
				t.Fatal("without a backlog the missing chunk is not given up")
			}
			continue
		}
		if m.FramingErrors != 0 {
			t.Fatalf("gave the queued chunk up: framing %d", m.FramingErrors)
		}
		release()
		c.feedChunk(enums.SocketDataDirectionIngress, call, half, len(call), 1, 1, 0, old)
		c.analyze()
		blocks := c.blocks[enums.SocketDataDirectionIngress]
		if m.FramingErrors != 0 || m.LateSkips != 0 || len(blocks) != 2 || blocks[0][":path"] != "/chunked" {
			t.Fatalf("framing %d, late %d, blocks %v", m.FramingErrors, m.LateSkips, blocks)
		}
	}
}

// feedChunk delivers the bytes from..to of a socket call as its chunk event seq
func (c *http2TestConn) feedChunk(direction enums.SocketDataDirection, data []byte, from, to int, seq uint16,
	dataID, prevDataID, start uint64) {
	ev := &aclevents.SocketDataUploadEvent{
		Protocol0: enums.ConnectionProtocolHTTP2, Direction0: direction, Sequence0: seq,
		DataLen: uint16(to - from), StartTime0: start, EndTime0: start,
		ConnectionID: 1, RandomID: 1, DataID0: dataID, PrevDataID0: prevDataID, TotalSize0: uint64(len(data)),
	}
	if to == len(data) {
		ev.Finished = 1
	}
	ev.Buffer = buffer.AdmittedEventData(data[from:to])
	c.conn.AppendData(ev)
}
