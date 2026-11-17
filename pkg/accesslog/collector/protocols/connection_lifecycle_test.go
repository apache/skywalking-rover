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
	"bufio"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// TestAppendToRemovedConnectionReleases: an event the partition goroutine appends to a connection the analysis
// removed meanwhile gives its pooled buffer back, instead of holding it (and its share of the budget) forever
func TestAppendToRemovedConnectionReleases(t *testing.T) {
	protocols, _ := newFixedProtocols()
	p := newTestPartition(protocols)
	connection := p.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP, 1)
	// what processEvents0 does to a closed connection, with the partition goroutine holding it already
	connection.removed.Store(true)
	p.connections.Remove(common.NewConnectionKey(1, 1))
	connection.ReleasePendingData()

	before := eventsInUse()
	event := &aclevents.SocketDataUploadEvent{Protocol0: enums.ConnectionProtocolHTTP, ConnectionID: 1, RandomID: 1,
		DataID0: 2, Finished: 1}
	event.Buffer = buffer.AcquireEventBuffer(128)
	if event.Buffer == nil {
		t.Fatal("no buffer")
	}
	event.DataLen = 128
	p.AppendAndMaybeAnalyze(connection, event)
	if after := eventsInUse(); after != before {
		t.Fatalf("events in use: %d before the append, %d after", before, after)
	}
	if n := connection.PendingDataLength(); n != 0 {
		t.Fatalf("the removed connection holds %d events", n)
	}
}

// TestSummaryToRemovedConnectionRefused: a summary delivered after the connection released its summaries is
// refused (it goes on its own) instead of waiting in an inbox nothing takes anymore
func TestSummaryToRemovedConnectionRefused(t *testing.T) {
	r, _, _ := newDrainTest()
	p := newTestPartition([]Protocol{r})
	connection := p.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP2, 1)
	summary := &benchSummary{stream: 3, dir: enums.SocketDataDirectionEgress, bytes: 10, first: 2}
	if !AppendHTTP2Summary(connection, summary) {
		t.Fatal("a summary of a connection that is there is refused")
	}
	connection.ReleasePendingData()
	if AppendHTTP2Summary(connection, summary) {
		t.Fatal("a summary of a released connection is taken")
	}
}

// TestWasRemoved: the partition remembers the connections it removed, until it has the connection again or
// removedMemory passed
func TestWasRemoved(t *testing.T) {
	protocols, _ := newFixedProtocols()
	p := newTestPartition(protocols)
	connection := p.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP, 1)
	if p.WasRemoved(1, 1) {
		t.Fatal("a connection that is there is removed")
	}
	connection.closed = true
	p.processEvents0(true)
	if p.FindConnectionContext(1, 1) != nil || !p.WasRemoved(1, 1) {
		t.Fatal("a closed connection is not removed")
	}
	p.forgetRemoved(timeNowPlus(removedMemory / 2))
	if !p.WasRemoved(1, 1) {
		t.Fatal("a removed connection is forgotten early")
	}
	p.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP, 3)
	if p.WasRemoved(1, 1) {
		t.Fatal("a connection that is there again is removed")
	}
	p.forgetRemoved(timeNowPlus(removedMemory))
	if len(p.removed) != 0 {
		t.Fatalf("removed connections are not forgotten: %v", p.removed)
	}
}

// TestHTTP2WaitedForLessTheBacklog: an event is waited for since it was made, less how far the delivery was behind
// when the pass started, so a backlog of the partitions does not make the stale decisions give up on it
func TestHTTP2WaitedForLessTheBacklog(t *testing.T) {
	m := &HTTP2Metrics{}
	made := bpfNow() - uint64(5*time.Second)
	if waited := m.waitedFor(made); waited < 5*time.Second || waited > 6*time.Second {
		t.Fatalf("without a backlog: waited %s", waited)
	}
	m.links.behind = linkClock() - int64(10*time.Second)
	if waited := m.waitedFor(made); waited > 0 {
		t.Fatalf("behind a backlog of 10s: waited %s", waited)
	}
}

// TestHTTP2UpgradePathAsSent: the path of stream 1 is the request target as sent, without its query, as the
// :path of the other HTTP/2 streams is reported (not the decoded URL path)
func TestHTTP2UpgradePathAsSent(t *testing.T) {
	for target, want := range map[string]string{
		"/up/load":            "/up/load",
		"/a%2Fb/c?x=1":        "/a%2Fb/c",
		"/space%20here?q=a?b": "/space%20here",
	} {
		request, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n")))
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := http2UpgradePath(request); !ok || got != want {
			t.Fatalf("%s: %q, expected %q", target, got, want)
		}
	}
}

// TestHTTP2GoAwayForgetsUnprocessedStreams: the streams the client opened above the last stream id of the server's
// GOAWAY get no response and are forgotten; the ones at or below it are still reported
func TestHTTP2GoAwayForgetsUnprocessedStreams(t *testing.T) {
	c := newHTTP2TestConn(t)
	client, server := newHTTP2Peer(), newHTTP2Peer()
	client.preface()
	client.headers(1, true, requestFields("/kept")...)
	client.headers(3, true, requestFields("/refused")...)
	client.headers(5, true, requestFields("/refused-too")...)
	c.feed(enums.SocketDataDirectionIngress, client.take(), 0)
	c.analyze()
	if n := len(c.metrics().Streams); n != 3 {
		t.Fatalf("%d open streams", n)
	}
	_ = server.framer.WriteGoAway(1, http2.ErrCodeNo, nil)
	server.headers(1, true, hf(":status", "200"))
	c.feed(enums.SocketDataDirectionEgress, server.take(), 0)
	c.analyze()
	if n := len(c.metrics().Streams); n != 0 {
		t.Fatalf("%d streams left after the GOAWAY", n)
	}
	if len(c.analyzer.streams) != 1 || c.analyzer.streams[0].req[":path"] != "/kept" {
		t.Fatalf("reported streams: %+v", c.analyzer.streams)
	}
}
