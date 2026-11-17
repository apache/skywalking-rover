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

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// drainAnalyzer is an HTTP/2 analyzer with summaries: the map BPF keeps (by stream and direction), the drains it
// was asked for, and the streams it reported with their summaries
type drainAnalyzer struct {
	kept     map[uint32][]HTTP2Summary
	drains   [][]HTTP2DrainRequest
	reported map[*HTTP2Streaming]int
	orphans  int
}

func (a *drainAnalyzer) HandleWholeStream(_ *PartitionConnection, s *HTTP2Streaming) error {
	a.reported[s] = len(s.ReqSummaries) + len(s.RespSummaries)
	return nil
}
func (a *drainAnalyzer) OnProtocolBreak(*PartitionConnection, *HTTP2Metrics) {}
func (a *drainAnalyzer) DrainSummaries(_, _ uint64, streamID uint32, requests []HTTP2DrainRequest) []HTTP2Summary {
	a.drains = append(a.drains, append([]HTTP2DrainRequest(nil), requests...))
	var out, rest []HTTP2Summary
	for _, s := range a.kept[streamID] {
		taken := false
		for _, r := range requests {
			if r.Direction == s.SummaryDirection() {
				taken = true
			}
		}
		if taken {
			out = append(out, s)
		} else {
			rest = append(rest, s)
		}
	}
	a.kept[streamID] = rest
	return out
}
func (a *drainAnalyzer) OnOrphanSummary(*PartitionConnection, HTTP2Summary) { a.orphans++ }

func newDrainTest() (*HTTP2Protocol, *HTTP2Metrics, *drainAnalyzer) {
	a := &drainAnalyzer{kept: make(map[uint32][]HTTP2Summary), reported: make(map[*HTTP2Streaming]int)}
	r := NewHTTP2Analyzer(nil, a)
	m := r.GenerateConnection(1, 1).(*HTTP2Metrics)
	return r, m, a
}

func summarisedStream(id uint32, in, out uint64) *HTTP2Streaming {
	_ = id
	s := &HTTP2Streaming{}
	s.summarised[enums.SocketDataDirectionIngress] = in
	s.summarised[enums.SocketDataDirectionEgress] = out
	return s
}

// TestReportStreamDefersTheDrain: a stream that ends without all of its summaries waits one round before the map
// is drained for it; a summary BPF sent that comes in that round is not looked for in the map, and the drain asks
// only for the bytes still missing
func TestReportStreamDefersTheDrain(t *testing.T) {
	in, out := enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress
	r, m, a := newDrainTest()
	a.kept[3] = []HTTP2Summary{&benchSummary{stream: 3, dir: out, bytes: 700, first: 20}}
	s3 := summarisedStream(3, 500, 700)
	r.reportStream(nil, m, 3, s3)
	if len(a.drains) != 0 || len(a.reported) != 0 {
		t.Fatalf("drained %d times, reported %d at the end of the stream", len(a.drains), len(a.reported))
	}
	// the same round: nothing drained yet
	r.processSummaries(nil, m)
	if len(a.drains) != 0 || len(a.reported) != 0 {
		t.Fatalf("drained in the round of the end: %v", a.drains)
	}
	// the summary BPF sent at the end of the requests arrives with the next round's events
	m.addSummary(&benchSummary{stream: 3, dir: in, bytes: 500, first: 10})
	r.processSummaries(nil, m)
	if len(a.drains) != 1 || len(a.drains[0]) != 1 || a.drains[0][0] != (HTTP2DrainRequest{Direction: out, Missing: 700}) {
		t.Fatalf("drains %v, want one for the egress 700 bytes", a.drains)
	}
	if got, ok := a.reported[s3]; !ok || got != 2 {
		t.Fatalf("reported %v, want stream 3 with 2 summaries", a.reported)
	}

	// a stream whose summaries all come before the next round is never drained for
	r, m, a = newDrainTest()
	s5 := summarisedStream(5, 500, 0)
	r.reportStream(nil, m, 5, s5)
	r.processSummaries(nil, m)
	m.addSummary(&benchSummary{stream: 5, dir: in, bytes: 500, first: 10})
	r.processSummaries(nil, m)
	r.processSummaries(nil, m)
	if len(a.drains) != 0 || a.reported[s5] != 1 {
		t.Fatalf("drains %v, reported %v", a.drains, a.reported)
	}

	// a complete stream is reported at once, no drain
	r, m, a = newDrainTest()
	m.addSummary(&benchSummary{stream: 7, dir: in, bytes: 500, first: 10})
	s7 := summarisedStream(7, 500, 0)
	r.reportStream(nil, m, 7, s7)
	if len(a.drains) != 0 || a.reported[s7] != 1 {
		t.Fatalf("complete: drains %v, reported %v", a.drains, a.reported)
	}
}

// TestReleaseDrainsDeferredStreams: a connection that goes before the round the drain was deferred to still
// drains for its waiting streams, so their summaries are attached as before
func TestReleaseDrainsDeferredStreams(t *testing.T) {
	out := enums.SocketDataDirectionEgress
	r, m, a := newDrainTest()
	a.kept[9] = []HTTP2Summary{&benchSummary{stream: 9, dir: out, bytes: 64, first: 30}}
	s9 := summarisedStream(9, 0, 64)
	r.reportStream(nil, m, 9, s9)
	m.sums.conn = &PartitionConnection{}
	m.releaseSummaries()
	if len(a.drains) != 1 || a.reported[s9] != 1 || a.orphans != 0 {
		t.Fatalf("drains %v, reported %v, orphans %d", a.drains, a.reported, a.orphans)
	}
}

// TestEndedTimesAreIntegers: the ended streams are forgotten after http2SummaryOrphanAge as before
func TestEndedTimesAreIntegers(t *testing.T) {
	_, m, _ := newDrainTest()
	m.markEnded(3)
	m.markEnded(5)
	if len(m.sums.ended) != 2 || len(m.sums.endedQueue) != 2 {
		t.Fatalf("ended %d, queue %d", len(m.sums.ended), len(m.sums.endedQueue))
	}
	m.forgetEnded(timeNowPlus(http2SummaryOrphanAge / 2))
	if len(m.sums.ended) != 2 {
		t.Fatalf("forgotten too early")
	}
	m.markEnded(3) // marked again: its later mark stays when the first one is forgotten
	m.sums.endedQueue[0].at -= int64(time.Second)
	m.sums.endedQueue[1].at -= int64(time.Second)
	m.sums.ended[5] -= int64(time.Second)
	m.forgetEnded(timeNowPlus(http2SummaryOrphanAge - time.Second/2))
	if _, ok := m.sums.ended[3]; !ok || len(m.sums.ended) != 1 {
		t.Fatalf("ended after the first marks went: %v", m.sums.ended)
	}
	m.forgetEnded(timeNowPlus(3 * http2SummaryOrphanAge))
	if len(m.sums.ended) != 0 || len(m.sums.endedQueue) != 0 {
		t.Fatalf("ended %d, queue %d after every age", len(m.sums.ended), len(m.sums.endedQueue))
	}
}

func timeNowPlus(d time.Duration) time.Time { return time.Now().Add(d) }

// benchSummary is a summary of the tests (HTTP2Summary)
type benchSummary struct {
	stream uint32
	dir    enums.SocketDataDirection
	bytes  uint64
	first  uint64
}

func (s *benchSummary) SummaryStreamID() uint32                     { return s.stream }
func (s *benchSummary) SummaryDirection() enums.SocketDataDirection { return s.dir }
func (s *benchSummary) SummaryBytes() uint64                        { return s.bytes }
func (s *benchSummary) SummaryFirstDataID() uint64                  { return s.first }
