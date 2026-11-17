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
	"sort"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The summaries of the skipped h2c DATA payload (summarize_h2c_payload, bpf/accesslog/common/h2c_sum.h).
//
// BPF does not upload the socket calls that lie wholly inside a DATA payload: it sums them up per stream and
// direction, and the positional event that follows them carries their bytes (buffer.SummaryGap), so the
// frames are parsed and every body is counted as before. What the parser does not get with the frames are the
// kernel log details of those calls: they come in summaries (HTTP2Summary), in any order with the frames,
// from the batches BPF sends and from the map the user space drains. A stream counts the summarized bytes of
// its body (HTTP2Streaming.summarized, from the gaps its DATA frames covered); once it ends, it is reported
// when the summaries of its stream id have brought those bytes, with the summaries attached
// (HTTP2Streaming.ReqSummaries, RespSummaries), which the analyzer turns into the details the calls would have
// given. A stream whose summaries do not arrive within http2SummaryWait is reported without the missing ones.
// A summary no stream takes (a reset stream, a stream that never ended, one the parser dropped) is handed to
// the analyzer on its own (HTTP2SummaryHandler.OnOrphanSummary), after http2SummaryOrphanAge.
//
// BPF also summarizes the calls of whole DATA frames (a run, buffer.SummaryGap with a stream): a writer that writes
// a frame per call (Go's server, writing a large response body) makes calls the parser reads nothing of but the
// frame header, which BPF summarizes header and all, in the direction of the responses, consecutive frames of one
// stream. The parser takes such a gap where a frame header is expected (handleSummaryRun): the payload goes into
// the body of the stream, and the gap, headers included, into what the summaries of the stream must bring, which
// count the calls as a whole.

// HTTP2Summary is a summary of the summarized calls of one stream and direction
type HTTP2Summary interface {
	SummaryStreamID() uint32
	SummaryDirection() enums.SocketDataDirection
	SummaryBytes() uint64
	// SummaryFirstDataID is the data id of the first call of the summary, which places it among the events
	SummaryFirstDataID() uint64
}

// HTTP2SummaryHandler is an optional interface of an HTTP2StreamAnalyzer, for the summaries
type HTTP2SummaryHandler interface {
	// DrainSummaries takes the summaries of the stream that BPF still keeps in the directions of the requests, when
	// the parser sees the stream end and misses some
	DrainSummaries(connectionID, randomID uint64, streamID uint32, requests []HTTP2DrainRequest) []HTTP2Summary
	// OnOrphanSummary is handed a summary that belongs to no reported stream
	OnOrphanSummary(connection *PartitionConnection, summary HTTP2Summary)
}

// HTTP2DrainRequest asks DrainSummaries for the summaries of one direction of a stream. Missing is the summarized
// bytes of the direction no summary brought yet (0: not known, as for a reset stream): a drain that took exactly
// that many bytes has every summary of the direction, and need not look further.
type HTTP2DrainRequest struct {
	Direction enums.SocketDataDirection
	Missing   uint64
}

var (
	// http2SummaryWait is how long an ended stream waits for its summaries: BPF sends the summary of a stream
	// when it sees the end of it, or the user space flushes it within about a second
	http2SummaryWait = 5 * time.Second
	// http2SummaryOrphanAge is how long a summary waits for a stream to take it. It stays below the time the
	// connection manager keeps a closed connection (25s, connectionDeleteDelayTime) with a flush period to spare:
	// the summaries of a connection that closes come about when it closes, and an orphan sent after the manager
	// forgot its connection would not be reported
	http2SummaryOrphanAge = 20 * time.Second
)

// SetHTTP2SummaryTimes replaces http2SummaryWait and http2SummaryOrphanAge, for the tests
func SetHTTP2SummaryTimes(wait, orphan time.Duration) (oldWait, oldOrphan time.Duration) {
	oldWait, oldOrphan = http2SummaryWait, http2SummaryOrphanAge
	http2SummaryWait, http2SummaryOrphanAge = wait, orphan
	return oldWait, oldOrphan
}

// http2Summaries is the summary state of a connection
type http2Summaries struct {
	// the summaries delivered to the connection and not taken by the analysis yet: they are delivered by the
	// partition goroutine while the analysis runs on its own
	inboxLock sync.Mutex
	inbox     []HTTP2Summary
	// closed is set (under inboxLock) when the connection goes (releaseSummaries): a summary delivered later is
	// not taken by anything anymore, so AppendHTTP2Summary refuses it and it goes on its own
	closed bool
	// owned by the analysis: the summaries by stream id, and the ended streams that wait for theirs
	byStream map[uint32]*http2StreamSummaries
	waiting  map[uint32]*http2WaitingStream
	// the streams reported or reset (stream ids are never reused on a connection): a summary of one that comes
	// later has no stream to wait for. Forgotten after http2SummaryOrphanAge.
	ended map[uint32]int64
	// endedQueue is the streams markEnded saw, in that order (so by time): ended forgets them from the front,
	// instead of a look at every one of them on every round
	endedQueue []http2EndedStream
	// touched are the stream ids summaries were added to since the last processSummaries (touchedSpare the
	// other buffer): only their streams can have become complete, or their summaries orphans of an ended
	// stream, between the sweeps over every waiting stream and every summary (lastSweep)
	touched      []uint32
	touchedSpare []uint32
	lastSweep    time.Time
	// drainQueued are the streams reportStream left waiting during this round without draining the map for them,
	// drainDue the ones of the round before: processSummaries drains for the due ones (still waiting, still
	// missing summaries) and makes the queued ones due. The summaries BPF sent when it saw the end of a direction
	// travel in a per-CPU batch that reaches the partition a little after the event of the end, so a drain at once
	// looked them up in vain (BPF had deleted them); one round later they have come, and the drain only looks
	// for what BPF keeps.
	drainQueued []uint32
	drainDue    []uint32
	// what an orphan is handed to, and what reports a waiting stream, when the connection goes
	// (ReleasePendingData)
	handler HTTP2SummaryHandler
	conn    *PartitionConnection
	owner   *HTTP2Protocol
}

// http2EndedStream is a stream markEnded saw, at (UnixNano): the times of ended and endedQueue are integers, not
// time.Time, so neither holds a pointer the garbage collector would have to scan (a connection remembers about
// http2SummaryOrphanAge of its streams)
type http2EndedStream struct {
	id uint32
	at int64
}

type http2StreamSummaries struct {
	pieces  []HTTP2Summary
	bytes   [3]uint64
	created time.Time
}

type http2WaitingStream struct {
	streaming *HTTP2Streaming
	since     time.Time
	// drainedAgain: the map was drained for the stream once more, half way through the wait
	drainedAgain bool
	// drained: the map was drained for the stream (reportStream defers the first drain to the next round,
	// drainDue)
	drained bool
}

// AppendHTTP2Summary delivers a summary to the HTTP/2 parser of the connection; false when the connection has
// no HTTP/2 parser
func AppendHTTP2Summary(connection *PartitionConnection, s HTTP2Summary) bool {
	m, ok := connection.Metrics(enums.ConnectionProtocolHTTP2).(*HTTP2Metrics)
	if !ok || m == nil || m.sums == nil {
		return false
	}
	m.sums.inboxLock.Lock()
	if m.sums.closed {
		m.sums.inboxLock.Unlock()
		return false
	}
	m.sums.inbox = append(m.sums.inbox, s)
	m.sums.inboxLock.Unlock()
	connection.markDataAppended()
	return true
}

func (r *HTTP2Protocol) summaryHandler() HTTP2SummaryHandler {
	h, _ := r.analyzer.(HTTP2SummaryHandler)
	return h
}

// takeSummaries moves the delivered summaries to their streams
func (m *HTTP2Metrics) takeSummaries() {
	if m.sums == nil {
		m.sums = &http2Summaries{}
	}
	m.sums.inboxLock.Lock()
	inbox := m.sums.inbox
	m.sums.inbox = nil
	m.sums.inboxLock.Unlock()
	for _, s := range inbox {
		m.addSummary(s)
	}
}

func (m *HTTP2Metrics) addSummary(s HTTP2Summary) {
	if m.sums == nil {
		m.sums = &http2Summaries{}
	}
	if m.sums.byStream == nil {
		m.sums.byStream = make(map[uint32]*http2StreamSummaries)
	}
	id := s.SummaryStreamID()
	st := m.sums.byStream[id]
	if st == nil {
		st = &http2StreamSummaries{created: time.Now()}
		m.sums.byStream[id] = st
	}
	st.pieces = append(st.pieces, s)
	if d := s.SummaryDirection(); int(d) < len(st.bytes) {
		st.bytes[d] += s.SummaryBytes()
	}
	m.sums.touched = append(m.sums.touched, id)
}

// summariesComplete tells whether the summaries of the stream bring the bytes it summarized
func (m *HTTP2Metrics) summariesComplete(id uint32, streaming *HTTP2Streaming) bool {
	var st *http2StreamSummaries
	if m.sums != nil {
		st = m.sums.byStream[id]
	}
	for d := range streaming.summarized {
		if streaming.summarized[d] == 0 {
			continue
		}
		if st == nil || st.bytes[d] < streaming.summarized[d] {
			return false
		}
	}
	return true
}

// attachSummaries hands the summaries of the stream to it, in the order of their calls, by the side of the
// stream they belong to
func (m *HTTP2Metrics) attachSummaries(id uint32, streaming *HTTP2Streaming) {
	if m.sums == nil {
		return
	}
	st := m.sums.byStream[id]
	if st == nil {
		return
	}
	delete(m.sums.byStream, id)
	sort.SliceStable(st.pieces, func(i, j int) bool {
		return st.pieces[i].SummaryFirstDataID() < st.pieces[j].SummaryFirstDataID()
	})
	for _, s := range st.pieces {
		if m.isRequestSide(s.SummaryDirection(), streaming) {
			streaming.ReqSummaries = append(streaming.ReqSummaries, s)
		} else {
			streaming.RespSummaries = append(streaming.RespSummaries, s)
		}
	}
}

func (m *HTTP2Metrics) isRequestSide(d enums.SocketDataDirection, streaming *HTTP2Streaming) bool {
	if m.requestDirection != 0 {
		return d == m.requestDirection
	}
	return !streaming.IsInResponse
}

// drainSummaries asks the analyzer for the summaries BPF still keeps of the stream, in the directions whose
// summaries are missing (streaming nil: both)
func (r *HTTP2Protocol) drainSummaries(m *HTTP2Metrics, id uint32, streaming *HTTP2Streaming) {
	h := r.summaryHandler()
	if h == nil {
		return
	}
	var requests []HTTP2DrainRequest
	var st *http2StreamSummaries
	if m.sums != nil {
		st = m.sums.byStream[id]
	}
	for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
		if streaming == nil {
			requests = append(requests, HTTP2DrainRequest{Direction: d})
			continue
		}
		var have uint64
		if st != nil {
			have = st.bytes[d]
		}
		if streaming.summarized[d] > 0 && have < streaming.summarized[d] {
			requests = append(requests, HTTP2DrainRequest{Direction: d, Missing: streaming.summarized[d] - have})
		}
	}
	if len(requests) == 0 {
		return
	}
	for _, s := range h.DrainSummaries(m.ConnectionID, m.RandomID, id, requests) {
		m.addSummary(s)
	}
}

// reportStream reports an ended stream, at once when its summaries are complete, otherwise once they are (or
// http2SummaryWait passed)
func (r *HTTP2Protocol) reportStream(connection *PartitionConnection, m *HTTP2Metrics, id uint32, streaming *HTTP2Streaming) {
	if streaming.summarized != [3]uint64{} {
		m.takeSummaries()
		if !m.summariesComplete(id, streaming) {
			// the map is drained for the stream the next round (drainDue), when what BPF sent at the end of the
			// stream has come: the stream waits until then
			if m.sums.waiting == nil {
				m.sums.waiting = make(map[uint32]*http2WaitingStream)
			}
			m.sums.waiting[id] = &http2WaitingStream{streaming: streaming, since: time.Now()}
			m.sums.drainQueued = append(m.sums.drainQueued, id)
			// what drains for a waiting stream when the connection goes before the next round (releaseSummaries)
			m.sums.owner = r
			return
		}
	}
	r.handleWholeStream(connection, m, id, streaming)
}

func (r *HTTP2Protocol) handleWholeStream(connection *PartitionConnection, m *HTTP2Metrics, id uint32, streaming *HTTP2Streaming) {
	m.attachSummaries(id, streaming)
	if streaming.summarized != [3]uint64{} {
		m.markEnded(id)
	}
	if err := r.analyzer.HandleWholeStream(connection, streaming); err != nil {
		http2Log.Debugf("failed to handle HTTP/2 stream, connection ID: %d, stream ID: %d, error: %v", m.ConnectionID, id, err)
	}
}

// http2SummarySweep is how often processSummaries looks at every waiting stream and every summary of a connection:
// between two sweeps it only looks at the streams summaries came for. So a stream that waited long enough, or a
// summary that waited long enough for a stream, is handled up to this late; a stream whose summaries come, or a
// summary of an ended stream, at once.
func http2SummarySweep() time.Duration {
	return min(time.Second, http2SummaryWait/5, http2SummaryOrphanAge/5)
}

// processSummaries takes the delivered summaries, reports the waiting streams whose summaries are complete or
// that waited long enough, and hands the summaries no stream takes to the analyzer. It runs on every analysis
// round of the connection, so it does not look at everything every time: at the streams new summaries came for,
// at every stream and summary once per http2SummarySweep, and at the ended streams to forget in their order.
//
//nolint:gocyclo // summary matching state machine run on every analysis round
func (r *HTTP2Protocol) processSummaries(connection *PartitionConnection, m *HTTP2Metrics) {
	if m.sums == nil {
		return
	}
	m.sums.handler, m.sums.conn, m.sums.owner = r.summaryHandler(), connection, r
	m.takeSummaries()
	sums := m.sums
	now := time.Now()
	sweep := now.Sub(sums.lastSweep) >= http2SummarySweep()
	if sweep {
		sums.lastSweep = now
	}
	// the streams whose drain reportStream deferred a round ago: drained for when still missing summaries (the
	// summaries a drain adds touch their stream, which is looked at below), and the ones of this round become due
	due := sums.drainDue
	sums.drainDue, sums.drainQueued = sums.drainQueued, nil
	for _, id := range due {
		if w, ok := sums.waiting[id]; ok && !w.drained {
			w.drained = true
			if !m.summariesComplete(id, w.streaming) {
				r.drainSummaries(m, id, w.streaming)
			}
		}
	}
	clear(due)
	sums.drainQueued = due[:0]
	// the streams touched until now; the ones a drain below touches are looked at the next time
	touched := sums.touched
	sums.touched = sums.touchedSpare[:0]
	if len(sums.waiting) > 0 {
		if sweep {
			for id, w := range sums.waiting {
				r.processWaiting(connection, m, id, w, now)
			}
		} else {
			for _, id := range touched {
				if w, ok := sums.waiting[id]; ok {
					r.processWaiting(connection, m, id, w, now)
				}
			}
		}
	}
	if len(sums.byStream) > 0 {
		if sweep {
			for id, st := range sums.byStream {
				m.orphanIfUnclaimed(id, st, now)
			}
		} else {
			for _, id := range touched {
				if st := sums.byStream[id]; st != nil {
					m.orphanIfUnclaimed(id, st, now)
				}
			}
		}
	}
	clear(touched)
	sums.touchedSpare = touched[:0]
	m.forgetEnded(now)
}

// processWaiting reports the waiting stream when its summaries are complete or it waited long enough, and drains
// what BPF still keeps of it once half way through the wait
func (r *HTTP2Protocol) processWaiting(connection *PartitionConnection, m *HTTP2Metrics, id uint32, w *http2WaitingStream,
	now time.Time) {
	complete := m.summariesComplete(id, w.streaming)
	if !complete && now.Sub(w.since) < http2SummaryWait {
		if !w.drainedAgain && now.Sub(w.since) > http2SummaryWait/2 {
			// what BPF still keeps is drained once more half way through the wait
			r.drainSummaries(m, id, w.streaming)
			w.drainedAgain = true
			complete = m.summariesComplete(id, w.streaming)
		}
		if !complete {
			return
		}
	}
	delete(m.sums.waiting, id)
	r.handleWholeStream(connection, m, id, w.streaming)
}

// orphanIfUnclaimed hands the summaries of the stream to the analyzer on their own when no stream takes them: the
// stream is not open and does not wait, and it ended, or the summaries waited http2SummaryOrphanAge for it
func (m *HTTP2Metrics) orphanIfUnclaimed(id uint32, st *http2StreamSummaries, now time.Time) {
	if _, open := m.Streams[id]; open {
		return
	}
	if _, waiting := m.sums.waiting[id]; waiting {
		return
	}
	if _, ended := m.sums.ended[id]; !ended && now.Sub(st.created) < http2SummaryOrphanAge {
		return
	}
	m.orphanSummaries(id)
}

// forgetEnded forgets the ended streams marked http2SummaryOrphanAge ago, from the front of endedQueue (a stream
// marked again since stays, with its later mark further back in the queue)
func (m *HTTP2Metrics) forgetEnded(now time.Time) {
	q := m.sums.endedQueue
	n := 0
	nowNanos, age := now.UnixNano(), int64(http2SummaryOrphanAge)
	for n < len(q) && nowNanos-q[n].at >= age {
		if at, ok := m.sums.ended[q[n].id]; ok && at == q[n].at {
			delete(m.sums.ended, q[n].id)
		}
		n++
	}
	if n == 0 {
		return
	}
	if n == len(q) {
		m.sums.endedQueue = q[:0]
		return
	}
	m.sums.endedQueue = q[n:]
}

// markEnded remembers a stream that was reported or reset, see http2Summaries.ended
func (m *HTTP2Metrics) markEnded(id uint32) {
	if m.sums.ended == nil {
		m.sums.ended = make(map[uint32]int64)
	}
	now := time.Now().UnixNano()
	m.sums.ended[id] = now
	m.sums.endedQueue = append(m.sums.endedQueue, http2EndedStream{id: id, at: now})
}

// orphanSummaries hands every summary of the stream to the analyzer on its own
func (m *HTTP2Metrics) orphanSummaries(id uint32) {
	if m.sums == nil {
		return
	}
	st := m.sums.byStream[id]
	if st == nil {
		return
	}
	delete(m.sums.byStream, id)
	for _, s := range st.pieces {
		if m.sums.handler != nil {
			m.sums.handler.OnOrphanSummary(m.sums.conn, s)
		}
	}
}

// resetStreamSummaries is a reset stream: the summaries BPF keeps of it are drained, and every summary of it is
// handed to the analyzer on its own (the later ones once they are orphans)
func (r *HTTP2Protocol) resetStreamSummaries(connection *PartitionConnection, m *HTTP2Metrics, id uint32, streaming *HTTP2Streaming) {
	if m.sums == nil {
		return
	}
	if _, waiting := m.sums.waiting[id]; waiting {
		// the stream ended before (a peer may reset a stream it has seen end): it waits for its summaries
		return
	}
	if streaming == nil || streaming.summarized == [3]uint64{} {
		if m.sums.byStream[id] == nil {
			return
		}
	} else {
		r.drainSummaries(m, id, nil)
	}
	m.sums.handler, m.sums.conn = r.summaryHandler(), connection
	m.takeSummaries()
	m.orphanSummaries(id)
	m.markEnded(id)
}

// pendingSummaries is the summaries and waiting streams the connection holds
func (m *HTTP2Metrics) pendingSummaries() int {
	if m.sums == nil {
		return 0
	}
	m.sums.inboxLock.Lock()
	n := len(m.sums.inbox)
	m.sums.inboxLock.Unlock()
	return n + len(m.sums.byStream) + len(m.sums.waiting)
}

// releaseSummaries reports the waiting streams and hands every other summary to the analyzer, when the
// connection goes
func (m *HTTP2Metrics) releaseSummaries() {
	if m.sums == nil {
		return
	}
	// from here on a delivered summary goes on its own (AppendHTTP2Summary): what came before is taken below
	m.sums.inboxLock.Lock()
	m.sums.closed = true
	m.sums.inboxLock.Unlock()
	m.takeSummaries()
	if r := m.sums.owner; r != nil {
		// a stream whose drain was deferred to a round that did not come: what BPF keeps of it is attached to
		// it as the drain at its end did before the deferral
		for id, w := range m.sums.waiting {
			if !w.drained {
				w.drained = true
				if !m.summariesComplete(id, w.streaming) {
					r.drainSummaries(m, id, w.streaming)
				}
			}
		}
		m.takeSummaries()
		m.sums.drainQueued, m.sums.drainDue = nil, nil
	}
	for id, w := range m.sums.waiting {
		delete(m.sums.waiting, id)
		if m.sums.owner != nil && m.sums.conn != nil {
			r := m.sums.owner
			r.handleWholeStream(m.sums.conn, m, id, w.streaming)
		}
	}
	for id := range m.sums.byStream {
		m.orphanSummaries(id)
	}
}
