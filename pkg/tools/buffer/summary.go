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

package buffer

import (
	"fmt"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// The summaries of the h2c DATA payload (summarize_h2c_payload, bpf/accesslog/common/h2c_sum.h).
//
// BPF does not upload the socket calls that lie wholly inside a DATA payload: it adds them to a summary of
// their stream, and the next socket call of the direction it uploads (a positional event) carries how many
// payload bytes it summarized since the previous one (SummarizedBefore). Those bytes come right in front of
// that event in the stream of the direction, inside the payload of one DATA frame. The HTTP/2 parser puts a
// SummaryGap of that size in front of the event: a payload skipped element, which DiscardBytes counts as a
// whole like a call uploaded without its content, so every frame stays where it is and every body keeps its
// size. The gap carries no kernel log detail: the details of the summarized calls come with the summaries.
//
// The summarized bytes can also be a run (SummaryRun): whole DATA frames of one stream, each a call of its own
// that BPF summarized header and all because the parser reads nothing of it but its length (a writer that
// writes a frame per call, as Go's server writes a large response body). Such a gap lies on frame boundaries:
// the parser takes it where it expects a frame header, as that many frames of the stream without END_STREAM or
// PADDED, whose payload is its size less the frame headers (HTTP2 handleSummaryRun).
//
// The last frame of a run can be open (H2C_SUM_RUN_OPEN): its payload goes on behind the gap, in the calls of the event
// that carries the run and the following ones (a reader that reads a frame header with the start of its payload and the
// rest in other calls, as Go's HTTP/2 client does). BPF marks the stream of such a run (summaryRunOpen) and gives the
// rest of the payload of that frame, from the start of the call of the event (SummaryRunOpenBuffer): the gap keeps it
// (Open), and the parser counts that many bytes behind the gap into the frame.
//
// A run can also start behind summarized payload of the frame in front of it (H2C_SUM_RUN_HEAD), its head: the frame
// whose header the parser read from an earlier event, whose payload it discards when it gets to the gap. BPF marks
// the frames of such a run (summaryRunHead); the discard (Buffer.DiscardBytes) takes the bytes it still wants of the
// gap as the head (Head), stops in front of the gap, and the parser takes the run behind the head where it expects
// the next frame header.

// SummarizedBeforeBuffer is implemented by the events that can carry summarized payload bytes in front of
// them
type SummarizedBeforeBuffer interface {
	SummarizedBefore() uint32
}

// SummarizedBefore is the payload bytes BPF summarized in front of the event, 0 for an event that carries
// none. Only the first chunk of a call counts (every chunk of it carries the same value).
func SummarizedBefore(b SocketDataBuffer) uint32 {
	s, ok := b.(SummarizedBeforeBuffer)
	if !ok || b.DataSequence() != 0 {
		return 0
	}
	return s.SummarizedBefore()
}

// What the h2c follower of BPF knew of the frames of a socket call (h2c_frames of the event, H2C_FRAMES_* in
// bpf/accesslog/syscalls/h2c.h): H2CFramesKnown, it knew where the frames were at the start of the call (and the
// offset of the first frame header that starts in the call is given, 0xffff when none does); H2CFramesNoHeaderBlock,
// no byte of the call belongs to a HEADERS, CONTINUATION or PUSH_PROMISE frame (no header, no payload, no rest of
// one from the call before); H2CFramesStartsInHeaderBlock, the bytes in front of the first frame header (all of them
// when there is none) belong to such a frame (the rest of one from the call before). None when nothing is known.
// Behind the first frame header BPF does not tell the frames apart: H2CFramesNoHeaderBlock is only set for a call
// without a frame header (or one header of a frame the parser discards), and the frames from the offset on are in
// the bytes of the event (every byte up to where BPF cut the call; what it cut is DATA payload).
const (
	H2CFramesKnown               = 1
	H2CFramesNoHeaderBlock       = 2
	H2CFramesStartsInHeaderBlock = 4
	h2cFramesFlags               = H2CFramesKnown | H2CFramesNoHeaderBlock | H2CFramesStartsInHeaderBlock
)

// H2CFramesBuffer is implemented by the events that carry what the h2c follower knew of the frames of their call
type H2CFramesBuffer interface {
	H2CFrames() (flags uint8, firstFrameOff uint16)
}

// H2CFramesOf is what the h2c follower knew of the frames of the call of the event (the event of a slice end
// included): the flags and the offset of the first frame header in the call, ok false when the event carries none
// (flags 0: nothing is known). Every chunk of a call carries the values of the call.
func H2CFramesOf(b SocketDataBuffer) (flags uint8, firstFrameOff uint16, ok bool) {
	if limited, isLimited := b.(*SocketDataEventLimited); isLimited {
		b = limited.SocketDataBuffer
	}
	f, isFrames := b.(H2CFramesBuffer)
	if !isFrames {
		return 0, 0xffff, false
	}
	flags, firstFrameOff = f.H2CFrames()
	return flags, firstFrameOff, true
}

// SummaryRunBuffer is implemented by the events that can carry a run in front of them: the stream and the
// frames the summarized bytes in front of them are, stream 0 when they are payload of one frame. The stream is
// the one BPF sent: with summaryRunOpen when the last frame of the run is open (summaryRunOf takes it apart).
type SummaryRunBuffer interface {
	SummaryRun() (stream uint32, frames uint16)
}

// summaryRunOpen marks the stream of a run whose last frame is open behind the run (H2C_SUM_RUN_OPEN in
// bpf/accesslog/common/h2c_sum.h); a stream id has 31 bits
const summaryRunOpen = 1 << 31

// summaryRunHead marks the frames of a run that starts behind a head (H2C_SUM_RUN_HEAD), the count is below it
const summaryRunHead = 1 << 15

// summaryRunOf is the run in front of the event (SummaryRunBuffer), 0 when there is none, and whether the run
// starts behind a head
func summaryRunOf(b SocketDataBuffer) (stream uint32, frames uint16, head bool) {
	s, ok := b.(SummaryRunBuffer)
	if !ok || b.DataSequence() != 0 {
		return 0, 0, false
	}
	stream, frames = s.SummaryRun()
	if stream &^= summaryRunOpen; stream == 0 {
		return 0, 0, false
	}
	return stream, frames &^ summaryRunHead, frames&summaryRunHead != 0
}

// SummaryRunOpenBuffer is implemented by the events that can carry a run whose last frame is open: the rest of the
// payload of that frame from the start of the call of the event, as BPF sent it (H2C_SUM_RUN_OPEN in
// bpf/accesslog/common/h2c_sum.h)
type SummaryRunOpenBuffer interface {
	SummaryRunOpenRest() uint32
}

// SummaryRunIsOpen tells whether a stream of a run as BPF sent it (SummaryRunBuffer) is the one of a run whose last
// frame is open
func SummaryRunIsOpen(stream uint32) bool {
	return stream&summaryRunOpen != 0 && stream&^summaryRunOpen != 0
}

// SummaryRunOpenRest is the rest of the payload of the open last frame of the run in front of the event, from the
// start of its call: 0 when there is no run or its last frame is not open, -1 when it is open but the event does not
// tell the rest (BPF never sends one)
func SummaryRunOpenRest(b SocketDataBuffer) int64 {
	s, ok := b.(SummaryRunBuffer)
	if !ok || b.DataSequence() != 0 {
		return 0
	}
	if stream, _ := s.SummaryRun(); !SummaryRunIsOpen(stream) {
		return 0
	}
	o, ok := b.(SummaryRunOpenBuffer)
	if !ok {
		return -1
	}
	if rest := o.SummaryRunOpenRest(); rest > 0 {
		return int64(rest)
	}
	return -1
}

// SummaryGap stands for the payload bytes BPF summarized in front of a positional event (Next). It sorts right in
// front of the event: the data id of the event and the sequence -1. It is not finished, so neither the
// end of the call nor the upload accounting of the data id are taken from it.
type SummaryGap struct {
	// Stream and Frames: the gap is a run of that many whole DATA frames of the stream (Size counts their
	// headers), Stream 0 when it is payload of one frame
	Stream uint32
	Frames uint16
	// Open is the rest of the payload of the last frame of the run behind the gap when that frame is open (0 when
	// it is not, -1 when it is open and the rest is not known)
	Open int64
	// Headed: the run starts behind a head, payload of the frame in front of it; Head is that head once a discard
	// took it (the part of Size that is not the run)
	Headed       bool
	Head         uint64
	Size         uint64
	ConnectionID uint64
	RandomID     uint64
	DataID0      uint64
	PrevDataID0  uint64
	StartTime0   uint64
	Direction0   enums.SocketDataDirection
	Protocol0    enums.ConnectionProtocol
}

// NewSummaryGap makes the gap of size bytes in front of next. It is counted as an event in use, which its
// release (ReleaseEvent of its ReleaseBuffer) takes back.
func NewSummaryGap(next SocketDataBuffer, size uint32, connectionID, randomID uint64) *SummaryGap {
	eventsInUse.Add(1)
	stream, frames, headed := summaryRunOf(next)
	var open int64
	if stream != 0 {
		open = SummaryRunOpenRest(next)
	}
	return &SummaryGap{
		Stream: stream, Frames: frames, Open: open, Headed: headed,
		Size: uint64(size), ConnectionID: connectionID, RandomID: randomID, DataID0: next.DataID(),
		PrevDataID0: next.PrevDataID(), StartTime0: next.StartTime(), Direction0: next.Direction(),
		Protocol0: next.Protocol(),
	}
}

func (g *SummaryGap) Protocol() enums.ConnectionProtocol { return g.Protocol0 }
func (g *SummaryGap) GenerateConnectionID() string {
	return fmt.Sprintf("%d_%d", g.ConnectionID, g.RandomID)
}
func (g *SummaryGap) BufferData() []byte                   { return nil }
func (g *SummaryGap) TotalSize() uint64                    { return g.Size }
func (g *SummaryGap) Direction() enums.SocketDataDirection { return g.Direction0 }
func (g *SummaryGap) BufferStartPosition() int             { return 0 }
func (g *SummaryGap) BufferLen() int                       { return 0 }
func (g *SummaryGap) DataID() uint64                       { return g.DataID0 }
func (g *SummaryGap) PrevDataID() uint64                   { return g.PrevDataID0 }
func (g *SummaryGap) DataSequence() int                    { return -1 }
func (g *SummaryGap) IsStart() bool                        { return true }
func (g *SummaryGap) IsFinished() bool                     { return false }
func (g *SummaryGap) HaveReduceDataAfterChunk() bool       { return false }
func (g *SummaryGap) StartTime() uint64                    { return g.StartTime0 }
func (g *SummaryGap) EndTime() uint64                      { return g.StartTime0 }
func (g *SummaryGap) ReleaseBuffer() []byte                { return nil }
func (g *SummaryGap) PayloadSkipped() bool                 { return true }
func (g *SummaryGap) BodyPayloadSkipped() bool             { return false }

// summaryGapOf is the buffer as a SummaryGap (or the gap of a slice end of one), nil when it is none
func summaryGapOf(b SocketDataBuffer) *SummaryGap {
	if limited, ok := b.(*SocketDataEventLimited); ok {
		b = limited.SocketDataBuffer
	}
	g, _ := b.(*SummaryGap)
	return g
}

// IsSummaryGap tells whether the buffer is a SummaryGap (or a slice end of one)
func IsSummaryGap(b SocketDataBuffer) bool {
	if limited, ok := b.(*SocketDataEventLimited); ok {
		b = limited.SocketDataBuffer
	}
	_, ok := b.(*SummaryGap)
	return ok
}

// SummaryRunGap is the buffer as a SummaryGap that is a run of whole frames, nil when it is not one
func SummaryRunGap(b SocketDataBuffer) *SummaryGap {
	if g, ok := b.(*SummaryGap); ok && g.Stream != 0 {
		return g
	}
	return nil
}
