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
	"fmt"
	"reflect"
	"testing"

	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// bodySliceView is what the stream analyzers read of a body buffer
type bodySliceView struct {
	Size       int64
	From, To   uint64
	ToFinished bool
	Details    []uint64
	FirstID    uint64
	FirstStart uint64
	LastID     uint64
	Events     []string
	WithHeader []string
	Combined   int64
}

func viewOfBody(header, body *buffer.Buffer) bodySliceView {
	v := bodySliceView{Size: body.DataSize(), Combined: buffer.CombineSlices(true, nil, header, body).DataSize()}
	idRange := body.BuildTotalDataIDRange()
	v.From, v.To, v.ToFinished = idRange.From, idRange.To, idRange.IsToBufferReadFinished
	for e := body.BuildDetails().Front(); e != nil; e = e.Next() {
		v.Details = append(v.Details, e.Value.(*aclevents.SocketDataUploadEvent).DataID0)
	}
	v.FirstID, v.FirstStart = body.FirstSocketBuffer().DataID(), body.FirstSocketBuffer().StartTime()
	v.LastID = body.LastSocketBuffer().DataID()
	describe := func(events []buffer.SocketDataBuffer) (out []string) {
		for _, e := range events {
			out = append(out, fmt.Sprintf("%d/%d/%d/%q", e.DataID(), e.BufferStartPosition(), e.BufferLen(), e.BufferData()))
		}
		return out
	}
	// the analyzers walk the events of the four buffers of a stream together, never of one alone (a single
	// buffer would be returned as it is, with the offset of a partly read head not applied)
	v.Events = describe(buffer.CombinedSocketBuffers(body, nil))
	v.WithHeader = describe(buffer.CombinedSocketBuffers(header, body))
	return v
}

// TestHTTP2AppendBodySliceMatchesAppendSlices: keeping the slice of the first DATA frame as the body
// reads the same as the buffer AppendSlices builds from it, for a slice starting inside an event or not,
// of one event or several, with virtual bytes, and once the next frame is appended
func TestHTTP2AppendBodySliceMatchesAppendSlices(t *testing.T) {
	connBuf := buffer.NewBuffer()
	db := buffer.NewViewBuffer(connBuf)
	for id := uint64(1); id <= 6; id++ {
		ev := &aclevents.SocketDataUploadEvent{Protocol0: enums.ConnectionProtocolHTTP2, Direction0: enums.SocketDataDirectionIngress,
			DataLen: 10, StartTime0: 100 + id, EndTime0: 200 + id, DataID0: id, PrevDataID0: id - 1, TotalSize0: 10, Finished: 1}
		ev.Buffer = buffer.AdmittedEventData([]byte(fmt.Sprintf("event-%04d", id)))
		db.AppendDataEvent(ev)
		connBuf.AppendDetailEvent(&aclevents.SocketDataUploadEvent{DataID0: id, StartTime0: 100 + id, EndTime0: 200 + id})
	}
	at := func(offset int) *buffer.Position {
		db.PrepareForReading()
		return db.OffsetPosition(offset)
	}
	header := db.Slice(true, at(0), at(3))
	cases := []struct{ from, to, nextTo int }{
		{3, 7, 12},  // inside one event
		{0, 10, 25}, // a whole event
		{3, 25, 38}, // across events, starting inside one
		{10, 30, 59},
		{5, 6, 7},
	}
	for _, c := range cases {
		for _, virtual := range []int64{0, 7} {
			first := func() *buffer.Buffer {
				s := db.Slice(true, at(c.from), at(c.to))
				s.AddVirtualBytes(virtual)
				return s
			}
			next := func() *buffer.Buffer { return db.Slice(true, at(c.to), at(c.nextTo)) }
			want := buffer.AppendSlices(true, connBuf, nil, first())
			got := http2AppendBodySlice(connBuf, nil, first())
			if w, g := viewOfBody(header, want), viewOfBody(header, got); !reflect.DeepEqual(w, g) {
				t.Fatalf("%+v virtual %d: first frame\nwant %+v\ngot  %+v", c, virtual, w, g)
			}
			want = buffer.AppendSlices(true, connBuf, want, next())
			got = http2AppendBodySlice(connBuf, got, next())
			if w, g := viewOfBody(header, want), viewOfBody(header, got); !reflect.DeepEqual(w, g) {
				t.Fatalf("%+v virtual %d: second frame\nwant %+v\ngot  %+v", c, virtual, w, g)
			}
		}
	}
	if http2AppendBodySlice(connBuf, nil, nil) == nil {
		t.Fatal("a missing slice still goes through AppendSlices")
	}
}
