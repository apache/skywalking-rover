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
	"bytes"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"

	"golang.org/x/net/http2"
)

// TestHTTP2DroppedHeaderBytesWithFrameFlags: droppedHeaderBytes with what BPF knew of the frames of the call
// (h2c_frames bits 0-2 and first_frame_off) against the conservative walk without them
func TestHTTP2DroppedHeaderBytesWithFrameFlags(t *testing.T) {
	frames := func(write func(f *http2.Framer)) []byte {
		var b bytes.Buffer
		write(http2.NewFramer(&b, nil))
		return b.Bytes()
	}
	rest := []byte("rest!") // the end of a frame of the call before
	dataOnly := frames(func(f *http2.Framer) {
		_ = f.WritePing(false, [8]byte{})
		_ = f.WriteRawFrame(0xfe, 0, 0, []byte("unknown type"))
		_ = f.WriteData(1, false, []byte("payload"))
	})
	headers := frames(func(f *http2.Framer) {
		_ = f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82, 0x86}, EndHeaders: true})
	})
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	withHeaders := cat(dataOnly, headers)
	headersThenData := cat(headers, dataOnly)
	// a DATA frame whose payload runs past the uploaded bytes to the end of the call (BPF's cut)
	cutData := frames(func(f *http2.Framer) { _ = f.WriteData(1, false, make([]byte, 100)) })[:http2FrameHeaderLen]

	cases := []struct {
		name  string
		flags *HTTP2CallFrames
		data  []byte
		from  int
		total int // the size of the call when BPF uploaded less (0: the bytes)
		want  bool
	}{
		{"no flags, not a frame boundary", nil, cat(rest, dataOnly), 0, 0, true},
		{"no header bytes", &HTTP2CallFrames{CursorKnown: true, NoHeaderBytes: true, FirstFrameOffset: -1}, []byte("anything"), 0, 0, false},
		{"rest of a header block", &HTTP2CallFrames{CursorKnown: true, StartsInHeaderBlock: true, FirstFrameOffset: 5},
			cat(rest, dataOnly), 0, 0, true},
		{"rest of a header block, already parsed", &HTTP2CallFrames{CursorKnown: true, StartsInHeaderBlock: true, FirstFrameOffset: 5},
			cat(rest, dataOnly), 5, 0, false},
		{"all rest of a header block", &HTTP2CallFrames{CursorKnown: true, StartsInHeaderBlock: true, FirstFrameOffset: -1}, rest, 0, 0, true},
		{"all rest of a DATA payload", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: -1}, rest, 0, 0, false},
		{"rest of DATA, then control and unknown frames", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 5}, cat(rest, dataOnly), 0, 0, false},
		{"rest of DATA, then a HEADERS frame", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 5}, cat(rest, withHeaders), 0, 0, true},
		{"HEADERS before the offset", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 0}, headersThenData, len(headers), 0, false},
		{"HEADERS reaching past the offset", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 0}, headersThenData, len(headers) - 1, 0, true},
		{"cut by BPF inside a DATA payload", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 0},
			cat(dataOnly, cutData), 0, len(dataOnly) + http2FrameHeaderLen + 100, false},
		{"cut by the upload limit behind whole frames", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 0}, dataOnly, 0, len(dataOnly) + 50, true},
		{"a frame header cut before its type", &HTTP2CallFrames{CursorKnown: true, FirstFrameOffset: 0}, cat(dataOnly, []byte{0, 0}), 0, 0, true},
	}
	defer SetHTTP2CallFramesSource(nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flags := c.flags
			SetHTTP2CallFramesSource(func(buffer.SocketDataBuffer) (HTTP2CallFrames, bool) {
				if flags == nil {
					return HTTP2CallFrames{}, false
				}
				return *flags, true
			})
			ev := testEvent(c.data, hpIn)
			if c.total > 0 {
				ev.TotalSize0, ev.HaveReduce = uint64(c.total), 1
			}
			m := newHTTP2TestConn(t).metrics()
			if got := m.droppedHeaderBytes(hpIn, ev, c.from); got != c.want {
				t.Fatalf("droppedHeaderBytes = %v, want %v", got, c.want)
			}
		})
	}
}
