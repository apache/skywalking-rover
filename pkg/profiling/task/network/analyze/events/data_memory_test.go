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

package events_test

import (
	"encoding/binary"
	"testing"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
)

// eventSize is the size class of the event of the network profiling, which embeds the 20KB array
const eventSize = 21760

// TestSocketDataUploadEventMemory: with the event overhead of the access log (a small event) the memory protection
// charges an event of the network profiling its embedded array on top, and its release gives it all back; with the
// default overhead (an event that embeds the array) nothing is added
func TestSocketDataUploadEventMemory(t *testing.T) {
	old := buffer.SetEventSize(512)
	defer buffer.SetEventSize(old)
	// the header of an event (65 bytes, data_len at 6) and 4 bytes of data
	raw := make([]byte, 65+4)
	binary.LittleEndian.PutUint16(raw[6:], 4)
	copy(raw[65:], "abcd")

	before := buffer.InflightBytes()
	if !buffer.AcquireEvent() {
		t.Fatal("refused")
	}
	var e events.SocketDataUploadEvent
	e.ReadFrom(btf.NewReader(raw))
	if got := buffer.InflightBytes() - before; got != eventSize+64 {
		t.Errorf("an event in use holds %d bytes, want %d", got, eventSize+64)
	}
	buffer.ReleaseEvent(e.ReleaseBuffer())
	if got := buffer.InflightBytes(); got != before {
		t.Errorf("after the release %d bytes, before %d", got, before)
	}

	// a broken sample: the reader discards the event, which gives everything back
	if !buffer.AcquireEvent() {
		t.Fatal("refused")
	}
	var broken events.SocketDataUploadEvent
	r := btf.NewReader(raw[:67])
	broken.ReadFrom(r)
	if r.HasError() == nil {
		t.Fatal("a broken sample decoded")
	}
	broken.Discard()
	if got := buffer.InflightBytes(); got != before {
		t.Errorf("after the discard %d bytes, before %d", got, before)
	}

	// the default overhead covers the embedded array
	buffer.SetEventSize(old)
	if !buffer.AcquireEvent() {
		t.Fatal("refused")
	}
	beforeDefault := buffer.InflightBytes()
	var d events.SocketDataUploadEvent
	d.ReadFrom(btf.NewReader(raw))
	if got := buffer.InflightBytes() - beforeDefault; got != 0 {
		t.Errorf("charged %d with the default overhead", got)
	}
	buffer.ReleaseEvent(d.ReleaseBuffer())
	if got := buffer.InflightBytes(); got != before {
		t.Errorf("default: after the release %d bytes, before %d", got, before)
	}
}
