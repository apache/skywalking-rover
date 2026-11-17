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

package events

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// uploadRecord is a perf record of a socket data event carrying data
func uploadRecord(t testing.TB, data []byte) []byte {
	var record bytes.Buffer
	wire := &socketDataUploadWire{Protocol0: enums.ConnectionProtocolHTTP2, Finished: 1, DataLen: uint16(len(data)),
		DataID0: 7, TotalSize0: uint64(len(data)), Direction0: enums.SocketDataDirectionIngress}
	if err := binary.Write(&record, binary.LittleEndian, wire); err != nil {
		t.Fatal(err)
	}
	record.Write(data)
	return record.Bytes()
}

func readUploadEvent(t testing.TB, record []byte) *SocketDataUploadEvent {
	e := &SocketDataUploadEvent{}
	reader := btf.NewReader(record)
	e.ReadFrom(reader)
	if err := reader.HasError(); err != nil {
		t.Fatalf("read: %v", err)
	}
	return e
}

// TestSmallEventKeepsDataInline: up to inlineDataSize bytes the data is kept in the event and no pooled
// buffer is taken or given back; above, the event takes one from the pool as before. Either way the
// data, the detached copy and the release read the same.
func TestSmallEventKeepsDataInline(t *testing.T) {
	for size := 0; size <= 3*inlineDataSize; size++ {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte('a' + (size+i)%26)
		}
		e := readUploadEvent(t, uploadRecord(t, data))
		if !bytes.Equal(e.BufferData(), data) || e.BufferLen() != size {
			t.Fatalf("size %d: read %q", size, e.BufferData())
		}
		if d := e.Detach(); d.Buffer != nil || d.BufferData() != nil || d.BufferLen() != size {
			t.Fatalf("size %d: the detached copy must not carry the data", size)
		}
		released := e.ReleaseBuffer()
		switch {
		case size == 0 && released != nil:
			t.Fatalf("an event without data has nothing to release")
		case size > 0 && size <= inlineDataSize && released != nil:
			t.Fatalf("size %d: the inline data must not go to the pool", size)
		case size > inlineDataSize && (len(released) != size || cap(released) < 2048):
			t.Fatalf("size %d: the pooled buffer is not given back (len %d, cap %d)", size, len(released), cap(released))
		}
		if e.Buffer != nil || e.BufferData() != nil {
			t.Fatalf("size %d: a released event must not expose data", size)
		}
		buffer.ReleaseBufferOnly(released)
		if e.ReleaseBuffer() != nil {
			t.Fatalf("size %d: a second release gives nothing back", size)
		}
	}
}

// TestSmallEventAccounting: the admission counter comes back to where it was for inline and pooled events
func TestSmallEventAccounting(t *testing.T) {
	before, _, _, _ := buffer.MemoryStats()
	for _, size := range []int{9, inlineDataSize, inlineDataSize + 1, 2000} {
		if !buffer.AcquireEvent() {
			t.Fatal("the memory protection is off in the test")
		}
		e := readUploadEvent(t, uploadRecord(t, make([]byte, size)))
		e.Discard()
	}
	if after, _, _, _ := buffer.MemoryStats(); after != before {
		t.Fatalf("events in use %d, before %d", after, before)
	}
}

// TestSmallEventRace reads events on one goroutine and analyzes and releases them on another, as the
// reader and the partitions do
func TestSmallEventRace(t *testing.T) {
	records := [][]byte{uploadRecord(t, []byte("settings-ack")), uploadRecord(t, bytes.Repeat([]byte{'d'}, 1500))}
	ch := make(chan *SocketDataUploadEvent, 16)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range ch {
			_ = e.Detach()
			if len(e.BufferData()) != e.BufferLen() {
				t.Errorf("read %d of %d bytes", len(e.BufferData()), e.BufferLen())
			}
			buffer.ReleaseBufferOnly(e.ReleaseBuffer())
		}
	}()
	for i := 0; i < 2000; i++ {
		ch <- readUploadEvent(t, records[i%len(records)])
	}
	close(ch)
	wg.Wait()
}
