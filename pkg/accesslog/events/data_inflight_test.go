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
	"sync"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
)

// TestInflightChargeOfSmallEvents: an inline event is charged the event overhead only, a pooled one the
// overhead plus the capacity of its pool class, and both give it back on release
func TestInflightChargeOfSmallEvents(t *testing.T) {
	charge := func(size int) int64 {
		before := buffer.InflightBytes()
		if !buffer.AcquireEvent() {
			t.Fatal("the memory protection is off in the test")
		}
		e := readUploadEvent(t, uploadRecord(t, make([]byte, size)))
		held := buffer.InflightBytes() - before
		e.Discard()
		if after := buffer.InflightBytes(); after != before {
			t.Fatalf("size %d: in-flight %d after the release, %d before", size, after, before)
		}
		return held
	}
	inline, pooled := charge(13), charge(40)
	if inline <= 0 || pooled-inline != 2048 {
		t.Fatalf("inline charge %d, pooled charge %d: want the 2048 byte class between them", inline, pooled)
	}
}

// TestInflightBalanceWithDetach reads inline and pooled events on several goroutines and analyzes them
// on others, which detach the metadata and release the events through every release path, as the
// partitions do; the in-flight accounting must come back to where it was
func TestInflightBalanceWithDetach(t *testing.T) {
	records := [][]byte{uploadRecord(t, []byte("settings-ack")), uploadRecord(t, bytes.Repeat([]byte{'d'}, 1500)),
		uploadRecord(t, bytes.Repeat([]byte{'x'}, 9000)), uploadRecord(t, nil)}
	before, _, _, _ := buffer.MemoryStats()
	inflightBefore := buffer.InflightBytes()
	ch := make(chan *SocketDataUploadEvent, 64)
	var analyzers sync.WaitGroup
	for a := 0; a < 4; a++ {
		analyzers.Add(1)
		go func(a int) {
			defer analyzers.Done()
			conn := buffer.NewBuffer()
			n := 0
			for e := range ch {
				detached := e.Detach()
				if detached.Buffer != nil {
					t.Error("the detached copy must not carry the buffer")
				}
				switch n % 3 {
				case 0:
					e.Discard()
				case 1:
					buffer.ReleaseEvent(e.ReleaseBuffer())
				default:
					conn.AppendDataEvent(e)
				}
				n++
				if n%50 == 0 {
					conn.Clean()
				}
			}
			conn.ReleaseAll()
		}(a)
	}
	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func(r int) {
			defer readers.Done()
			for i := 0; i < 1000; i++ {
				if !buffer.AcquireEvent() {
					t.Error("the memory protection is off in the test")
					return
				}
				ch <- readUploadEvent(t, records[(i+r)%len(records)])
			}
		}(r)
	}
	readers.Wait()
	close(ch)
	analyzers.Wait()
	if after, _, _, _ := buffer.MemoryStats(); after != before {
		t.Fatalf("events in use %d, before %d", after, before)
	}
	if got := buffer.InflightBytes(); got != inflightBefore {
		t.Fatalf("in-flight %d, before %d", got, inflightBefore)
	}
}
