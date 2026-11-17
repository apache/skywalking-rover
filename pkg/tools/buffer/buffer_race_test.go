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
	"sync"
	"testing"
)

// TestAppendWhileReading appends data events, some of them out of order, on one goroutine while another
// moves the reading position the way an analysis pass does (PrepareForReading, Peek, ResetForLoopReading)
// without the event lock. The append must never read the reading position: it used to compare
// r.current with the new event in a deferred check, and a reader that reset the position between two
// loads of r.current crashed the agent with a nil pointer dereference. Run with -race.
func TestAppendWhileReading(t *testing.T) {
	const events = 20000
	buf := NewBuffer()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < events; i++ {
			id := uint64(i + 1)
			// every fourth event arrives before its predecessor
			switch i % 4 {
			case 2:
				id++
			case 3:
				id--
			}
			buf.AppendDataEvent(&testEvent{dataID: id, data: []byte("0123456789"), start: id})
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		peek := make([]byte, 4)
		for {
			select {
			case <-done:
				return
			default:
			}
			if buf.PrepareForReading() {
				_, _ = buf.Peek(peek)
			}
			buf.ResetForLoopReading()
		}
	}()
	wg.Wait()
	if !buf.PrepareForReading() {
		t.Fatalf("the buffer must hold the appended events")
	}
	if got := buf.dataEvents.Len(); got != events {
		t.Fatalf("%d events in the buffer, expected %d", got, events)
	}
}
