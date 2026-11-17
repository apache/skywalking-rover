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

import "testing"

// TestSummaryGapBetweenACutCallAndTheNext: a call cut behind its header (truncated, 9 of 100 bytes uploaded),
// 4000 summarised bytes in front of the next call, which starts with the rest of the payload: the discard of
// the payload counts the 91 bytes the cut call did not upload and the gap, reports the gap as summarised, and
// stops in the next call; removing the read elements keeps the upload accounting of the next call's data id
// (the gap shares it), so a truncation of that call is still measured right
func TestSummaryGapBetweenACutCallAndTheNext(t *testing.T) {
	next := &truncatedEvent{testEvent: testEvent{dataID: 5, data: []byte("PAYLOADnext")}, total: 40}
	gap := NewSummaryGap(next, 4000, 1, 1)
	b := skipTestBuffer(true,
		&truncatedEvent{testEvent: testEvent{dataID: 1, data: []byte("header123")}, total: 100},
		gap, next)
	head := make([]byte, 9)
	if err := b.ReadUntilBufferFull(head); err != nil {
		t.Fatalf("read the header: %v", err)
	}
	b.SetFollowTruncation(true)
	result, err := b.DiscardBytes(91 + 4000 + 7)
	if err != nil || result.Consumed != 4098 || result.Virtual != 4091 || result.Summarised != 4000 {
		t.Fatalf("discard: %+v %v", result, err)
	}
	if b.RemoveReadElements(false) {
		t.Fatalf("the next call was removed")
	}
	if uploaded := b.UploadedBytes(5); uploaded != int64(len(next.data)) {
		t.Fatalf("the next call uploaded %d bytes, the buffer counts %d", len(next.data), uploaded)
	}
	if !IsSummaryGap(gap) || !IsPayloadSkipped(gap) || gap.IsFinished() || gap.DataSequence() != -1 {
		t.Fatalf("the gap is not a skipped, unfinished element in front of its event")
	}
	if SummarisedBefore(gap) != 0 {
		t.Fatalf("a gap carries no summarised bytes of its own")
	}
}

// TestSummaryGapSortsInFrontOfItsEvent: a gap appended after its event still goes in front of it
func TestSummaryGapSortsInFrontOfItsEvent(t *testing.T) {
	next := &testEvent{dataID: 7, data: []byte("frame")}
	b := skipTestBuffer(true, &testEvent{dataID: 3, data: []byte("abc")}, next, NewSummaryGap(next, 10, 1, 1))
	var order []int
	for _, e := range b.TotalBuffer() {
		order = append(order, e.DataSequence())
	}
	if len(order) != 3 || order[1] != -1 || order[2] != 0 {
		t.Fatalf("order %v", order)
	}
}
