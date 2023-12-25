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
	"container/list"
	"testing"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/events"
)

func TestOffsetPosition(t *testing.T) {
	type position struct {
		eventIndex  int
		bufferIndex int
	}
	var tests = []struct {
		events  []int
		current position
		offset  int
		result  *position
	}{
		{
			events:  []int{10, 10, 10},
			current: position{0, 0},
			offset:  10,
			result:  &position{1, 0},
		},
		{
			events:  []int{10, 10, 10},
			current: position{1, 0},
			offset:  -10,
			result:  &position{0, 0},
		},
		{
			events:  []int{10, 10, 10},
			current: position{2, 5},
			offset:  -10,
			result:  &position{1, 5},
		},
		{
			events:  []int{10, 10, 10},
			current: position{2, 5},
			offset:  -20,
			result:  &position{0, 5},
		},
		{
			events:  []int{10, 10, 10},
			current: position{2, 5},
			offset:  10,
			result:  nil,
		},
	}

	for _, test := range tests {
		eventList := list.New()
		buffer := Buffer{dataEvents: eventList}
		var curElement *list.Element
		for i, e := range test.events {
			element := eventList.PushBack(&events.SocketDataUploadEvent{
				DataID0: uint64(i),
				DataLen: uint16(e),
			})
			if i == test.current.eventIndex {
				curElement = element
			}
		}

		buffer.PrepareForReading()
		buffer.current = &Position{element: curElement, bufIndex: test.current.bufferIndex}
		offsetPosition := buffer.OffsetPosition(test.offset)
		if offsetPosition == nil && test.result == nil {
			continue
		}
		if int(offsetPosition.element.Value.(*events.SocketDataUploadEvent).DataID()) != test.result.eventIndex ||
			offsetPosition.bufIndex != test.result.bufferIndex {
			t.Fatalf("excepted: %d,%d, actual: %d,%d", test.result.eventIndex, test.result.bufferIndex,
				offsetPosition.element.Value.(*events.SocketDataUploadEvent).DataID(), offsetPosition.bufIndex)
		}
	}
}
