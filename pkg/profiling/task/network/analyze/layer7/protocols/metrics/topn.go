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

package metrics

import (
	"container/list"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
)

type TopN struct {
	MaxLength int
	List      *list.List
}

type TopNData interface {
	Flush(duration int64, process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder)
}

type TopNRecord struct {
	Duration int64
	Data     TopNData
}

func NewTopN(length int) *TopN {
	return &TopN{
		MaxLength: length,
		List:      list.New(),
	}
}

func (t *TopN) AddRecord(data TopNData, duration int64) {
	// don't need to be added if the duration is lower than the latest value
	if t.List.Len() >= t.MaxLength && t.List.Back().Value.(*TopNRecord).Duration > duration {
		return
	}
	node := t.createNode(data, duration)
	if t.List.Len() == 0 {
		t.List.PushFront(node)
		return
	}

	// insert to the list
	added := false
	for element := t.List.Back(); element != nil; element = element.Prev() {
		if element.Value.(*TopNRecord).Duration < duration {
			t.List.InsertBefore(node, element)
			added = true
			break
		}
	}
	if !added {
		t.List.PushBack(node)
	}

	// remove latest value
	if t.List.Len() > t.MaxLength {
		t.List.Remove(t.List.Back())
	}
}

func (t *TopN) MergeAndClean(other *TopN) {
	for element := other.List.Front(); element != nil; element = element.Next() {
		record := element.Value.(*TopNRecord)
		t.AddRecord(record.Data, record.Duration)
	}

	other.List.Init()
}

func (t *TopN) AppendData(process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) int {
	result := 0
	for element := t.List.Front(); element != nil; element = element.Next() {
		record := element.Value.(*TopNRecord)
		record.Data.Flush(record.Duration, process, traffic, metricsBuilder)
		result++
	}
	return result
}

func (t *TopN) createNode(data TopNData, duration int64) *TopNRecord {
	return &TopNRecord{Data: data, Duration: duration}
}
