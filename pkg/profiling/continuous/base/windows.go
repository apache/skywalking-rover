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

package base

import (
	"container/list"
	"sync"
	"time"
)

// WindowData the slot data under TimeWindows
type WindowData[D any, R any] interface {
	// Reset the data content
	Reset()
	// Accept add data
	Accept(data D)
	// Get calculate the result
	Get() R
}

// LatestWindowData only save the last data in one slot
type LatestWindowData[D comparable] struct {
	Value D
}

func NewLatestWindowData[D comparable]() WindowData[D, D] {
	return &LatestWindowData[D]{}
}

func (t *LatestWindowData[D]) Reset() {
	var empty D
	t.Value = empty
}

func (t *LatestWindowData[D]) Accept(data D) {
	t.Value = data
}

func (t *LatestWindowData[D]) Get() D {
	return t.Value
}

type TimeWindows[V any, R any] struct {
	data            *list.List
	endTime         *time.Time
	windowLocker    sync.RWMutex
	windowGenerator func() WindowData[V, R]

	// mark the latest flush endTime
	lastFlushTime *time.Time
}

func NewTimeWindows[V any, R any](items []*PolicyItem, generator func() WindowData[V, R]) *TimeWindows[V, R] {
	var maxPeriod int
	for _, i := range items {
		if i.Period > maxPeriod {
			maxPeriod = i.Period
		}
	}
	generatorWrapper := func() WindowData[V, R] {
		return newWindowDataWrapper[V, R](generator)
	}

	window := &TimeWindows[V, R]{
		data:            list.New(),
		windowGenerator: generatorWrapper,
	}

	for i := 0; i < maxPeriod; i++ {
		window.data.PushFront(generatorWrapper())
	}
	return window
}

func (t *TimeWindows[V, R]) MatchRule(policy *PolicyItem, check func(slot R) bool) (lastMatch R, isMatch bool) {
	t.windowLocker.RLock()
	defer t.windowLocker.RUnlock()

	needsCount := policy.Count
	matchedCount := 0
	for e := t.data.Back(); e != nil; e = e.Prev() {
		getVal := e.Value.(*windowDataWrapper[V, R]).Get()
		if check(getVal) {
			matchedCount++
			lastMatch = getVal
		}
	}
	return lastMatch, matchedCount >= needsCount
}

func (t *TimeWindows[V, R]) ScalePeriod(items []*PolicyItem) {
	var maxPeriod int
	for _, i := range items {
		if i.Period > maxPeriod {
			maxPeriod = i.Period
		}
	}

	t.windowLocker.Lock()
	defer t.windowLocker.Unlock()
	if t.data.Len() == maxPeriod {
		return
	}

	val := maxPeriod - t.data.Len()
	if val > 0 {
		// need scale up
		for i := 0; i < val; i++ {
			t.data.PushBack(t.windowGenerator())
		}
	} else {
		// need to scale down
		val = -val
		for i := 0; i < val; i++ {
			t.data.Remove(t.data.Back())
		}
	}
}

func (t *TimeWindows[D, R]) Add(tm time.Time, val D) {
	if t.endTime == nil {
		t.endTime = &tm
	}

	second := int(t.endTime.Sub(tm).Seconds())
	if second < 0 {
		t.moveTo(tm)
		second = 0
	}

	if second >= t.data.Len() {
		// add the older data, ignore it
		return
	}

	t.appendDataToSlot(t.data.Len()-second-1, val)
}

func (t *TimeWindows[D, R]) FlushMostRecentData() (R, bool) {
	endTime := t.endTime
	if !t.shouldFlush(endTime) {
		var empty R
		return empty, false
	}
	t.lastFlushTime = endTime
	return t.data.Back().Value.(*windowDataWrapper[D, R]).Get(), true
}

func (t *TimeWindows[D, R]) FlushMultipleRecentData() ([]R, bool) {
	endTime := t.endTime
	if !t.shouldFlush(endTime) {
		return nil, false
	}
	result := make([]R, 0)
	slotCount := t.data.Len()
	if t.lastFlushTime != nil {
		slotCount = int(t.endTime.Sub(*t.lastFlushTime).Seconds()) - 1
	}
	for e := t.data.Back(); e != nil && slotCount >= 0; e = e.Prev() {
		if e.Value.(*windowDataWrapper[D, R]).hasData {
			result = append(result, e.Value.(*windowDataWrapper[D, R]).Get())
		}
		slotCount--
	}
	t.lastFlushTime = endTime
	return result, true
}

func (t *TimeWindows[D, R]) shouldFlush(endTime *time.Time) bool {
	if endTime == nil {
		return false
	}
	if t.lastFlushTime == nil {
		return true
	}

	return t.lastFlushTime != endTime && t.lastFlushTime.Before(*endTime)
}

func (t *TimeWindows[D, R]) moveTo(tm time.Time) {
	t.windowLocker.Lock()
	defer t.windowLocker.Unlock()

	addSeconds := int(tm.Sub(*t.endTime).Seconds())
	if addSeconds <= 0 {
		// same second or older
		return
	} else if addSeconds > t.data.Len() {
		// out of second count
		for e := t.data.Front(); e != nil; e = e.Next() {
			e.Value.(*windowDataWrapper[D, R]).Reset()
		}
	} else {
		for i := 0; i < addSeconds; i++ {
			// remove the older data
			first := t.data.Remove(t.data.Front()).(*windowDataWrapper[D, R])
			first.Reset()
			t.data.PushBack(first)
		}
	}
	t.endTime = &tm
}

func (t *TimeWindows[V, R]) appendDataToSlot(index int, data V) {
	t.windowLocker.RLock()
	defer t.windowLocker.RUnlock()

	if index < 0 || index > t.data.Len() {
		return
	}

	dataLen := t.data.Len()
	var element *list.Element
	if index < (dataLen >> 1) {
		d := t.data.Front()
		for i := 0; i < index; i++ {
			d = d.Next()
		}
		element = d
	} else {
		d := t.data.Back()
		for i := dataLen - 1; i > index; i-- {
			d = d.Prev()
		}
		element = d
	}

	element.Value.(*windowDataWrapper[V, R]).Accept(data)
}

type windowDataWrapper[D any, R any] struct {
	WindowData[D, R]
	hasData bool
}

func newWindowDataWrapper[D any, R any](generator func() WindowData[D, R]) *windowDataWrapper[D, R] {
	return &windowDataWrapper[D, R]{
		WindowData: generator(),
		hasData:    false,
	}
}

func (t *windowDataWrapper[D, R]) Reset() {
	t.hasData = false
	t.WindowData.Reset()
}

func (t *windowDataWrapper[D, R]) Accept(data D) {
	t.hasData = true
	t.WindowData.Accept(data)
}
