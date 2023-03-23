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
	"reflect"
	"testing"
	"time"
)

var (
	defaultTime = time.Now()
)

func TestAdd(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		dataOp func(window *TimeWindows[float64, float64])
		result []float64
	}{
		{
			name: "normal",
			size: 3,
			dataOp: func(window *TimeWindows[float64, float64]) {
				addData(window, 1, 1)
				addData(window, 2, 2)
				addData(window, 3, 3)
			},
			result: []float64{1, 2, 3},
		},
		{
			name: "out of count",
			size: 3,
			dataOp: func(window *TimeWindows[float64, float64]) {
				addData(window, 1, 1)
				addData(window, 2, 2)
				addData(window, 3, 3)
				addData(window, 4, 4)
			},
			result: []float64{2, 3, 4},
		},
		{
			name: "add older data",
			size: 3,
			dataOp: func(window *TimeWindows[float64, float64]) {
				addData(window, 1, 1)
				addData(window, 2, 2)
				addData(window, 3, 3)
				addData(window, 4, 4)
				addData(window, 2, 4)
				addData(window, 1, 8)
				addData(window, 0, 10)
			},
			result: []float64{4, 3, 4},
		},
		{
			name: "add new data which bigger than windows count",
			size: 3,
			dataOp: func(window *TimeWindows[float64, float64]) {
				addData(window, 1, 1)
				addData(window, 4, 2)
				addData(window, 5, 3)
				addData(window, 7, 5)
			},
			result: []float64{3, 0, 5},
		},
	}

	for _, tt := range tests {
		windows := timeWindows(tt.size)
		tt.dataOp(windows)
		actualValue := getAllValues(windows)
		if !reflect.DeepEqual(tt.result, actualValue) {
			t.Fatalf("test [%s] failure, expceted: %v, actual: %v", tt.name, tt.result, actualValue)
		}
	}
}

func TestFlushData(t *testing.T) {
	tests := []struct {
		name       string
		size       int
		operations []interface{}
	}{
		{
			name: "normal[most recent]",
			size: 3,
			operations: []interface{}{
				appendDataOperation{1, 1},
				mostRecentDataChecker{1, true},
				mostRecentDataChecker{0, false},

				appendDataOperation{2, 2},
				appendDataOperation{3, 3},
				mostRecentDataChecker{3, true},
				mostRecentDataChecker{0, false},
			},
		},
		{
			name: "has older data[most recent]",
			size: 3,
			operations: []interface{}{
				appendDataOperation{1, 1},
				appendDataOperation{2, 2},
				appendDataOperation{1, 3},
				mostRecentDataChecker{2, true},
				mostRecentDataChecker{0, false},

				appendDataOperation{3, 3},
				appendDataOperation{4, 4},
				appendDataOperation{1, 9},
				mostRecentDataChecker{4, true},
				mostRecentDataChecker{0, false},
			},
		},
		{
			name: "normal[multiple recent]",
			size: 3,
			operations: []interface{}{
				appendDataOperation{1, 1},
				appendDataOperation{2, 2},
				appendDataOperation{3, 3},
				multipleRecentDataChecker{[]float64{3, 2, 1}, true},
				multipleRecentDataChecker{nil, false},

				appendDataOperation{4, 4},
				multipleRecentDataChecker{[]float64{4}, true},
				multipleRecentDataChecker{nil, false},
			},
		},
		{
			name: "has older data[multiple recent]",
			size: 3,
			operations: []interface{}{
				appendDataOperation{1, 1},
				appendDataOperation{2, 2},
				appendDataOperation{4, 4},
				multipleRecentDataChecker{[]float64{4, 2}, true},
				multipleRecentDataChecker{nil, false},

				appendDataOperation{1, 1},
				multipleRecentDataChecker{nil, false},
			},
		},
	}

	for _, tt := range tests {
		windows := timeWindows(tt.size)
		for _, op := range tt.operations {
			switch v := op.(type) {
			case appendDataOperation:
				addData(windows, v.second, v.value)
			case mostRecentDataChecker:
				val, hasData := windows.FlushMostRecentData()
				if val != v.value || v.hasData != hasData {
					t.Fatalf("test[%s] failure, excepted: %v-%t, actual: %v-%t", tt.name,
						v.value, v.hasData, val, hasData)
				}
			case multipleRecentDataChecker:
				val, hasData := windows.FlushMultipleRecentData()
				if !reflect.DeepEqual(val, v.value) || v.hasData != hasData {
					t.Fatalf("test[%s] failure, excepted: %v-%t, actual: %v-%t", tt.name,
						v.value, v.hasData, val, hasData)
				}
			}
		}
	}
}

type appendDataOperation struct {
	second int
	value  float64
}

type mostRecentDataChecker struct {
	value   float64
	hasData bool
}

type multipleRecentDataChecker struct {
	value   []float64
	hasData bool
}

func addData(win *TimeWindows[float64, float64], second int, val float64) {
	result := defaultTime.Add(time.Second * time.Duration(second))
	win.Add(result, val)
}

func timeWindows(count int) *TimeWindows[float64, float64] {
	return NewTimeWindows([]*PolicyItem{{Period: count}}, func() WindowData[float64, float64] {
		return NewLatestWindowData[float64]()
	})
}

func getAllValues(win *TimeWindows[float64, float64]) []float64 {
	result := make([]float64, 0)
	for e := win.data.Front(); e != nil; e = e.Next() {
		result = append(result, e.Value.(*windowDataWrapper[float64, float64]).Get())
	}
	return result
}
