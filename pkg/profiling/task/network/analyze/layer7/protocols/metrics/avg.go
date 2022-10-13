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
	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

type AvgCounter struct {
	Value float64
	Times int
}

func NewAvgCounter() *AvgCounter {
	return &AvgCounter{
		Value: 0,
		Times: 0,
	}
}

func (a *AvgCounter) Increase(val float64) {
	a.Value += val
	a.Times++
}

func (a *AvgCounter) MergeAndClean(other *AvgCounter) {
	a.Value += other.Value
	a.Times += other.Times

	// clean
	other.Value, other.Times = 0, 0
}

func (a *AvgCounter) Calculate() float64 {
	if a.Value == 0 {
		return 0
	}
	val := a.Value / float64(a.Times)
	return val
}

func (a *AvgCounter) CusHalfOfMetrics() Metrics {
	// avg counter don't need to cut half
	return a
}

func (a *AvgCounter) AppendMeter(list []*v3.MeterData, name string, labels []*v3.Label) []*v3.MeterData {
	if a.Value == 0 {
		return list
	}
	return append(list, &v3.MeterData{
		Metric: &v3.MeterData_SingleValue{
			SingleValue: &v3.MeterSingleValue{
				Name:   name,
				Labels: labels,
				Value:  a.Calculate(),
			},
		},
	})
}
