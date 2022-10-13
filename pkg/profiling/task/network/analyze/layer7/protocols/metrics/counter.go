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

import v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"

type Counter struct {
	value int
}

func NewCounter() *Counter {
	return &Counter{
		value: 0,
	}
}

func (c *Counter) Increase() {
	c.value++
}

func (c *Counter) Get() int {
	return c.value
}

func (c *Counter) MergeAndClean(other *Counter) {
	c.value += other.value

	// clean
	other.value = 0
}

func (c *Counter) CusHalfOfMetrics() Metrics {
	result := NewCounter()
	result.value = c.value / 2
	return result
}

func (c *Counter) AppendMeter(list []*v3.MeterData, name string, labels []*v3.Label) []*v3.MeterData {
	if c.value == 0 {
		return list
	}

	return append(list, &v3.MeterData{
		Metric: &v3.MeterData_SingleValue{
			SingleValue: &v3.MeterSingleValue{
				Name:   name,
				Labels: labels,
				Value:  float64(c.value),
			},
		},
	})
}
