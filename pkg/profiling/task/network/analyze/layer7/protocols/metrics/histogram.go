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

type Histogram struct {
	Buckets []float64
	Values  []int
}

func NewHistogram(buckets []float64) *Histogram {
	values := make([]int, len(buckets))
	return &Histogram{
		Buckets: buckets,
		Values:  values,
	}
}

func (h *Histogram) Increase(val float64) {
	for inx, curVal := range h.Buckets {
		if inx > 0 && curVal > val {
			h.Values[uint64(inx-1)]++
			return
		}
	}
	h.Values[len(h.Buckets)-1]++
}

func (h *Histogram) MergeAndClean(other *Histogram) {
	for inx, val := range other.Values {
		h.Values[inx] += val
	}

	// clean
	for inx := range other.Values {
		other.Values[inx] = 0
	}
}

func (h *Histogram) CusHalfOfMetrics() Metrics {
	result := NewHistogram(h.Buckets)
	for inx, val := range h.Values {
		result.Values[inx] = val / 2
	}
	return result
}

func (h *Histogram) AppendMeter(list []*v3.MeterData, name string, labels []*v3.Label) []*v3.MeterData {
	values := make([]*v3.MeterBucketValue, 0)
	var haveValue = false
	for inx, bucket := range h.Buckets {
		val := h.Values[inx]
		if val > 0 {
			haveValue = true
		}
		values = append(values, &v3.MeterBucketValue{
			Bucket: bucket,
			Count:  int64(val),
		})
	}

	// is no data, then ignore it
	if !haveValue {
		return list
	}
	return append(list, &v3.MeterData{
		Metric: &v3.MeterData_Histogram{
			Histogram: &v3.MeterHistogram{
				Name:   name,
				Labels: labels,
				Values: values,
			},
		},
	})
}
