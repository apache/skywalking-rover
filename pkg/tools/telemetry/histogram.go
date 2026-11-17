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

package telemetry

import (
	"strconv"
	"sync/atomic"
)

// Histogram counts integer observations into fixed buckets and is written in the Prometheus histogram
// layout: <name>_bucket{le="..."} (cumulative), <name>_sum and <name>_count. Observe is lock free, so it
// can be called on the data path.
type Histogram struct {
	bounds []int64
	counts []atomic.Int64 // one per bound, plus the last for +Inf
	sum    atomic.Int64
	// scraped is the +Inf bucket of the last scrape of the buckets: the count a scrape writes after them (Write
	// orders the series by name, _bucket before _count), so the two always agree as Prometheus expects
	scraped atomic.Int64
}

// NewHistogram registers a histogram with the upper bounds of its buckets (ascending) and returns it
func NewHistogram(name, help string, bounds []int64) *Histogram {
	h := &Histogram{bounds: bounds, counts: make([]atomic.Int64, len(bounds)+1)}
	RegisterSeries(name+"_bucket", help, Counter, h.buckets)
	Register(name+"_sum", help+" (sum of the observations)", Counter, func() float64 { return float64(h.sum.Load()) })
	Register(name+"_count", help+" (number of observations)", Counter, func() float64 { return float64(h.scraped.Load()) })
	return h
}

// Observe adds one observation; a negative one counts as 0, so the sum, a counter, never goes down
func (h *Histogram) Observe(v int64) {
	v = max(v, 0)
	i := len(h.bounds)
	for b, bound := range h.bounds {
		if v <= bound {
			i = b
			break
		}
	}
	h.counts[i].Add(1)
	h.sum.Add(v)
}

func (h *Histogram) buckets() []Sample {
	samples := make([]Sample, 0, len(h.counts))
	var cumulative int64
	for i := range h.counts {
		cumulative += h.counts[i].Load()
		le := "+Inf"
		if i < len(h.bounds) {
			le = strconv.FormatInt(h.bounds[i], 10)
		}
		samples = append(samples, Sample{Labels: map[string]string{"le": le}, Value: float64(cumulative)})
	}
	h.scraped.Store(cumulative)
	return samples
}
