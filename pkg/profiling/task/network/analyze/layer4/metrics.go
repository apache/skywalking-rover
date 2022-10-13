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

package layer4

import "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"

type Metrics struct {
	// basic statics
	// read/write
	WriteCounter *SocketDataCounterWithHistory
	ReadCounter  *SocketDataCounterWithHistory
	// write RTT
	WriteRTTCounter *SocketDataCounterWithHistory

	// histograms
	// write execute time and RTT
	WriteRTTHistogram     *SocketDataHistogramWithHistory
	WriteExeTimeHistogram *SocketDataHistogramWithHistory
	// read execute time
	ReadExeTimeHistogram *SocketDataHistogramWithHistory

	// the connection connect or close execute time
	ConnectExecuteTime      uint64
	CloseExecuteTime        uint64
	ConnectCounter          *SocketDataCounterWithHistory
	CloseCounter            *SocketDataCounterWithHistory
	ConnectExeTimeHistogram *SocketDataHistogramWithHistory
	CloseExeTimeHistogram   *SocketDataHistogramWithHistory

	// exception counters
	RetransmitCounter *SocketDataCounterWithHistory
	DropCounter       *SocketDataCounterWithHistory
}

func NewLayer4Metrics() *Metrics {
	return &Metrics{
		WriteCounter:            NewSocketDataCounterWithHistory(),
		ReadCounter:             NewSocketDataCounterWithHistory(),
		WriteRTTCounter:         NewSocketDataCounterWithHistory(),
		WriteRTTHistogram:       NewSocketDataHistogramWithHistory(HistogramDataUnitUS),
		WriteExeTimeHistogram:   NewSocketDataHistogramWithHistory(HistogramDataUnitNS),
		ReadExeTimeHistogram:    NewSocketDataHistogramWithHistory(HistogramDataUnitNS),
		ConnectCounter:          NewSocketDataCounterWithHistory(),
		ConnectExeTimeHistogram: NewSocketDataHistogramWithHistory(HistogramDataUnitNS),
		CloseCounter:            NewSocketDataCounterWithHistory(),
		CloseExeTimeHistogram:   NewSocketDataHistogramWithHistory(HistogramDataUnitNS),
		RetransmitCounter:       NewSocketDataCounterWithHistory(),
		DropCounter:             NewSocketDataCounterWithHistory(),
	}
}

func (l *Metrics) MergeMetricsFromConnection(connection *base.ConnectionContext) {
	metrics := connection.Metrics.GetMetrics(Name).(*Metrics)

	l.WriteCounter.IncreaseToCurrent(metrics.WriteCounter.CalculateIncrease())
	l.ReadCounter.IncreaseToCurrent(metrics.ReadCounter.CalculateIncrease())
	l.WriteRTTCounter.IncreaseToCurrent(metrics.WriteRTTCounter.CalculateIncrease())

	l.WriteRTTHistogram.IncreaseToCurrent(metrics.WriteRTTHistogram.CalculateIncrease())
	l.WriteExeTimeHistogram.IncreaseToCurrent(metrics.WriteExeTimeHistogram.CalculateIncrease())
	l.ReadExeTimeHistogram.IncreaseToCurrent(metrics.ReadExeTimeHistogram.CalculateIncrease())

	l.RetransmitCounter.IncreaseToCurrent(metrics.RetransmitCounter.CalculateIncrease())
	l.DropCounter.IncreaseToCurrent(metrics.DropCounter.CalculateIncrease())

	if connection.FlushDataCount == 0 && metrics.ConnectExecuteTime > 0 {
		l.ConnectCounter.IncreaseToCurrent(NewSocketDataCounterWithValue(0, 1, metrics.ConnectExecuteTime))
		l.ConnectExeTimeHistogram.Cur.IncreaseByValue(metrics.ConnectExecuteTime)
	}
	if connection.FlushDataCount == 0 && metrics.CloseExecuteTime > 0 {
		l.CloseCounter.IncreaseToCurrent(NewSocketDataCounterWithValue(0, 1, metrics.CloseExecuteTime))
		l.CloseExeTimeHistogram.Cur.IncreaseByValue(metrics.CloseExecuteTime)
	}
}

type SocketDataCounter struct {
	Bytes   uint64
	Count   uint64
	ExeTime uint64
}

func NewSocketDataCounter() *SocketDataCounter {
	return &SocketDataCounter{}
}

func NewSocketDataCounterWithValue(bytes, count, exeTime uint64) *SocketDataCounter {
	ret := &SocketDataCounter{}
	ret.IncreaseByValue(bytes, count, exeTime)
	return ret
}

func (s *SocketDataCounter) Increase(d *SocketDataCounter) {
	s.IncreaseByValue(d.Bytes, d.Count, d.ExeTime)
}

func (s *SocketDataCounter) IncreaseByValue(bytes, count, exeTime uint64) {
	s.Bytes += bytes
	s.Count += count
	s.ExeTime += exeTime
}

func (s *SocketDataCounter) NotEmpty() bool {
	return s.Count > 0
}

// SocketDataCounterWithHistory means the socket send/receive data metrics
type SocketDataCounterWithHistory struct {
	Pre *SocketDataCounter
	Cur *SocketDataCounter
}

func NewSocketDataCounterWithHistory() *SocketDataCounterWithHistory {
	return &SocketDataCounterWithHistory{
		Pre: NewSocketDataCounter(),
		Cur: NewSocketDataCounter(),
	}
}

func (c *SocketDataCounterWithHistory) RefreshCurrent() {
	c.Pre = c.Cur
	c.Cur = NewSocketDataCounterWithValue(c.Cur.Bytes, c.Cur.Count, c.Cur.ExeTime)
}

func (c *SocketDataCounterWithHistory) UpdateToCurrent(bytes, count, exeTime uint64) {
	c.Pre = c.Cur
	c.Cur = &SocketDataCounter{
		Bytes:   bytes,
		Count:   count,
		ExeTime: exeTime,
	}
}

func (c *SocketDataCounterWithHistory) IncreaseToCurrent(other *SocketDataCounter) {
	c.Cur.Increase(other)
}

func (c *SocketDataCounterWithHistory) CalculateIncrease() *SocketDataCounter {
	return &SocketDataCounter{
		Bytes:   subtractionValue(c.Cur.Bytes, c.Pre.Bytes),
		Count:   subtractionValue(c.Cur.Count, c.Pre.Count),
		ExeTime: subtractionValue(c.Cur.ExeTime, c.Pre.ExeTime),
	}
}

// SocketHistogramBucketsNs means the histogram bucket: 0ms, 0.01ms, 0.05ms, 0.1ms, 0.5ms, 1ms, 1.2ms, 1.5ms, 1.7ms, 2ms,
// 2.5ms, 3ms, 5ms, 7ms, 10ms, 13ms, 16ms, 20ms, 25ms, 30ms, 35ms, 40ms, 45ms, 50ms, 70ms, 100ms, 150ms,
// 200ms, 300ms, 500ms, 1s, 2s, 3s, 5s
// value unit: ns
var SocketHistogramBucketsNs = []float64{0, 10000, 50000, 100000, 500000, 1000000, 1200000, 1500000, 1700000, 2000000,
	2500000, 3000000, 5000000, 7000000, 10000000, 13000000, 16000000, 20000000, 25000000, 30000000, 35000000, 40000000,
	45000000, 50000000, 70000000, 100000000, 150000000, 200000000, 300000000, 500000000, 1000000000, 2000000000,
	3000000000, 5000000000}

// SocketHistogramBucketsUs same with SocketHistogramBucketsNs, but the value unit: us
var SocketHistogramBucketsUs = []float64{0, 10, 50, 100, 500, 1000, 1200, 1500, 1700, 2000,
	2500, 3000, 5000, 7000, 10000, 13000, 16000, 20000, 25000, 30000, 35000, 40000,
	45000, 50000, 70000, 100000, 150000, 200000, 300000, 500000, 1000000, 2000000,
	3000000, 5000000}
var SocketHistogramBucketsCount = len(SocketHistogramBucketsNs)

type SocketDataHistogram struct {
	Unit    HistogramDataUnit
	Buckets map[uint64]uint32
}

func (h *SocketDataHistogram) Overwrite(other *SocketDataHistogram) {
	for k, v := range other.Buckets {
		h.Buckets[k] = v
	}
}

func (h *SocketDataHistogram) Update(bucket uint64, value uint32) {
	h.Buckets[bucket] = value
}

func (h *SocketDataHistogram) Increase(other *SocketDataHistogram) {
	for k, v := range other.Buckets {
		h.Buckets[k] += v
	}
}

func (h *SocketDataHistogram) IncreaseByValue(val uint64) {
	floatVal := float64(val)
	for inx, curVal := range SocketHistogramBucketsNs {
		if inx > 0 && curVal > floatVal {
			h.Buckets[uint64(inx-1)]++
			return
		}
	}
	h.Buckets[uint64(len(SocketHistogramBucketsNs)-1)]++
}

func (h *SocketDataHistogram) NotEmpty() bool {
	for _, v := range h.Buckets {
		if v > 0 {
			return true
		}
	}
	return false
}

func NewSocketDataHistogram(unit HistogramDataUnit) *SocketDataHistogram {
	buckets := make(map[uint64]uint32, SocketHistogramBucketsCount)
	for i := 0; i < SocketHistogramBucketsCount; i++ {
		buckets[uint64(i)] = 0
	}
	return &SocketDataHistogram{
		Unit:    unit,
		Buckets: buckets,
	}
}

type HistogramDataUnit int

const (
	HistogramDataUnitNS HistogramDataUnit = 1
	HistogramDataUnitUS HistogramDataUnit = 2
)

type SocketDataHistogramWithHistory struct {
	Pre *SocketDataHistogram
	Cur *SocketDataHistogram
}

func NewSocketDataHistogramWithHistory(unit HistogramDataUnit) *SocketDataHistogramWithHistory {
	return &SocketDataHistogramWithHistory{
		Pre: NewSocketDataHistogram(unit),
		Cur: NewSocketDataHistogram(unit),
	}
}

func (h *SocketDataHistogramWithHistory) RefreshCurrent() {
	// storage the current value to the previous buckets
	h.Pre.Overwrite(h.Cur)
}

func (h *SocketDataHistogramWithHistory) UpdateToCurrent(bucket uint64, val uint32) {
	h.Cur.Update(bucket, val)
}

func (h *SocketDataHistogramWithHistory) IncreaseToCurrent(other *SocketDataHistogram) {
	h.Cur.Increase(other)
}

func (h *SocketDataHistogramWithHistory) CalculateIncrease() *SocketDataHistogram {
	histogram := NewSocketDataHistogram(h.Cur.Unit)
	var increaseVal uint32
	for curK, curV := range h.Cur.Buckets {
		if increaseVal = curV - h.Pre.Buckets[curK]; increaseVal > 0 {
			histogram.Buckets[curK] = increaseVal
		}
	}
	return histogram
}

func subtractionValue(v1, v2 uint64) uint64 {
	if v1 > v2 {
		return v1 - v2
	}
	return 0
}
