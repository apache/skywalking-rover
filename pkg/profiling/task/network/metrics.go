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

package network

import (
	"fmt"
	"time"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/tools"

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

type SocketDataCounter struct {
	Bytes   uint64
	Count   uint64
	ExeTime uint64
}

func NewSocketDataCounter() *SocketDataCounter {
	return &SocketDataCounter{}
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

func (c *SocketDataCounterWithHistory) UpdateToCurrent(bytes, count, exeTime uint64) {
	c.Pre = c.Cur
	c.Cur = &SocketDataCounter{
		Bytes:   bytes,
		Count:   count,
		ExeTime: exeTime,
	}
}

func (c *SocketDataCounterWithHistory) CalculateIncrease() *SocketDataCounter {
	return &SocketDataCounter{
		Bytes:   subtractionValue(c.Cur.Bytes, c.Pre.Bytes),
		Count:   subtractionValue(c.Cur.Count, c.Pre.Count),
		ExeTime: subtractionValue(c.Cur.ExeTime, c.Pre.ExeTime),
	}
}

// SocketHistogramBuckets means the histogram bucket: 0ms, 0.01ms, 0.05ms, 0.1ms, 0.5ms, 1ms, 1.2ms, 1.5ms, 1.7ms, 2ms,
// 2.5ms, 3ms, 5ms, 7ms, 10ms, 13ms, 16ms, 20ms, 25ms, 30ms, 35ms, 40ms, 45ms, 50ms, 70ms, 100ms, 150ms,
// 200ms, 300ms, 500ms, 1s, 2s, 3s, 5s
// value unit: us
var SocketHistogramBuckets = []float64{0, 10, 50, 100, 500, 1000, 1200, 1500, 1700, 2000,
	2500, 3000, 5000, 7000, 10000, 13000, 16000, 20000, 25000, 30000, 35000, 40000,
	45000, 50000, 70000, 100000, 150000, 200000, 300000, 500000, 1000000, 2000000,
	3000000, 5000000}
var SocketHistogramBucketsCount = len(SocketHistogramBuckets)

type SocketDataHistogram struct {
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
	for inx, curVal := range SocketHistogramBuckets {
		if inx > 0 && curVal > floatVal {
			h.Buckets[uint64(inx-1)]++
			return
		}
	}
	h.Buckets[uint64(len(SocketHistogramBuckets)-1)]++
}

func (h *SocketDataHistogram) NotEmpty() bool {
	for _, v := range h.Buckets {
		if v > 0 {
			return true
		}
	}
	return false
}

func NewSocketDataHistogram() *SocketDataHistogram {
	buckets := make(map[uint64]uint32, SocketHistogramBucketsCount)
	for i := 0; i < SocketHistogramBucketsCount; i++ {
		buckets[uint64(i)] = 0
	}
	return &SocketDataHistogram{
		Buckets: buckets,
	}
}

type SocketDataHistogramWithHistory struct {
	Pre *SocketDataHistogram
	Cur *SocketDataHistogram
}

func NewSocketDataHistogramWithHistory() *SocketDataHistogramWithHistory {
	return &SocketDataHistogramWithHistory{
		Pre: NewSocketDataHistogram(),
		Cur: NewSocketDataHistogram(),
	}
}

func (h *SocketDataHistogramWithHistory) RefreshCurrent() {
	// storage the current value to the previous buckets
	h.Pre.Overwrite(h.Cur)
}

func (h *SocketDataHistogramWithHistory) UpdateToCurrent(bucket uint64, val uint32) {
	h.Cur.Update(bucket, val)
}

func (h *SocketDataHistogramWithHistory) CalculateIncrease() *SocketDataHistogram {
	histogram := NewSocketDataHistogram()
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

type ProcessTraffic struct {
	// local process information
	LocalPid       uint32
	LocalProcesses []api.ProcessInterface
	LocalIP        string
	LocalPort      uint16

	// current connection role of local process
	ConnectionRole ConnectionRole

	// remote process/address information
	RemoteIP        string
	RemotePort      uint16
	RemotePid       uint32
	RemoteProcesses []api.ProcessInterface

	// statics
	WriteCounter *SocketDataCounter
	ReadCounter  *SocketDataCounter
	// write RTT
	WriteRTTCounter *SocketDataCounter

	// connection operate
	ConnectCounter *SocketDataCounter
	CloseCounter   *SocketDataCounter

	// exception operate
	RetransmitCounter *SocketDataCounter
	DropCounter       *SocketDataCounter

	// histograms
	// write execute time and RTT
	WriteRTTHistogram     *SocketDataHistogram
	WriteExeTimeHistogram *SocketDataHistogram
	// read execute time
	ReadExeTimeHistogram *SocketDataHistogram

	// connection operate
	ConnectExeTimeHistogram *SocketDataHistogram
	CloseExeTimeHistogram   *SocketDataHistogram
}

func (r *ProcessTraffic) ContainsAnyTraffic() bool {
	return r.WriteCounter.NotEmpty() || r.ReadCounter.NotEmpty() || r.WriteRTTCounter.NotEmpty() || r.ConnectCounter.NotEmpty() ||
		r.CloseCounter.NotEmpty() || r.WriteRTTHistogram.NotEmpty() || r.WriteExeTimeHistogram.NotEmpty() || r.ReadExeTimeHistogram.NotEmpty() ||
		r.ConnectExeTimeHistogram.NotEmpty() || r.CloseExeTimeHistogram.NotEmpty()
}

func (r *ProcessTraffic) GenerateMetrics(metricsPrefix string) []*v3.MeterDataCollection {
	result := make([]*v3.MeterDataCollection, 0)
	for _, p := range r.LocalProcesses {
		collection := make([]*v3.MeterData, 0)
		collection = r.appendCounterValues(collection, metricsPrefix, "write", p, r.WriteCounter)
		collection = r.appendCounterValues(collection, metricsPrefix, "read", p, r.ReadCounter)
		collection = r.appendCounterValues(collection, metricsPrefix, "write_rtt", p, r.WriteRTTCounter)
		collection = r.appendCounterValues(collection, metricsPrefix, "connect", p, r.ConnectCounter)
		collection = r.appendCounterValues(collection, metricsPrefix, "close", p, r.CloseCounter)
		collection = r.appendCounterValues(collection, metricsPrefix, "retransmit", p, r.RetransmitCounter)
		collection = r.appendCounterValues(collection, metricsPrefix, "drop", p, r.DropCounter)

		collection = r.appendHistogramValue(collection, metricsPrefix, "write_rtt", p, r.WriteRTTHistogram)
		collection = r.appendHistogramValue(collection, metricsPrefix, "write_exe_time", p, r.WriteExeTimeHistogram)
		collection = r.appendHistogramValue(collection, metricsPrefix, "read_exe_time", p, r.ReadExeTimeHistogram)
		collection = r.appendHistogramValue(collection, metricsPrefix, "connect_exe_time", p, r.ConnectExeTimeHistogram)
		collection = r.appendHistogramValue(collection, metricsPrefix, "close_exe_time", p, r.CloseExeTimeHistogram)

		if len(collection) == 0 {
			continue
		}

		// add entity
		collection[0].Service = p.Entity().ServiceName
		collection[0].ServiceInstance = p.Entity().InstanceName
		collection[0].Timestamp = time.Now().UnixMilli()
		result = append(result, &v3.MeterDataCollection{
			MeterData: collection,
		})
	}

	return result
}

func (r *ProcessTraffic) appendCounterValues(metrics []*v3.MeterData, metricsPrefix, name string, local api.ProcessInterface,
	counter *SocketDataCounter) []*v3.MeterData {
	if !counter.NotEmpty() {
		return metrics
	}

	count := float64(counter.Count)
	metrics = append(metrics, r.buildSingleValue(metricsPrefix, name+"_counts_counter", local, count))
	if counter.Bytes > 0 {
		metrics = append(metrics, r.buildSingleValue(metricsPrefix, name+"_bytes_counter", local, float64(counter.Bytes)))
	}
	if counter.ExeTime > 0 {
		metrics = append(metrics, r.buildSingleValue(metricsPrefix, name+"_exe_time_counter", local, float64(counter.ExeTime)/count))
	}
	return metrics
}

func (r *ProcessTraffic) appendHistogramValue(metrics []*v3.MeterData, metricsPrefix, name string,
	local api.ProcessInterface, histogram *SocketDataHistogram) []*v3.MeterData {
	if !histogram.NotEmpty() {
		return metrics
	}

	role, labels := r.buildBasicMeterLabels(local)
	values := make([]*v3.MeterBucketValue, 0)
	for bucket, count := range histogram.Buckets {
		var bucketInx = int(bucket)
		if bucketInx >= SocketHistogramBucketsCount {
			bucketInx = SocketHistogramBucketsCount - 1
		}
		values = append(values, &v3.MeterBucketValue{
			Bucket: SocketHistogramBuckets[bucketInx],
			Count:  int64(count),
		})
	}

	return append(metrics, &v3.MeterData{
		Metric: &v3.MeterData_Histogram{
			Histogram: &v3.MeterHistogram{
				Name:   fmt.Sprintf("%s%s_%s_histogram", metricsPrefix, role.String(), name),
				Labels: labels,
				Values: values,
			},
		},
	})
}

func (r *ProcessTraffic) buildSingleValue(prefix, name string, local api.ProcessInterface, val float64) *v3.MeterData {
	role, labels := r.buildBasicMeterLabels(local)

	return &v3.MeterData{
		Metric: &v3.MeterData_SingleValue{
			SingleValue: &v3.MeterSingleValue{
				Name:   fmt.Sprintf("%s%s_%s", prefix, role.String(), name),
				Labels: labels,
				Value:  val,
			},
		},
	}
}

func (r *ProcessTraffic) buildBasicMeterLabels(local api.ProcessInterface) (ConnectionRole, []*v3.Label) {
	curRole := r.ConnectionRole
	// add the default role
	if curRole == ConnectionRoleUnknown {
		curRole = ConnectionRoleClient
	}
	labels := make([]*v3.Label, 0)

	// two pair process/address info
	labels = r.appendMeterValue(labels, fmt.Sprintf("%s_process_id", curRole.String()), local.ID())
	labels = r.appendRemoteAddrssInfo(labels, curRole.Revert().String(), local)

	labels = r.appendMeterValue(labels, "side", curRole.String())
	return curRole, labels
}

func (r *ProcessTraffic) appendRemoteAddrssInfo(labels []*v3.Label, prefix string, local api.ProcessInterface) []*v3.Label {
	if len(r.RemoteProcesses) != 0 {
		for _, p := range r.RemoteProcesses {
			// only match with same service instance
			if local.Entity().ServiceName == p.Entity().ServiceName &&
				local.Entity().InstanceName == p.Entity().InstanceName {
				return r.appendMeterValue(labels, prefix+"_process_id", p.ID())
			}
		}
	}

	if tools.IsLocalHostAddress(r.RemoteIP) {
		return r.appendMeterValue(labels, prefix+"_local", "true")
	}

	return r.appendMeterValue(labels, prefix+"_address", fmt.Sprintf("%s:%d", r.RemoteIP, r.RemotePort))
}

func (r *ProcessTraffic) appendMeterValue(labels []*v3.Label, name, value string) []*v3.Label {
	return append(labels, &v3.Label{
		Name:  name,
		Value: value,
	})
}
