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

package btf

import (
	"sync"
	"sync/atomic"
	"time"
)

// lostSampleLogInterval is how often the aggregated dropped-sample summary is logged. The kernel
// drops samples in bursts, so logging every single occurrence floods the log; instead the counts
// are accumulated and reported once per interval.
const lostSampleLogInterval = 30 * time.Second

var lostSamples = &lostSampleCounter{counts: make(map[string]uint64)}

// lostSampleCounter accumulates the number of perf event samples the kernel dropped (because the
// per-CPU buffer was full and userspace did not drain it in time), keyed by the perf map name.
type lostSampleCounter struct {
	mutex       sync.Mutex
	counts      map[string]uint64
	loggerStart sync.Once
}

// recordLostSamples accumulates dropped samples for a perf map and lazily starts the periodic
// aggregated logger on first loss.
func recordLostSamples(mapName string, count uint64) {
	lossEpoch.Add(1)
	lostSamples.mutex.Lock()
	lostSamples.counts[mapName] += count
	lostSamples.mutex.Unlock()

	lostSamples.loggerStart.Do(func() {
		go lostSamples.logPeriodically()
	})
}

// recordDroppedByLimit counts an event the consumer refused because the memory protection is active.
// It is reported next to the lost samples but with its own cause and advice: the remedy is memory, not
// a larger perf buffer. The counter is an atomic so the drop path, which runs exactly when the agent
// is already saturated, does not take the summary lock per event.
func recordDroppedByLimit(mapName string, sample []byte) {
	if observer := droppedSampleObserver.Load(); observer != nil && observer.mapName == mapName {
		observer.observe(sample)
	} else {
		lossEpoch.Add(1)
	}
	droppedByMemoryProtection.Add(1)
	lostSamples.loggerStart.Do(func() {
		go lostSamples.logPeriodically()
	})
}

var droppedByMemoryProtection atomic.Uint64

// lossEpoch grows whenever the reader loses socket events it never parses: samples the kernel dropped,
// events the memory protection refused and samples that could not be parsed
var lossEpoch atomic.Uint64

// droppedSampleObserver is told about the samples of one perf map the consumer refused, see
// SetDroppedSampleObserver
var droppedSampleObserver atomic.Pointer[sampleObserver]

type sampleObserver struct {
	mapName string
	observe func(sample []byte)
}

// SetDroppedSampleObserver hands the samples of the perf map (by its name, ebpf.Map.String) the consumer
// refuses (memory protection) to the observer, on the goroutine that reads the map, which can tell the
// events lost by their raw bytes; the loss epoch then does not count them. Nil removes it.
func SetDroppedSampleObserver(mapName string, observe func(sample []byte)) {
	if observe == nil {
		droppedSampleObserver.Store(nil)
		return
	}
	droppedSampleObserver.Store(&sampleObserver{mapName: mapName, observe: observe})
}

// shedSampleDetector tells the samples of one perf map that stand for an event the consumer refused, see
// SetShedSampleDetector
var shedSampleDetector atomic.Pointer[sampleDetector]

type sampleDetector struct {
	mapName string
	detect  func(sample []byte) bool
	supply  func() interface{}
}

// SetShedSampleDetector has the reader of the perf map (by its name, ebpf.Map.String) ask detect about
// every sample before it is decoded: a sample it reports is first handled exactly like one the consumer
// refused (recordDroppedByLimit, the dropped sample observer included). It is for the events the kernel
// sends without their data while the memory protection is under pressure. When supply is not nil, the
// sample is then decoded into what it returns (unless that is nil) and handed over like any event: the
// consumer keeps what the event says of its call besides the data. Nil detect removes it.
func SetShedSampleDetector(mapName string, detect func(sample []byte) bool, supply func() interface{}) {
	if detect == nil {
		shedSampleDetector.Store(nil)
		return
	}
	shedSampleDetector.Store(&sampleDetector{mapName: mapName, detect: detect, supply: supply})
}

// shedSample tells whether the sample of the perf map stands for a refused event, and what decodes it then
func shedSample(mapName string, sample []byte) (shed bool, supply func() interface{}) {
	d := shedSampleDetector.Load()
	if d == nil || d.mapName != mapName || !d.detect(sample) {
		return false, nil
	}
	return true, d.supply
}

// batchSampleSplitter turns one sample of a perf map that carries several events (a batch) into those
// events, see SetBatchSampleSplitter
var batchSampleSplitter atomic.Pointer[sampleSplitter]

type sampleSplitter struct {
	mapName string
	split   func(sample []byte, deliver func(data interface{}), drop func(sample []byte)) bool
	// drop is what split is handed for the events the consumer refuses: made once, not per sample
	drop func(sample []byte)
}

// SetBatchSampleSplitter has the reader of the perf map (by its name) offer every sample to split before
// anything else: a sample split reports as handled (true) is a batch, and split hands each event it carries
// to deliver, which routes it like any decoded event, and each event the consumer refuses (the memory
// protection) to drop, as the raw sample of that event, which is then handled exactly like a refused
// sample (recordDroppedByLimit, the dropped sample observer included). A batch lost in the kernel is a lost
// sample like any other (recordLostSamples, the loss epoch): the consumers tell the gap of every connection
// it carried by the previous data ids. Nil split removes it.
func SetBatchSampleSplitter(mapName string, split func(sample []byte, deliver func(data interface{}), drop func(sample []byte)) bool) {
	if split == nil {
		batchSampleSplitter.Store(nil)
		return
	}
	batchSampleSplitter.Store(&sampleSplitter{mapName: mapName, split: split,
		drop: func(refused []byte) { recordDroppedByLimit(mapName, refused) }})
}

// splitSample offers the sample to the batch splitter of the perf map; true when it was a batch
func splitSample(mapName string, sample []byte, deliver func(data interface{})) bool {
	s := batchSampleSplitter.Load()
	if s == nil || s.mapName != mapName {
		return false
	}
	return s.split(sample, deliver, s.drop)
}

// LossEpoch tells a consumer that follows the events of a connection in order whether any were lost
// since it last looked: the value changed
func LossEpoch() uint64 {
	return lossEpoch.Load()
}

// drain atomically returns the samples accumulated since the last drain and resets the counter, so
// each reporting interval directly reads the newly-dropped counts without tracking previous totals,
// and the map does not grow unbounded.
func (c *lostSampleCounter) drain() map[string]uint64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if len(c.counts) == 0 {
		return nil
	}
	drained := c.counts
	c.counts = make(map[string]uint64)
	return drained
}

func (c *lostSampleCounter) logPeriodically() {
	ticker := time.NewTicker(lostSampleLogInterval)
	defer ticker.Stop()
	for range ticker.C {
		for name, dropped := range c.drain() {
			log.Warnf("perf event queue(%s) dropped %d samples in the last %s, "+
				"consider increasing the per_cpu_buffer or parse_parallels", name, dropped, lostSampleLogInterval)
		}
		if dropped := droppedByMemoryProtection.Swap(0); dropped > 0 {
			log.Warnf("memory protection dropped %d socket data events in the last %s, "+
				"consider giving the agent more memory or raising access_log.protocol_analyze.max_memory_percent",
				dropped, lostSampleLogInterval)
		}
	}
}
