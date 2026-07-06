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
	lostSamples.mutex.Lock()
	lostSamples.counts[mapName] += count
	lostSamples.mutex.Unlock()

	lostSamples.loggerStart.Do(func() {
		go lostSamples.logPeriodically()
	})
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
	}
}
