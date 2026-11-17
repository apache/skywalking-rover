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

import "testing"

func TestLostSampleCounterDrain(t *testing.T) {
	c := &lostSampleCounter{counts: make(map[string]uint64)}
	c.counts["q1"] += 3
	c.counts["q1"] += 2
	c.counts["q2"] += 7

	drained := c.drain()
	if drained["q1"] != 5 || drained["q2"] != 7 {
		t.Fatalf("unexpected drained counts: %v", drained)
	}

	// after a drain the counter must be reset, so a subsequent drain with no new samples is empty
	if again := c.drain(); again != nil {
		t.Fatalf("expected nil after reset, got: %v", again)
	}
}

// TestShedSampleDetector: a sample the detector reports for its perf map is handled as a refused one (the
// dropped sample observer sees it and it counts as dropped), samples of other maps are not asked about
func TestShedSampleDetector(t *testing.T) {
	var observed, asked int
	SetDroppedSampleObserver("queue", func([]byte) { observed++ })
	SetShedSampleDetector("queue", func(sample []byte) bool { asked++; return len(sample) > 0 && sample[0] == 3 }, nil)
	defer SetDroppedSampleObserver("", nil)
	defer SetShedSampleDetector("", nil, nil)
	isShedSample := func(name string, sample []byte) bool { shed, _ := shedSample(name, sample); return shed }
	if isShedSample("other", []byte{3}) || asked != 0 {
		t.Fatal("the samples of another map are not asked about")
	}
	if isShedSample("queue", []byte{1}) || !isShedSample("queue", []byte{3}) {
		t.Fatal("the detector decides")
	}
	before := droppedByMemoryProtection.Load()
	recordDroppedByLimit("queue", []byte{3})
	if observed != 1 || droppedByMemoryProtection.Load() != before+1 {
		t.Fatalf("observed %d, dropped %d", observed, droppedByMemoryProtection.Load()-before)
	}
	SetShedSampleDetector("", nil, nil)
	if isShedSample("queue", []byte{3}) {
		t.Fatal("removed")
	}
}

func TestBatchSampleSplitter(t *testing.T) {
	const name = "test_batch_queue"
	var delivered []interface{}
	var observed [][]byte
	SetDroppedSampleObserver(name, func(sample []byte) { observed = append(observed, append([]byte(nil), sample...)) })
	defer SetDroppedSampleObserver(name, nil)
	SetBatchSampleSplitter(name, func(sample []byte, deliver func(data interface{}), drop func(sample []byte)) bool {
		if len(sample) == 0 || sample[0] != 0xBA {
			return false
		}
		deliver("first")
		drop([]byte{1, 2, 3})
		deliver("second")
		return true
	})
	defer SetBatchSampleSplitter(name, nil)

	deliver := func(data interface{}) { delivered = append(delivered, data) }
	if splitSample(name, []byte{0x01}, deliver) {
		t.Fatalf("a sample that is no batch must go the usual way")
	}
	if splitSample("another_queue", []byte{0xBA}, deliver) {
		t.Fatalf("the splitter of another map must not take the sample")
	}
	if !splitSample(name, []byte{0xBA}, deliver) {
		t.Fatalf("a batch must be taken by the splitter")
	}
	if len(delivered) != 2 || delivered[0] != "first" || delivered[1] != "second" {
		t.Fatalf("delivered %v", delivered)
	}
	// a refused event of the batch is handled like any refused sample: the observer sees it
	if len(observed) != 1 || len(observed[0]) != 3 {
		t.Fatalf("observed %v", observed)
	}
}

// TestSplitSampleDoesNotAllocate: offering a sample to the splitter allocates nothing (the drop function is made
// once, when the splitter is set, not per sample)
func TestSplitSampleDoesNotAllocate(t *testing.T) {
	const name = "test_batch_alloc_queue"
	SetBatchSampleSplitter(name, func(sample []byte, deliver func(data interface{}), drop func(sample []byte)) bool {
		return len(sample) > 0 && sample[0] == 0xBA
	})
	defer SetBatchSampleSplitter(name, nil)
	deliver := func(data interface{}) {}
	sample := []byte{0xBA, 1, 2}
	if n := testing.AllocsPerRun(1000, func() { splitSample(name, sample, deliver) }); n != 0 {
		t.Fatalf("splitSample allocates %v times per sample", n)
	}
}
