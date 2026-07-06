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
