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

package buffer

import "testing"

// TestLenCountsEveryEvent: Len sums the length of every event, not the first event's length once per event
func TestLenCountsEveryEvent(t *testing.T) {
	b := skipTestBuffer(false,
		&testEvent{dataID: 1, data: []byte("abcd")},
		&testEvent{dataID: 2, data: []byte("efghijkl")},
		&testEvent{dataID: 3, data: []byte("mn")})
	if got := b.Len(); got != 14 {
		t.Fatalf("Len = %d, want 14", got)
	}
}
