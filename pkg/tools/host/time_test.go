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

package host

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

// legacySameMinute is SameMinute before it was computed on the seconds
func legacySameMinute(first, second uint64) bool {
	return Time(first).Truncate(time.Minute).Equal(Time(second).Truncate(time.Minute))
}

// TestSameMinuteAsTruncate: the same answer as truncating the times, around the minute boundaries, for
// offsets past the int64 range (negative durations) and for boot times before the epoch
func TestSameMinuteAsTruncate(t *testing.T) {
	saved := BootTime
	defer func() { BootTime = saved }()
	r := rand.New(rand.NewSource(1))
	boots := []time.Time{saved, time.Unix(1_700_000_000, 999_999_999), time.Unix(1_700_000_040, 0),
		time.Unix(-61, 500_000_000), time.Unix(0, 0)}
	for _, boot := range boots {
		BootTime = boot
		// the offsets that put the time on a minute boundary of this boot time
		toMinute := uint64((60-boot.Unix()%60)%60)*1e9 - uint64(boot.Nanosecond())
		values := []uint64{0, 1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64, toMinute, toMinute - 1, toMinute + 1}
		for i := 0; i < 2000; i++ {
			values = append(values, toMinute+uint64(r.Int63n(int64(10*time.Minute)))-uint64(5*time.Minute), r.Uint64())
		}
		for i, a := range values {
			for _, b := range []uint64{a, a + 1, a - 1, a + uint64(time.Minute), values[(i+1)%len(values)],
				toMinute, toMinute - 1, a + uint64(r.Int63n(int64(2*time.Minute)))} {
				if got, want := SameMinute(a, b), legacySameMinute(a, b); got != want {
					t.Fatalf("boot %v: SameMinute(%d, %d) = %t, truncating gives %t", boot, a, b, got, want)
				}
			}
		}
	}
}
