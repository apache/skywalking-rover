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
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	v3 "skywalking.apache.org/repo/goapi/collect/common/v3"
)

// BootTime the System boot time
var BootTime time.Time

func init() {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	now := time.Now()
	if err != nil {
		panic(fmt.Errorf("init boot time error: %v", err))
	}
	bootTimeNano := now.UnixNano() - ts.Nano()
	BootTime = time.Unix(bootTimeNano/1e9, bootTimeNano%1e9)
}

func TimeToInstant(bpfTime uint64) *v3.Instant {
	result := Time(bpfTime)
	return &v3.Instant{
		Seconds: result.Unix(),
		Nanos:   int32(result.Nanosecond()),
	}
}

func Time(bpfTime uint64) time.Time {
	timeCopy := time.Unix(BootTime.Unix(), int64(BootTime.Nanosecond()))
	return timeCopy.Add(time.Duration(bpfTime))
}

// SameMinute reports whether two kernel timestamps fall into the same wall clock minute. The backend
// places a record into a minute bucket by the boot time of the node plus the offset the agent sends,
// so this is the same arithmetic, and it is what decides whether two records may be reported as one.
func SameMinute(first, second uint64) bool {
	bootSeconds, bootNanos := BootTime.Unix(), int64(BootTime.Nanosecond())
	return unixMinute(bootSeconds, bootNanos, first) == unixMinute(bootSeconds, bootNanos, second)
}

// unixMinute is the minute of Time(bpfTime) since the epoch: time.Time.Add carried over the seconds,
// and Truncate(time.Minute) is the floor of the seconds by 60, the epoch being a whole minute after
// the zero time Truncate counts from
func unixMinute(bootSeconds, bootNanos int64, bpfTime uint64) int64 {
	d := int64(time.Duration(bpfTime))
	seconds, nanos := bootSeconds+d/1e9, bootNanos+d%1e9
	if nanos >= 1e9 {
		seconds++
	} else if nanos < 0 {
		seconds--
	}
	minute := seconds / 60
	if seconds%60 < 0 {
		minute--
	}
	return minute
}
