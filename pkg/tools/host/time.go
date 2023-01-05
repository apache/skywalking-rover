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
