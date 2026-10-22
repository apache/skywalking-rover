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

package events

import (
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

func detail(start, end uint64, ifIndex uint32, name enums.SocketFunctionName, packages uint32, size uint64) *SocketDetailEvent {
	return &SocketDetailEvent{
		ConnectionID: 1, RandomID: 2, DataID0: start,
		StartTime: start, EndTime: end,
		L4Duration: end - start, L4PackageCount: packages, L4TotalPackageSize: size,
		L3NetFilterCount: 1, L3NetFilterDuration: 5,
		IfIndex: ifIndex, FunctionName: name,
	}
}

// TestMergeDetailsOfOneMessage is the case the option exists for: a body read in several syscalls
// becomes one record whose counters are the sum of all of them.
func TestMergeDetailsOfOneMessage(t *testing.T) {
	details := []SocketDetail{
		detail(1000, 2000, 3, enums.SocketFunctionNameRead, 170, 20480),
		detail(3000, 4000, 3, enums.SocketFunctionNameRead, 171, 20480),
		detail(5000, 6000, 3, enums.SocketFunctionNameRead, 172, 10240),
	}
	merged := MergeDetails(details)
	if len(merged) != 1 {
		t.Fatalf("expected one record, got %d", len(merged))
	}
	got := merged[0].(*SocketDetailEvent)
	if got.StartTime != 1000 || got.EndTime != 6000 {
		t.Errorf("times = %d-%d, want the first start and the last end 1000-6000", got.StartTime, got.EndTime)
	}
	// the package count of one syscall does not fit in the kernel width, the sum of three never would
	if got.L4PackageCount != 513 {
		t.Errorf("package count = %d, want 513", got.L4PackageCount)
	}
	if got.L4TotalPackageSize != 51200 {
		t.Errorf("package size = %d, want 51200", got.L4TotalPackageSize)
	}
	if got.L4Duration != 3000 {
		t.Errorf("l4 duration = %d, want the sum 3000", got.L4Duration)
	}
	// the backend reads the duration only when the count is positive: they must be summed together
	if got.L3NetFilterCount != 3 || got.L3NetFilterDuration != 15 {
		t.Errorf("net filter = %d in %d, want 3 in 15", got.L3NetFilterCount, got.L3NetFilterDuration)
	}
}

// TestMergeDetailsKeepsTheOriginals guards the reason the merge copies: one socket call can carry the
// end of a message and the start of the next, so its detail belongs to two protocol logs.
func TestMergeDetailsKeepsTheOriginals(t *testing.T) {
	shared := detail(1000, 2000, 1, enums.SocketFunctionNameRead, 10, 1024)
	details := []SocketDetail{shared, detail(3000, 4000, 1, enums.SocketFunctionNameRead, 11, 2048)}
	merged := MergeDetails(details)
	if len(merged) != 1 {
		t.Fatalf("expected one record, got %d", len(merged))
	}
	if shared.L4PackageCount != 10 || shared.L4TotalPackageSize != 1024 || shared.EndTime != 2000 {
		t.Fatalf("the first detail was modified in place: %+v", shared)
	}
}

func TestMergeDetailsKeepsGroupsApart(t *testing.T) {
	bootTime := host.Time(0)
	minute := uint64(bootTime.Truncate(time.Minute).Add(time.Minute).Sub(bootTime))
	tests := []struct {
		name    string
		details []SocketDetail
		want    int
	}{
		{"syscall change", []SocketDetail{
			detail(1000, 2000, 1, enums.SocketFunctionNameRead, 1, 10),
			detail(3000, 4000, 1, enums.SocketFunctionNameWrite, 1, 10),
		}, 2},
		{"interface change", []SocketDetail{
			detail(1000, 2000, 1, enums.SocketFunctionNameRead, 1, 10),
			detail(3000, 4000, 2, enums.SocketFunctionNameRead, 1, 10),
		}, 2},
		{"minute boundary", []SocketDetail{
			detail(minute-1000, minute-500, 1, enums.SocketFunctionNameRead, 1, 10),
			detail(minute+1000, minute+2000, 1, enums.SocketFunctionNameRead, 1, 10),
		}, 2},
		{"same minute", []SocketDetail{
			detail(minute+1000, minute+2000, 1, enums.SocketFunctionNameRead, 1, 10),
			detail(minute+3000, minute+4000, 1, enums.SocketFunctionNameRead, 1, 10),
		}, 1},
		{"read write read keeps the order", []SocketDetail{
			detail(1000, 2000, 1, enums.SocketFunctionNameRead, 1, 10),
			detail(3000, 4000, 1, enums.SocketFunctionNameWrite, 1, 10),
			detail(5000, 6000, 1, enums.SocketFunctionNameRead, 1, 10),
		}, 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := len(MergeDetails(test.details)); got != test.want {
				t.Fatalf("merged into %d records, want %d", got, test.want)
			}
		})
	}
}

func TestMergeDetailsTotalsAreKept(t *testing.T) {
	details := make([]SocketDetail, 0, 16)
	var wantPackages uint32
	var wantSize uint64
	for i := uint64(0); i < 16; i++ {
		details = append(details, detail(1000*i, 1000*i+500, 7, enums.SocketFunctionNameReadv, 200, 20480))
		wantPackages += 200
		wantSize += 20480
	}
	var gotPackages uint32
	var gotSize uint64
	for _, merged := range MergeDetails(details) {
		gotPackages += merged.GetL4PackageCount()
		gotSize += merged.GetL4TotalPackageSize()
	}
	if gotPackages != wantPackages || gotSize != wantSize {
		t.Fatalf("after merging: packages %d size %d, want %d and %d", gotPackages, gotSize, wantPackages, wantSize)
	}
	if len(MergeDetails(nil)) != 0 {
		t.Fatal("merging nothing must return nothing")
	}
}
