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

package profiling

var KernelSymbolFilePath = "/proc/kallsyms"

// Info of profiling process
type Info struct {
	Symbols []*Symbol
}

// Symbol of executable file
type Symbol struct {
	Name     string
	Location uint64
}

type StatFinder interface {
	// IsSupport to stat the executable file for profiling
	IsSupport(filePath string) bool
	// Analyze the executable file
	Analyze(filePath string) (*Info, error)
}

// FindSymbolName by address
func (i *Info) FindSymbolName(address uint64) string {
	symbols := i.Symbols

	start := 0
	end := len(symbols)
	for start < end {
		mid := start + (end-start)/2
		result := int64(address) - int64(symbols[mid].Location)

		if result < 0 {
			end = mid
		} else if result > 0 {
			start = mid + 1
		} else {
			return symbols[mid].Name
		}
	}

	if start >= 1 && symbols[start-1].Location < address && address < symbols[start].Location {
		return symbols[start-1].Name
	}

	return ""
}
