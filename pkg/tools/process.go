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

package tools

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

var (
	// NotSupportProfilingExe mean which program are not support for profiling
	// Not Support JIT and Script language for now
	NotSupportProfilingExe = []string{
		"java", "python", "node", "bash", "ruby", "ssh",
	}

	// executable file profiling finders
	profilingStatFinderList = []profiling.StatFinder{
		profiling.NewGoLibrary(), profiling.NewObjDump(),
	}

	// kernel profiling finder
	kernelFinder = profiling.NewKernelFinder()
)

// KernelFileProfilingStat is works for read the kernel and get is support for kernel symbol analyze
func KernelFileProfilingStat() (*profiling.Info, error) {
	if !kernelFinder.IsSupport(profiling.KernelSymbolFilePath) {
		return nil, fmt.Errorf("not support kernel space profiling")
	}
	return kernelFinder.Analyze(profiling.KernelSymbolFilePath)
}

// ExecutableFileProfilingStat is validating the exe file could be profiling and get info
func ExecutableFileProfilingStat(exePath string) (*profiling.Info, error) {
	stat, err := os.Stat(exePath)
	if err != nil {
		return nil, fmt.Errorf("check file error: %v", err)
	}
	for _, notSupport := range NotSupportProfilingExe {
		if strings.HasPrefix(stat.Name(), notSupport) {
			return nil, fmt.Errorf("not support %s language profiling", notSupport)
		}
	}

	var lastError error
	for _, finder := range profilingStatFinderList {
		if finder.IsSupport(exePath) {
			if r, err1 := analyzeByFinder(exePath, finder); err1 == nil {
				return r, nil
			}
			lastError = err
		}
	}

	if lastError == nil {
		lastError = fmt.Errorf("could not found library to analyze the file")
	}

	return nil, lastError
}

func analyzeByFinder(exePath string, finder profiling.StatFinder) (*profiling.Info, error) {
	// do analyze
	info, err := finder.Analyze(exePath)
	if err != nil {
		return nil, err
	}

	// order the symbols by address
	sort.SliceStable(info.Symbols, func(i, j int) bool {
		return info.Symbols[i].Location < info.Symbols[j].Location
	})

	return info, nil
}
