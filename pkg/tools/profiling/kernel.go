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

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/host"
)

type KernelFinder struct {
	kernelFileExists bool
}

func NewKernelFinder() *KernelFinder {
	stat, _ := os.Stat(host.GetHostProcInHost(KernelProcSymbolFilePath))
	return &KernelFinder{kernelFileExists: stat != nil}
}

func (k *KernelFinder) IsSupport(filepath string) bool {
	if filepath != KernelProcSymbolFilePath {
		return false
	}
	stat, _ := os.Stat(host.GetHostProcInHost(filepath))
	return stat != nil
}

func (k *KernelFinder) Analyze(filepath string) (*Info, error) {
	kernelPath, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(kernelPath)
	symbols := make([]*Symbol, 0)
	for scanner.Scan() {
		info := strings.Split(scanner.Text(), " ")
		atoi, err := strconv.ParseUint(info[0], 16, 64)

		if err != nil {
			return nil, fmt.Errorf("error read addr: %s, %v", info[0], err)
		}
		symbols = append(symbols, &Symbol{
			Name:     info[2],
			Location: atoi,
			Size:     0,
		})
	}

	kernelModule := &Module{
		Name:    "kernel",
		Symbols: symbols,
		// kernel module could handling all symbols
		Ranges: []*ModuleRange{
			{
				StartAddr: 0,
				EndAddr:   math.MaxUint64,
			},
		},
	}

	return NewInfo(map[string]*Module{
		"kernel": kernelModule,
	}), nil
}
