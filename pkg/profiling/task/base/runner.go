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

package base

import (
	"math"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

var log = logger.GetLogger("profiling", "task", "base")

type Runner struct {
	StackNotFoundCache map[uint32]bool
	ShutdownOnce       sync.Once
}

func NewBaseRunner() *Runner {
	return &Runner{StackNotFoundCache: make(map[uint32]bool)}
}

func (r *Runner) GenerateProfilingData(profilingInfo *profiling.Info, stackID uint32, stackMap *ebpf.Map,
	stackType v3.EBPFProfilingStackType, symbolArray []uint64) *v3.EBPFProfilingStackMetadata {
	if profilingInfo == nil || stackID <= 0 || stackID == math.MaxUint32 {
		return nil
	}
	if err := stackMap.Lookup(stackID, symbolArray); err != nil {
		if r.StackNotFoundCache[stackID] {
			return nil
		}
		r.StackNotFoundCache[stackID] = true
		log.Warnf("error to lookup %v stack: %d, error: %v", stackType, stackID, err)
		return nil
	}
	symbols := profilingInfo.FindSymbols(symbolArray, MissingSymbol)
	if len(symbols) == 0 {
		return nil
	}
	return &v3.EBPFProfilingStackMetadata{
		StackType:    stackType,
		StackId:      int32(stackID),
		StackSymbols: symbols,
	}
}
