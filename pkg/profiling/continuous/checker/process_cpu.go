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

package checker

import (
	"strconv"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/checker/common"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type ProcessCPUChecker struct {
	*common.ProcessBasedChecker[float64]
}

func NewProcessCPUChecker() *ProcessCPUChecker {
	return &ProcessCPUChecker{}
}

func (r *ProcessCPUChecker) Init(config *base.ContinuousConfig) error {
	r.ProcessBasedChecker = common.NewProcessBasedChecker(base.CheckTypeProcessCPU, func(val string) (float64, error) {
		threshold, err := strconv.ParseInt(val, 10, 32)
		if err != nil {
			return 0, err
		}
		return float64(threshold), nil
	}, func(p api.ProcessInterface) (float64, error) {
		percent, err := p.OriginalProcess().CPUPercent()
		if err != nil {
			return 0, err
		}
		return percent * 100, nil
	}, v3.ContinuousProfilingCauseType_ProcessCPU)
	return nil
}
