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

type ProcessThreadCountChecker struct {
	*common.ProcessBasedChecker[int32]
}

func NewProcessThreadCountChecker() *ProcessThreadCountChecker {
	return &ProcessThreadCountChecker{}
}

func (t *ProcessThreadCountChecker) Init(config *base.ContinuousConfig) error {
	t.ProcessBasedChecker = common.NewProcessBasedChecker(base.CheckTypeProcessThreadCount, func(val string) (int32, error) {
		count, err := strconv.ParseInt(val, 10, 32)
		return int32(count), err
	}, func(p api.ProcessInterface) (int32, error) {
		threads, err := p.OriginalProcess().NumThreads()
		return threads, err
	}, v3.ContinuousProfilingTriggeredMonitorType_ProcessThreadCount)
	return nil
}
