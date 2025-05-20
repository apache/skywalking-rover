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

package trigger

import (
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type OffCPUTrigger struct {
	*BaseTrigger
}

func NewOffCPUTrigger() base.Trigger {
	return &OffCPUTrigger{}
}

func (o *OffCPUTrigger) Init(_ *module.Manager, conf *base.ContinuousConfig) error {
	o.BaseTrigger = NewSingleProcessBaseTrigger(conf,
		func(task *profiling.ProfilingTask, _ []api.ProcessInterface, _ []base.ThresholdCause) {
			task.TargetType = profiling.TargetTypeOffCPU
		}, func(report *v3.ContinuousProfilingReport, _ []api.ProcessInterface, _ []base.ThresholdCause) {
			report.TargetTask = &v3.ContinuousProfilingReport_OffCPU{
				OffCPU: &v3.ContinuousOffCPUProfilingTask{},
			}
		})
	return o.BaseTrigger.Init(conf)
}
