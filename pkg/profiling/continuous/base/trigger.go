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
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task"
	taskBase "github.com/apache/skywalking-rover/pkg/profiling/task/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type TriggerReporter interface {
	ReportProcesses(causeProcess api.ProcessInterface, profilingProcesses []api.ProcessInterface, cases []ThresholdCause,
		taskSetter func(task *taskBase.ProfilingTask),
		reportSetter func(report *v3.ContinuousProfilingReport)) (*task.Context, error)
}

type Trigger interface {
	// Init trigger
	Init(moduleMgr *module.Manager, conf *ContinuousConfig) error
	// ShouldTrigger validate the process should be trigger task
	ShouldTrigger(p api.ProcessInterface) bool
	// TriggerTasks generate task and execute that policy could be trigger
	TriggerTasks(reporter TriggerReporter, causes []ThresholdCause) int
}
