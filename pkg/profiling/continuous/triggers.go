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

package continuous

import (
	"context"
	"fmt"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/trigger"
	"github.com/apache/skywalking-rover/pkg/profiling/task"
	taskBase "github.com/apache/skywalking-rover/pkg/profiling/task/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"

	"github.com/hashicorp/go-multierror"
)

var triggerRegistration map[base.TargetProfilingType]base.Trigger

func init() {
	triggerRegistration = make(map[base.TargetProfilingType]base.Trigger)
	triggerRegistration[base.TargetProfilingTypeOnCPU] = trigger.NewOnCPUTrigger()
	triggerRegistration[base.TargetProfilingTypeOffCPU] = trigger.NewOffCPUTrigger()
	triggerRegistration[base.TargetProfilingTypeNetwork] = trigger.NewNetworkTrigger()
}

type Triggers struct {
	taskManager      *task.Manager
	continuousClient v3.ContinuousProfilingServiceClient

	ctx context.Context
}

func NewTriggers(ctx context.Context, moduleMgr *module.Manager, taskManager *task.Manager, conf *base.ContinuousConfig) (*Triggers, error) {
	coreOperator := moduleMgr.FindModule(core.ModuleName).(core.Operator)
	continuousClient := v3.NewContinuousProfilingServiceClient(coreOperator.BackendOperator().GetConnection())

	var err error
	for _, t := range triggerRegistration {
		if e := t.Init(moduleMgr, conf); e != nil {
			err = multierror.Append(err, e)
		}
	}
	if err != nil {
		return nil, err
	}
	return &Triggers{
		taskManager:      taskManager,
		continuousClient: continuousClient,
		ctx:              ctx,
	}, nil
}

func (m *Triggers) handleCauses(causes []base.ThresholdCause) {
	// generate the profiling tasks from the triggerRegistration
	profilingTypeWithCauses := make(map[base.TargetProfilingType][]base.ThresholdCause)
	for _, cause := range causes {
		profilingType := cause.FromPolicy().Policy.TargetProfilingType
		profilingTypeWithCauses[profilingType] = append(profilingTypeWithCauses[profilingType], cause)
	}
	for profilingType, ps := range profilingTypeWithCauses {
		if taskCount := triggerRegistration[profilingType].TriggerTasks(m, ps); taskCount > 0 {
			log.Infof("total generate %d %s tasks", taskCount, profilingType)
		}
	}
}

func (m *Triggers) ReportProcesses(process api.ProcessInterface, profilingProcesses []api.ProcessInterface, cases []base.ThresholdCause,
	taskSetter func(task *taskBase.ProfilingTask), reportSetter func(report *v3.ContinuousProfilingReport)) (*task.Context, error) {
	transferCauses := make([]*v3.ContinuousProfilingCause, 0)
	for _, c := range cases {
		transferCauses = append(transferCauses, c.GenerateTransferCause())
	}

	// generate context
	taskContext, err := m.taskManager.BuildContextFromContinuous(profilingProcesses, taskSetter, func() (string, error) {
		report := &v3.ContinuousProfilingReport{
			Layer:        process.Entity().Layer,
			ServiceName:  process.Entity().ServiceName,
			InstanceName: process.Entity().InstanceName,
			ProcessName:  process.Entity().ProcessName,
			Causes:       transferCauses,
		}
		reportSetter(report)
		profilingTask, err := m.continuousClient.ReportProfilingTask(m.ctx, report)
		if err != nil {
			return "", err
		}

		command := profilingTask.Commands[0]
		if len(profilingTask.Commands) != 1 || command.GetCommand() != "ContinuousProfilingReportTask" {
			return "", fmt.Errorf("the profiling task result is not right, command count: %d", len(profilingTask.Commands))
		}
		for _, kv := range command.GetArgs() {
			if kv.GetKey() == "TaskId" {
				return kv.GetValue(), nil
			}
		}
		return "", fmt.Errorf("could not found the task ID from repoter")
	})
	if err != nil {
		return nil, err
	}

	// execute task from context
	m.taskManager.StartTask(taskContext)

	return taskContext, nil
}
