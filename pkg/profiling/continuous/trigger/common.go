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
	"fmt"
	"time"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task"
	taskBase "github.com/apache/skywalking-rover/pkg/profiling/task/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

var log = logger.GetLogger("profiling", "continuous", "trigger")

type BaseTrigger struct {
	profilingCache map[string]*task.Context
	executeTime    time.Duration
	silenceTime    time.Duration

	profilingTaskDimension func(p api.ProcessInterface) string
	mainProcessSelector    func(ps []api.ProcessInterface) api.ProcessInterface
	taskSetter             func(task *taskBase.ProfilingTask, processes []api.ProcessInterface, thresholds []base.ThresholdCause)
	reportSetter           func(report *v3.ContinuousProfilingReport, processes []api.ProcessInterface, thresholds []base.ThresholdCause)
}

func NewSingleProcessBaseTrigger(conf *base.ContinuousConfig,
	taskSetter func(task *taskBase.ProfilingTask, processes []api.ProcessInterface, thresholds []base.ThresholdCause),
	reportSetter func(report *v3.ContinuousProfilingReport, processes []api.ProcessInterface, thresholds []base.ThresholdCause)) *BaseTrigger {
	trigger := &BaseTrigger{
		profilingTaskDimension: func(p api.ProcessInterface) string {
			return p.ID()
		},
		mainProcessSelector: func(ps []api.ProcessInterface) api.ProcessInterface {
			return ps[0]
		},
		taskSetter:     taskSetter,
		reportSetter:   reportSetter,
		profilingCache: make(map[string]*task.Context),
	}
	return trigger
}

func NewMultipleProcessBasedTrigger(conf *base.ContinuousConfig,
	profilingTaskDimension func(p api.ProcessInterface) string,
	mainProcessSelector func(ps []api.ProcessInterface) api.ProcessInterface,
	taskSetter func(task *taskBase.ProfilingTask, processes []api.ProcessInterface, thresholds []base.ThresholdCause),
	reportSetter func(report *v3.ContinuousProfilingReport, processes []api.ProcessInterface, thresholds []base.ThresholdCause)) *BaseTrigger {
	trigger := &BaseTrigger{
		profilingTaskDimension: profilingTaskDimension,
		mainProcessSelector:    mainProcessSelector,
		taskSetter:             taskSetter,
		reportSetter:           reportSetter,
		profilingCache:         make(map[string]*task.Context),
	}
	return trigger
}

func (c *BaseTrigger) Init(conf *base.ContinuousConfig) error {
	executeDuration, err := time.ParseDuration(conf.Trigger.ExecuteDuration)
	if err != nil {
		return fmt.Errorf("check trigger task execute duration error: %v", err)
	}

	silenceDuration, err := time.ParseDuration(conf.Trigger.SilenceDuration)
	if err != nil {
		return fmt.Errorf("check trigger task silence duration error: %v", err)
	}

	c.executeTime = executeDuration
	c.silenceTime = silenceDuration
	return nil
}

func (c *BaseTrigger) ShouldTrigger(p api.ProcessInterface) bool {
	return c.shouldTriggerFromDimension(c.profilingTaskDimension(p))
}

func (c *BaseTrigger) TriggerTasks(reporter base.TriggerReporter, causes []base.ThresholdCause) int {
	executeCount := 0

	// build needs profiling processes data cache
	// key: dimension, value: map[process][]thresholds
	dimensionedProcessThresholds := make(map[string]map[api.ProcessInterface][]base.ThresholdCause)
	for _, cause := range causes {
		causeProcess := cause.Process()
		dimension := c.profilingTaskDimension(causeProcess)
		if !c.shouldTriggerFromDimension(dimension) {
			continue
		}

		processThresholds := dimensionedProcessThresholds[dimension]
		if processThresholds == nil {
			processThresholds = make(map[api.ProcessInterface][]base.ThresholdCause)
			dimensionedProcessThresholds[dimension] = processThresholds
		}

		processThresholds[causeProcess] = append(processThresholds[causeProcess], cause)
	}

	// reports task through cache
	for dimension, processWithThresholds := range dimensionedProcessThresholds {
		processes := make([]api.ProcessInterface, 0)
		var mainProcess api.ProcessInterface
		for process := range processWithThresholds {
			processes = append(processes, process)
		}
		if len(processes) == 1 {
			mainProcess = processes[0]
		} else {
			mainProcess = c.mainProcessSelector(processes)
		}

		thresholdCauses := processWithThresholds[mainProcess]
		taskContext, err := reporter.ReportProcesses(mainProcess, processes, thresholdCauses,
			func(task *taskBase.ProfilingTask) {
				task.MaxRunningDuration = c.executeTime
				c.taskSetter(task, processes, thresholdCauses)
			}, func(report *v3.ContinuousProfilingReport) {
				report.Duration = int32(c.executeTime.Seconds())
				c.reportSetter(report, processes, thresholdCauses)
			})
		if err != nil {
			log.Warnf("failure to report the cause, process id: %s, error: %v", mainProcess.ID(), err)
			continue
		}

		c.profilingCache[dimension] = taskContext
		executeCount++
	}
	return executeCount
}

func (c *BaseTrigger) shouldTriggerFromDimension(dimension string) bool {
	t := c.profilingCache[dimension]
	if t == nil {
		return true
	} else if t.IsRunning() {
		return false
	}
	return !t.RunningTime().IsZero() && time.Since(t.RunningTime()) > c.silenceTime
}
