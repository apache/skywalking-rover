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

package task

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
)

type RunningStatus uint8

const (
	_ RunningStatus = iota
	NotRunning
	Running
	Stopped
)

// Context of profiling task
type Context struct {
	task             *base.ProfilingTask
	process          api.ProcessInterface
	runner           base.ProfileTaskRunner
	status           RunningStatus
	startRunningTime time.Time
	runningWg        *sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
}

// UpdateTime of the profiling task
func (c *Context) UpdateTime() int64 {
	return c.task.UpdateTime
}

func (c *Context) TaskID() string {
	return c.task.TaskID
}

// BuildTaskIdentity for filter with same identity task
func (c *Context) BuildTaskIdentity() string {
	// use process id, target type, trigger type
	return fmt.Sprintf("%s_%s_%s", c.task.ProcessID, c.task.TargetType, c.task.TriggerType)
}

// CheckTaskRunnable means checks the task could be running
func (c *Context) CheckTaskRunnable() bool {
	// if running with FIXED_TIME type task, check the executing time range
	if c.task.TriggerType == base.TriggerTypeFixedTime {
		startTime := c.task.StartTime
		endTime := time.UnixMilli(startTime).Add(c.task.MaxRunningDuration).UnixMilli()
		now := time.Now().UnixMilli()

		if now > endTime {
			log.Infof("out of task executing time range. task id: %s", c.task.TaskID)
			return false
		}
	}
	return true
}
