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

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"

	common_v3 "skywalking.apache.org/repo/goapi/collect/common/v3"
	profiling_v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

var log = logger.GetLogger("profiling", "task")

type Manager struct {
	moduleMgr       *module.Manager
	processOperator process.Operator
	profilingClient profiling_v3.EBPFProfilingServiceClient
	flushInterval   time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	taskConfig      *base.TaskConfig

	tasks map[string]*Context
}

func NewManager(ctx context.Context, moduleMgr *module.Manager,
	profilingClient profiling_v3.EBPFProfilingServiceClient, flushInterval time.Duration, taskConfig *base.TaskConfig) (*Manager, error) {
	processOperator := moduleMgr.FindModule(process.ModuleName).(process.Operator)
	if err := CheckProfilingTaskConfig(taskConfig, moduleMgr); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	manager := &Manager{
		moduleMgr:       moduleMgr,
		processOperator: processOperator,
		profilingClient: profilingClient,
		taskConfig:      taskConfig,
		tasks:           make(map[string]*Context),
		flushInterval:   flushInterval,
		ctx:             ctx,
		cancel:          cancel,
	}
	return manager, nil
}

func (m *Manager) Start() {
	go m.startFlushProfilingData()
}

func (m *Manager) BuildContext(command *common_v3.Command) (*Context, error) {
	// analyze command
	t, err := base.ProfilingTaskFromCommand(command)
	if err != nil || t == nil {
		return nil, fmt.Errorf("parsing profiling task failure, command: %v, reason: %v", command.GetArgs(), err)
	}

	// find processes
	processes := make([]api.ProcessInterface, 0)
	for _, processID := range t.ProcessIDList {
		taskProcess := m.processOperator.FindProcessByID(processID)
		if taskProcess == nil {
			return nil, fmt.Errorf("could not found %s processes %s", t.TaskID, t.ProcessIDList)
		}
		processes = append(processes, taskProcess)
	}

	taskContext := &Context{task: t, processes: processes, status: NotRunning, recalcDuration: make(chan bool, 1)}
	// check existing task, extended the running time
	existTask := m.tasks[taskContext.BuildTaskIdentity()]
	// if task are same, then just rewrite the task information and return
	if existTask != nil && existTask.IsSameTask(taskContext) {
		existTask.task = t
		return existTask, nil
	}

	// init runner
	var r base.ProfileTaskRunner
	if runner, err := NewProfilingRunner(t.TargetType, m.taskConfig, m.moduleMgr); err != nil {
		return nil, err
	} else if err := runner.Init(t, processes); err != nil {
		return nil, fmt.Errorf("could not init %s runner for task: %s: %v", t.TriggerType, t.TaskID, err)
	} else {
		r = runner
	}

	taskContext.runner = r
	taskContext.ctx, taskContext.cancel = context.WithCancel(m.ctx)
	return taskContext, nil
}

func (m *Manager) StartTask(c *Context) {
	// shutdown task if exists
	taskIdentity := c.BuildTaskIdentity()
	existTask := m.tasks[taskIdentity]
	if existTask != nil {
		// just extend the task time if the task are same
		if c.IsSameTask(existTask) {
			// notify to re-calculate the task duration(task stop timer)
			c.recalcDuration <- true
			return
		}

		// close task if not same
		id := m.tasks[taskIdentity].TaskID()
		log.Infof("existing profiling task: %s, so need to stop it", id)
		if err := m.ShutdownAndRemoveTask(m.tasks[taskIdentity]); err != nil {
			log.Warnf("shutdown existing profiling task failure, so cannot to start new profiling task: %v. reason: %v", c.task.TaskID, err)
			return
		}
	}

	currentMilli := time.Now().UnixNano() / int64(time.Millisecond)
	m.tasks[taskIdentity] = c

	// already reach time
	if currentMilli >= c.task.StartTime {
		m.runTask(c)
		return
	}

	// schedule to execute
	afterRun := time.Since(time.UnixMilli(c.task.StartTime))
	go func() {
		select {
		case <-time.After(afterRun):
			log.Infof("the profiling task need to wait %fmin to run: %s", afterRun.Minutes(), c.TaskID())
			m.runTask(c)
		case <-c.ctx.Done():
			return
		}
	}()
}

func (m *Manager) runTask(c *Context) {
	log.Infof("ready to starting profiling task: %s", c.TaskID())
	var wg sync.WaitGroup
	wg.Add(1)
	c.runningWg = &wg
	go func() {
		defer func() {
			wg.Done()
			c.status = Stopped
		}()

		notify := func() {
			c.status = Running
			c.startRunningTime = time.Now()
			m.afterProfilingStartSuccess(c)
		}
		// start running
		if err := c.runner.Run(m.ctx, notify); err != nil {
			log.Warnf("executing profiling task failure, taskId: %s, reason: %v", c.task.TaskID, err)
		}
	}()
}

func (m *Manager) afterProfilingStartSuccess(c *Context) {
	pidList := make([]int32, 0)
	for _, p := range c.processes {
		pidList = append(pidList, p.Pid())
	}
	log.Infof("profiling task has been started. taskId: %s, pid: %d", c.task.TaskID, pidList)
	go func() {
		for {
			endTime := c.startRunningTime.Add(c.task.MaxRunningDuration)
			select {
			// shutdown task when arrived task running task
			case <-time.After(time.Until(endTime)):
				log.Infof("arrived task running time, shutting down task: %s", c.task.TaskID)
				if err := m.shutdownTask(c); err != nil {
					log.Warnf("shutting down task failure: %s, reason: %v", c.task.TaskID, err)
				}
				return
			case <-c.recalcDuration:
				// re-calculate the task end-time
				log.Infof("received the extend duration task, task id: %s", c.task.TaskID)
				continue
			// shutdown when context finished
			case <-c.ctx.Done():
				if err := m.shutdownTask(c); err != nil {
					log.Warnf("shutting down task failure: %s, reason: %v", c.task.TaskID, err)
				}
				return
			}
		}
	}()
}

func (m *Manager) shutdownTask(c *Context) error {
	// return if not running
	if c.runningWg == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			log.Warnf("recover from shutdown task, id: %s, error: %v", c.TaskID(), r)
		}
	}()
	err := c.runner.Stop()
	c.runningWg.Wait()
	c.cancel()
	return err
}

func (m *Manager) ShutdownAndRemoveTask(c *Context) error {
	err := m.shutdownTask(c)
	delete(m.tasks, c.BuildTaskIdentity())
	return err
}

func (m *Manager) Shutdown() error {
	m.cancel()
	return nil
}

func (m *Manager) checkStoppedTaskAndRemoved() {
	for identity, t := range m.tasks {
		if t.status == Stopped {
			delete(m.tasks, identity)
		}
	}
}

func (m *Manager) startFlushProfilingData() {
	timeTicker := time.NewTicker(m.flushInterval)
	for {
		select {
		case <-timeTicker.C:
			if err := m.flushProfilingData(); err != nil {
				log.Warnf("flush profiling data failure: %v", err)
			}
			// cleanup the stopped after flush profiling data to make sure all the profiling data been sent
			m.checkStoppedTaskAndRemoved()
		case <-m.ctx.Done():
			timeTicker.Stop()
			return
		}
	}
}

func (m *Manager) flushProfilingData() error {
	if len(m.tasks) == 0 {
		return nil
	}

	stream, err := m.profilingClient.CollectProfilingData(m.ctx)
	if err != nil {
		return err
	}
	currentMilli := time.Now().UnixMilli()
	totalSendCount := make(map[string]int)
	for _, t := range m.tasks {
		data, err1 := t.runner.FlushData()
		if err1 != nil {
			log.Warnf("reading profiling task data failure. taskId: %s, error: %v", t.task.TaskID, err1)
			continue
		}

		if len(data) == 0 {
			continue
		}

		totalSendCount[t.TaskID()] += len(data)
		// only the first data have task metadata
		data[0].Task = &profiling_v3.EBPFProfilingTaskMetadata{
			TaskId:             t.task.TaskID,
			ProcessId:          t.task.ProcessIDList[0], // the profiling(draw flame-graph) task usually have the one process only
			ProfilingStartTime: t.startRunningTime.UnixMilli(),
			CurrentTime:        currentMilli,
		}

		for _, d := range data {
			// send each data, stop flush data if the stream have found error
			if err1 := stream.Send(d); err1 != nil {
				return err1
			}
		}
	}

	if len(totalSendCount) > 0 {
		log.Infof("send profiling data summary: %v", totalSendCount)
	}
	_, err = stream.CloseAndRecv()
	return err
}
