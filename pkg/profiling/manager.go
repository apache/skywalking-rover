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
	"context"
	"fmt"
	"time"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/profiling/task"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

// Manager the profiling task, receive them from the backend side
type Manager struct {
	profilingClient v3.EBPFProfilingServiceClient
	interval        time.Duration
	taskManager     *task.Manager

	ctx    context.Context
	cancel context.CancelFunc

	instanceID     string
	lastUpdateTime int64
}

func NewManager(ctx context.Context, manager *module.Manager, conf *Config) (*Manager, error) {
	coreOperator := manager.FindModule(core.ModuleName).(core.Operator)
	connection := coreOperator.BackendOperator().GetConnection()
	profilingClient := v3.NewEBPFProfilingServiceClient(connection)
	instanceID := coreOperator.InstanceID()
	duration, err := time.ParseDuration(conf.CheckInterval)
	if err != nil {
		return nil, fmt.Errorf("parse profling check interval failure: %v", err)
	}

	flushDuration, err := time.ParseDuration(conf.FlushInterval)
	if err != nil {
		return nil, fmt.Errorf("parse profiling data flush interval failure: %v", err)
	}

	taskManager, err := task.NewManager(ctx, manager, profilingClient, flushDuration, conf.TaskConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Manager{
		profilingClient: profilingClient,
		taskManager:     taskManager,
		interval:        duration,
		ctx:             ctx,
		cancel:          cancel,
		instanceID:      instanceID,
		lastUpdateTime:  -1,
	}, nil
}

func (m *Manager) Start() {
	m.taskManager.Start()
	go func() {
		timeTicker := time.NewTicker(m.interval)
		for {
			select {
			case <-timeTicker.C:
				if err := m.startingWatchTask(); err != nil {
					log.Errorf("fetch profiling task failure: %v", err)
				}
			case <-m.ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()
}

func (m *Manager) startingWatchTask() error {
	// query task
	tasks, err := m.profilingClient.QueryTasks(m.ctx, &v3.EBPFProfilingTaskQuery{
		RoverInstanceId:  m.instanceID,
		LatestUpdateTime: m.lastUpdateTime,
	})
	if err != nil {
		return err
	}
	if len(tasks.Commands) == 0 {
		return nil
	}

	// analyze profiling tasks
	taskContexts := make([]*task.Context, 0)
	lastUpdateTime := m.lastUpdateTime
	for _, cmd := range tasks.Commands {
		taskContext, err := m.taskManager.BuildContext(cmd)
		if err != nil {
			log.Warnf("could not execute task, ignored. %v", err)
			continue
		}

		if taskContext.UpdateTime() > lastUpdateTime {
			lastUpdateTime = taskContext.UpdateTime()
		}

		if !taskContext.CheckTaskRunnable() {
			continue
		}

		taskContexts = append(taskContexts, taskContext)
	}

	// update last task time
	m.lastUpdateTime = lastUpdateTime

	if len(taskContexts) == 0 {
		return nil
	}

	taskIDList := make([]string, len(taskContexts))
	for inx, c := range taskContexts {
		taskIDList[inx] = c.TaskID()
	}
	log.Infof("received %d profiling task: %v", len(taskContexts), taskIDList)

	// start tasks
	for _, t := range taskContexts {
		m.taskManager.StartTask(t)
	}
	return nil
}

func (m *Manager) Shutdown() error {
	if err := m.taskManager.Shutdown(); err != nil {
		log.Warnf("task manager shutdown failure: %v", err)
	}
	m.cancel()
	return nil
}
