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

	"github.com/apache/skywalking-rover/pkg/profiling/continuous"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/profiling/task"
)

// Manager the profiling task, receive them from the backend side
type Manager struct {
	checkInterval     time.Duration
	flushInterval     time.Duration
	taskManager       *task.Manager
	continuousManager *continuous.Manager

	ctx    context.Context
	cancel context.CancelFunc
}

func NewManager(ctx context.Context, manager *module.Manager, conf *Config) (*Manager, error) {
	checkDuration, err := time.ParseDuration(conf.CheckInterval)
	if err != nil {
		return nil, fmt.Errorf("parse profling check interval failure: %v", err)
	}

	flushDuration, err := time.ParseDuration(conf.FlushInterval)
	if err != nil {
		return nil, fmt.Errorf("parse profiling data flush interval failure: %v", err)
	}

	taskManager, err := task.NewManager(ctx, manager, conf.TaskConfig)
	if err != nil {
		return nil, err
	}

	continuousManager, err := continuous.NewManager(ctx, taskManager, manager, conf.ContinuousConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Manager{
		checkInterval:     checkDuration,
		flushInterval:     flushDuration,
		taskManager:       taskManager,
		continuousManager: continuousManager,
		ctx:               ctx,
		cancel:            cancel,
	}, nil
}

func (m *Manager) Start() {
	m.taskManager.Start()
	m.continuousManager.Start()
	go func() {
		checkTicker := time.NewTicker(m.checkInterval)
		flushTicker := time.NewTicker(m.flushInterval)
		for {
			select {
			case <-checkTicker.C:
				m.logErrorIfContains(m.taskManager.StartingWatchTask(), "check profiling task")
				m.logErrorIfContains(m.continuousManager.CheckPolicies(), "check profiling policies")
			case <-flushTicker.C:
				m.logErrorIfContains(m.taskManager.FlushProfilingData(), "flush profiling task")
			case <-m.ctx.Done():
				checkTicker.Stop()
				return
			}
		}
	}()
}

func (m *Manager) logErrorIfContains(err error, t string) {
	if err != nil {
		log.Warnf("%s failure: %v", t, err)
	}
}

func (m *Manager) Shutdown() error {
	if err := m.taskManager.Shutdown(); err != nil {
		log.Warnf("task manager shutdown failure: %v", err)
	}
	if err := m.continuousManager.Shutdown(); err != nil {
		log.Warnf("continuous profiling manager shutdown failure: %v", err)
	}
	m.cancel()
	return nil
}
