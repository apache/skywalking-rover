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

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task"
)

var log = logger.GetLogger("profiling", "continuous")

type Manager struct {
	checkers *Checkers
	triggers *Triggers

	ctx    context.Context
	cancel context.CancelFunc
}

func NewManager(ctx context.Context, taskManager *task.Manager, moduleMgr *module.Manager, config *base.ContinuousConfig) (*Manager, error) {
	m := &Manager{}
	m.ctx, m.cancel = context.WithCancel(ctx)

	// init all checkers and triggerRegistration
	triggers, err := NewTriggers(m.ctx, moduleMgr, taskManager, config)
	if err != nil {
		return nil, err
	}
	m.triggers = triggers
	checkers, err := NewCheckers(m.ctx, moduleMgr, config, m.triggers)
	if err != nil {
		return nil, err
	}
	m.checkers = checkers

	return m, nil
}

func (m *Manager) Start() {
	m.checkers.Start()
}

func (m *Manager) CheckPolicies() error {
	return m.checkers.CheckProfilingPolicies()
}

func (m *Manager) Shutdown() error {
	err := m.checkers.Stop()
	m.cancel()
	return err
}
