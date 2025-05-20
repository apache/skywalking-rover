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

package process

import (
	"context"
	"time"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders"
	"github.com/apache/skywalking-rover/pkg/process/finders/kubernetes"
)

const ModuleName = "process_discovery"

type Module struct {
	config *Config

	manager *finders.ProcessManager
}

func NewModule() *Module {
	return &Module{config: &Config{}}
}

func (m *Module) Name() string {
	return ModuleName
}

func (m *Module) RequiredModules() []string {
	return []string{core.ModuleName}
}

func (m *Module) Config() module.ConfigInterface {
	return m.config
}

func (m *Module) Start(ctx context.Context, mgr *module.Manager) error {
	period, err := time.ParseDuration(m.config.HeartbeatPeriod)
	if err != nil {
		return err
	}
	processManager, err := finders.NewProcessManager(ctx, mgr, period, m.config.PropertiesReportPeriod, m.config.Kubernetes)
	if err != nil {
		return err
	}
	m.manager = processManager

	return nil
}

func (m *Module) NotifyStartSuccess() {
	// notify all finder to report processes
	m.manager.Start()
}

func (m *Module) Shutdown(context.Context, *module.Manager) error {
	return m.manager.Shutdown()
}

func (m *Module) GetAllProcesses() []api.ProcessInterface {
	return m.manager.GetAllProcesses()
}

func (m *Module) FindProcessByID(processID string) api.ProcessInterface {
	return m.manager.FindProcessByID(processID)
}

func (m *Module) FindAllRegisteredProcesses() []api.ProcessInterface {
	return m.manager.FindAllRegisteredProcesses()
}

func (m *Module) FindProcessByPID(pid int32) []api.ProcessInterface {
	return m.manager.FindProcessByPID(pid)
}

func (m *Module) AddListener(listener api.ProcessListener) {
	m.manager.AddListener(listener)
}

func (m *Module) DeleteListener(listener api.ProcessListener) {
	m.manager.DeleteListener(listener)
}

func (m *Module) ShouldMonitor(pid int32) bool {
	return m.manager.ShouldMonitor(pid)
}

func (m *Module) NodeName() string {
	return m.config.Kubernetes.NodeName
}

func (m *Module) IsPodIP(ip string) (bool, error) {
	k8sFinder, exist := m.manager.Finder(api.Kubernetes)
	if !exist {
		return false, nil
	}
	return k8sFinder.(*kubernetes.ProcessFinder).IsPodIP(ip)
}
