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

	"github.com/cilium/ebpf/rlimit"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
)

const ModuleName = "profiling"

var log = logger.GetLogger("profiling")

type Module struct {
	config *Config

	manager *Manager
}

func NewModule() *Module {
	return &Module{config: &Config{}}
}

func (m *Module) Name() string {
	return ModuleName
}

func (m *Module) RequiredModules() []string {
	return []string{core.ModuleName, process.ModuleName}
}

func (m *Module) Config() module.ConfigInterface {
	return m.config
}

func (m *Module) Start(ctx context.Context, mgr *module.Manager) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	manager, err := NewManager(ctx, mgr, m.config)
	if err != nil {
		return err
	}
	m.manager = manager
	return nil
}

func (m *Module) NotifyStartSuccess() {
	m.manager.Start()
}

func (m *Module) Shutdown(ctx context.Context, mgr *module.Manager) error {
	return m.manager.Shutdown()
}
