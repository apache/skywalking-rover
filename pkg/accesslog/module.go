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

package accesslog

import (
	"context"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
)

const ModuleName = "access_log"

type Module struct {
	config *common.Config

	runner *Runner
}

func NewModule() *Module {
	return &Module{config: &common.Config{}}
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
	runner, err := NewRunner(mgr, m.config)
	if err != nil {
		return err
	}
	err = runner.Start(ctx)
	if err != nil {
		return err
	}
	m.runner = runner
	return nil
}

func (m *Module) NotifyStartSuccess() {
}

func (m *Module) Shutdown(ctx context.Context, mgr *module.Manager) error {
	if m.runner != nil {
		return m.runner.Stop()
	}
	return nil
}
