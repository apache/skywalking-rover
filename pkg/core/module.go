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

package core

import (
	"context"

	"github.com/google/uuid"

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/core/backend"
	"github.com/apache/skywalking-rover/pkg/module"
)

const ModuleName = "core"

type Module struct {
	config *Config

	instanceID    string
	clusterName   string
	backendClient *backend.Client
}

func NewModule() *Module {
	return &Module{config: &Config{}}
}

func (m *Module) Name() string {
	return ModuleName
}

func (m *Module) RequiredModules() []string {
	return nil
}

func (m *Module) Config() module.ConfigInterface {
	return m.config
}

func (m *Module) ClusterName() string {
	return m.clusterName
}

func (m *Module) Start(ctx context.Context, mgr *module.Manager) error {
	// generate instance id
	m.instanceID = uuid.New().String()
	m.clusterName = m.config.ClusterName
	// backend client
	if m.config.BackendConfig != nil {
		m.backendClient = backend.NewClient(m.config.BackendConfig)
		if err := m.backendClient.Start(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (m *Module) NotifyStartSuccess() {
}

func (m *Module) Shutdown(ctx context.Context, mgr *module.Manager) error {
	var result *multierror.Error
	if m.backendClient != nil {
		result = multierror.Append(result, m.backendClient.Stop())
	}
	return result.ErrorOrNil()
}

func (m *Module) BackendOperator() backend.Operator {
	if m.backendClient == nil {
		return nil
	}
	return m.backendClient
}

func (m *Module) InstanceID() string {
	return m.instanceID
}
