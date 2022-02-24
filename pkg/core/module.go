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

	"github.com/apache/skywalking-rover/pkg/core/client/grpc"
	"github.com/apache/skywalking-rover/pkg/module"

	"github.com/hashicorp/go-multierror"
)

const ModuleName = "core"

type Module struct {
	config *Config

	grpcClient *grpc.Client
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

func (m *Module) Start(ctx context.Context, mgr *module.Manager) error {
	// grpc client
	if m.config.GrpcClientConfig != nil {
		m.grpcClient = grpc.NewClient(m.config.GrpcClientConfig)
		if err := m.grpcClient.Start(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (m *Module) Shutdown(ctx context.Context, mgr *module.Manager) error {
	var result *multierror.Error
	if m.grpcClient != nil {
		result = multierror.Append(result, m.grpcClient.Stop())
	}
	return result.ErrorOrNil()
}

func (m *Module) ClientGrpcOperator() grpc.Operator {
	if m.grpcClient == nil {
		return nil
	}
	return m.grpcClient
}
