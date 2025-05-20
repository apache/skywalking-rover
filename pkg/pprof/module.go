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

package pprof

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"sync"
	"time"

	"github.com/apache/skywalking-rover/pkg/module"
)

const ModuleName = "pprof"

type Module struct {
	config *Config

	mutex  sync.Mutex
	server *http.Server

	shutdown bool
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

func (m *Module) Start(_ context.Context, mgr *module.Manager) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", m.config.Port),
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           mux,
	}
	go func() {
		m.shutdown = false
		err := m.server.ListenAndServe()
		if err != nil && !m.shutdown {
			mgr.ShutdownModules(err)
		}
	}()
	return nil
}

func (m *Module) NotifyStartSuccess() {
}

func (m *Module) Shutdown(ctx context.Context, _ *module.Manager) error {
	m.shutdown = true
	if m.server != nil {
		return m.server.Shutdown(ctx)
	}
	return nil
}
