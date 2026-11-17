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

package boot

import (
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/config"
	"github.com/apache/skywalking-rover/pkg/module"
)

// the shipped configs/rover_configs.yaml must load through the real loader into every declared module, and the
// access log keys of the socket data layout (the attach of the programs, the h2c features) must reach its config
func TestLoadShippedRoverConfig(t *testing.T) {
	conf, err := config.Load("../../configs/rover_configs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findAllDeclaredModules(conf); err != nil {
		t.Fatal(err)
	}
	cfg, ok := module.FindModule(accesslog.ModuleName).Config().(*common.Config)
	if !ok {
		t.Fatalf("the access log config is %T", module.FindModule(accesslog.ModuleName).Config())
	}
	if cfg.BPF.AttachMode != "auto" || cfg.BPF.NATHook != "auto" {
		t.Fatalf("bpf: %+v", cfg.BPF)
	}
	if opts := cfg.LoaderOptions(); opts.AttachMode != "auto" || opts.NATHook != "auto" {
		t.Fatalf("loader options: %+v", opts)
	}
	if !cfg.ProtocolAnalyze.AnalyzeTraceContext {
		t.Fatal("analyze_trace_context is off")
	}
	if err := cfg.ResolveAnalyzeParallels(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROVER_ACCESS_LOG_BPF_ATTACH_MODE", "tracepoint")
	t.Setenv("ROVER_ACCESS_LOG_BPF_NAT_HOOK", "kprobe")
	t.Setenv("ROVER_ACCESS_LOG_PROTOCOL_ANALYZE_ANALYZE_TRACE_CONTEXT", "false")
	if _, err := findAllDeclaredModules(mustLoad(t, "../../configs/rover_configs.yaml")); err != nil {
		t.Fatal(err)
	}
	cfg = module.FindModule(accesslog.ModuleName).Config().(*common.Config)
	if opts := cfg.LoaderOptions(); opts.AttachMode != "tracepoint" || opts.NATHook != "kprobe" || cfg.ProtocolAnalyze.AnalyzeTraceContext {
		t.Fatalf("from the environment: %+v, trace %t", opts, cfg.ProtocolAnalyze.AnalyzeTraceContext)
	}
}

func mustLoad(t *testing.T, path string) *config.Config {
	t.Helper()
	conf, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

// TestTraceContextDefaultsOn: a configuration without analyze_trace_context analyzes the tracing context
func TestTraceContextDefaultsOn(t *testing.T) {
	if !accesslog.NewModule().Config().(*common.Config).ProtocolAnalyze.AnalyzeTraceContext {
		t.Fatal("the tracing context is off without the key")
	}
}
