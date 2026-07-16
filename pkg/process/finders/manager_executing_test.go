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

package finders

import (
	"context"
	"testing"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
)

// plainFinder monitors only long-lived processes, the way the VM finder does: it has no use for a
// process reported the instant it starts, so it does not implement ExecutingProcessFinder.
type plainFinder struct{}

func (p *plainFinder) Init(_ context.Context, _ base.FinderBaseConfig, _ base.ProcessManager) error {
	return nil
}
func (p *plainFinder) Start()                                              {}
func (p *plainFinder) Stop() error                                         { return nil }
func (p *plainFinder) DetectType() api.ProcessDetectType                   { return api.Kubernetes }
func (p *plainFinder) ShouldMonitor(_ int32) bool                          { return false }
func (p *plainFinder) ValidateProcessIsSame(_, _ api.DetectedProcess) bool { return false }
func (p *plainFinder) BuildEBPFProcess(_ *base.BuildEBPFProcessContext, _ api.DetectedProcess) *v3.EBPFProcessProperties {
	return nil
}
func (p *plainFinder) BuildNecessaryProperties(_ api.DetectedProcess) []*commonv3.KeyStringValuePair {
	return nil
}
func (p *plainFinder) ParseProcessID(_ api.DetectedProcess, _ *v3.EBPFProcessDownstream) string {
	return ""
}

// executingFinder additionally takes processes as they start, the way the Kubernetes finder does.
type executingFinder struct{ plainFinder }

func (e *executingFinder) ShouldMonitorExecuting(_ *api.ProcessExecuteContext) bool { return true }

// TestExecutingProcessesWanted pins the gate that decides whether the kernel is asked to report
// processes at all.
//
// The cost of getting this wrong is asymmetric and silent. Reporting when nothing can use the
// reports is what made these tracepoints unaffordable before: a finder that only monitors
// long-lived processes rejects every reported one *after* a /proc read, paying the full price for
// no coverage. Nothing fails; the agent just quietly burns CPU on every process the machine starts.
func TestExecutingProcessesWanted(t *testing.T) {
	tests := []struct {
		name    string
		finders []base.ProcessFinder
		want    bool
	}{
		{
			name:    "no finder can use the reports - do not ask for them",
			finders: []base.ProcessFinder{&plainFinder{}},
			want:    false,
		},
		{
			name:    "a finder takes processes as they start",
			finders: []base.ProcessFinder{&executingFinder{}},
			want:    true,
		},
		{
			name:    "one of several can use them",
			finders: []base.ProcessFinder{&plainFinder{}, &executingFinder{}},
			want:    true,
		},
		{
			name:    "no active finder at all",
			finders: nil,
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ProcessManager{finders: make(map[base.FinderBaseConfig]base.ProcessFinder)}
			for i, f := range tt.finders {
				m.finders[&stubConfig{id: i}] = f
			}
			if got := m.ExecutingProcessesWanted(); got != tt.want {
				t.Fatalf("ExecutingProcessesWanted() = %v, want %v", got, tt.want)
			}
		})
	}
}

type stubConfig struct{ id int }

func (s *stubConfig) ActiveFinder() bool { return true }
