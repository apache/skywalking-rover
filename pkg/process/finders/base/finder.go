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

package base

import (
	"context"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
)

type BuildEBPFProcessContext struct {
	HostIP string
}

// ProcessFinder is defined how to detect the process and communicate with backend
type ProcessFinder interface {
	// Init the finder before Start
	Init(ctx context.Context, conf FinderBaseConfig, manager ProcessManager) error
	// Start to detect process
	Start()
	// Stop the process detect
	Stop() error
	// DetectType of Process is detecting
	DetectType() api.ProcessDetectType

	// ShouldMonitor validate the process needs to be monitored, if true, then add it into the storage
	ShouldMonitor(pid int32) bool

	// ValidateProcessIsSame between two same finder process
	ValidateProcessIsSame(p1, p2 api.DetectedProcess) bool

	// BuildEBPFProcess is transform the process entity as backend protocol data
	BuildEBPFProcess(ctx *BuildEBPFProcessContext, process api.DetectedProcess) *v3.EBPFProcessProperties
	// BuildNecessaryProperties is getting minimize necessary properties when keep alive
	BuildNecessaryProperties(process api.DetectedProcess) []*commonv3.KeyStringValuePair
	// ParseProcessId is means how to read the process id receive from backend
	ParseProcessID(process api.DetectedProcess, downstream *v3.EBPFProcessDownstream) string
}

// ProcessManager is an API work for help ProcessFinder synchronized process with backend
type ProcessManager interface {
	GetModuleManager() *module.Manager
	// SyncAllProcessInFinder is mean synchronized all processes data from current ProcessFinder
	SyncAllProcessInFinder(processes []api.DetectedProcess)
	// AddDetectedProcess only add the specific processes
	AddDetectedProcess(processes []api.DetectedProcess)
}
