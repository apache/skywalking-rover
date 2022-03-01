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

package vm

import (
	"fmt"

	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

type Process struct {
	// original reference
	original     *process.Process
	finderConfig *ProcessFinderConfig

	// process data
	pid       int32
	cmd       string
	profiling *profiling.Info

	// entity for backend
	entity *api.ProcessEntity
}

func NewProcess(p *process.Process, cmdline string, config *ProcessFinderConfig) *Process {
	return &Process{original: p, pid: p.Pid, cmd: cmdline, finderConfig: config, entity: &api.ProcessEntity{}}
}

func (p *Process) Pid() int32 {
	return p.pid
}

func (p *Process) Entity() *api.ProcessEntity {
	return p.entity
}

func (p *Process) DetectType() api.ProcessDetectType {
	return api.VM
}

func (p *Process) OriginalProcess() *process.Process {
	return p.original
}

// BuildIdentity without pid
func (p *Process) BuildIdentity() string {
	return fmt.Sprintf("%s_%s_%s_%s", p.cmd, p.entity.ServiceName,
		p.entity.InstanceName, p.entity.ProcessName)
}
