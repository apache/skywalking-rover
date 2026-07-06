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

package kubernetes

import (
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

type Process struct {
	original *process.Process

	// process data
	pid                  int32
	cmd                  string
	supportProfilingOnce sync.Once
	supportProfiling     bool
	podContainer         *PodContainer

	// entity for the backend
	entity *api.ProcessEntity
}

func NewProcess(p *process.Process, cmdline string, pc *PodContainer, entity *api.ProcessEntity) *Process {
	return &Process{
		original:     p,
		pid:          p.Pid,
		cmd:          cmdline,
		podContainer: pc,
		entity:       entity,
	}
}

func (p *Process) Pid() int32 {
	return p.pid
}

func (p *Process) OriginalProcess() *process.Process {
	return p.original
}

func (p *Process) Entity() *api.ProcessEntity {
	return p.entity
}

func (p *Process) DetectType() api.ProcessDetectType {
	return api.Kubernetes
}

// ProfilingStat builds the full profiling info (heavy: parses and retains the ELF symbol tables).
// It intentionally does NOT cache the result on the process: the info is only needed while a
// profiling task runs and is held by that task's runner, so it is released once the task ends.
func (p *Process) ProfilingStat() *profiling.Info {
	stat, _ := base.BuildProfilingStat(p.original)
	return stat
}

// SupportProfiling reports whether the process can be profiled, WITHOUT retaining the symbol data.
// The result is a bool that is cheap to cache, so keep-alive reporting does not re-parse the ELF
// symbol tables of every discovered process on each report.
func (p *Process) SupportProfiling() bool {
	p.supportProfilingOnce.Do(func() {
		p.supportProfiling, _ = base.SupportProfiling(p.original)
	})
	return p.supportProfiling
}

func (p *Process) PodContainer() *PodContainer {
	return p.podContainer
}

func (p *Process) ExposePorts() []int {
	result := make([]int, 0)
	for _, cp := range p.podContainer.ContainerSpec.Ports {
		result = append(result, int(cp.ContainerPort))
		if cp.HostPort > 0 {
			result = append(result, int(cp.HostPort))
		}
	}
	connections, err := p.original.Connections()
	if err != nil {
		// A short-lived process may exit between discovery and this query, making its
		// /proc/<pid>/net/* files disappear. That is an expected race for ephemeral processes
		// (e.g. curl/sleep from load generators), not a real error, so keep it at debug level
		// to avoid flooding the log.
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file or directory") {
			log.Debugf("skip querying connections for the exited process, pid: %d, error: %v", p.pid, err)
		} else {
			log.Warnf("query the process connection error: pid: %d, error: %v", p.pid, err)
		}
		return result
	}
	for _, c := range connections {
		if c.Status == "LISTEN" {
			result = append(result, int(c.Laddr.Port))
		}
	}

	return result
}

func (p *Process) ExposeHosts() []string {
	result := make([]string, 0)
	for _, ip := range p.podContainer.Pod.Status.PodIPs {
		result = append(result, ip.IP)
	}
	return result
}
