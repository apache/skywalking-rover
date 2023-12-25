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

package scanner

import (
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

var listenStatus = "LISTEN"

type Process struct {
	// original reference
	original     *process.Process
	finderConfig *RegexFinder

	// process data
	pid       int32
	cmd       string
	profiling *profiling.Info

	// entity for backend
	entity *api.ProcessEntity
}

func NewProcessByRegex(p *process.Process, cmdline string, config *RegexFinder) *Process {
	stat, _ := base.BuildProfilingStat(p)
	return &Process{original: p, pid: p.Pid, cmd: cmdline, finderConfig: config, profiling: stat, entity: &api.ProcessEntity{}}
}

func NewProcessByAgent(p *process.Process, cmdline string, agent *AgentMetadata) (*Process, error) {
	// basic data check
	var err error
	err = requiredNotNull(err, "layer", agent.Layer)
	err = requiredNotNull(err, "service name", agent.ServiceName)
	err = requiredNotNull(err, "instance name", agent.InstanceName)
	err = requiredNotNull(err, "process name", agent.ProcessName)
	if err != nil {
		return nil, err
	}

	// labels getter
	labels := make([]string, 0)
	if agent.Labels != "" {
		labels = strings.Split(agent.Labels, ",")
	}

	// profiling status
	stat, _ := base.BuildProfilingStat(p)

	// build result
	return &Process{
		original:  p,
		pid:       p.Pid,
		cmd:       cmdline,
		profiling: stat,
		entity: &api.ProcessEntity{
			Layer:        agent.Layer,
			ServiceName:  agent.ServiceName,
			InstanceName: agent.InstanceName,
			ProcessName:  agent.ProcessName,
			Labels:       labels,
		},
	}, nil
}

func (p *Process) Pid() int32 {
	return p.pid
}

func (p *Process) Entity() *api.ProcessEntity {
	return p.entity
}

func (p *Process) DetectType() api.ProcessDetectType {
	return api.Scanner
}

func (p *Process) OriginalProcess() *process.Process {
	return p.original
}

func (p *Process) ProfilingStat() *profiling.Info {
	return p.profiling
}

// BuildIdentity without pid
func (p *Process) BuildIdentity() string {
	return fmt.Sprintf("%s_%s_%s_%s", p.entity.Layer, p.entity.ServiceName,
		p.entity.InstanceName, p.entity.ProcessName)
}

func (p *Process) ExposePorts() []int {
	connections, err := p.original.Connections()
	if err != nil {
		log.Warnf("error getting the process connections, pid: %d, error: %v", p.pid, err)
	}
	ports := make([]int, 0)
	for _, con := range connections {
		if con.Status == listenStatus {
			ports = append(ports, int(con.Laddr.Port))
		}
	}
	return ports
}

func (p *Process) ExposeHosts() []string {
	connections, err := p.original.Connections()
	if err != nil {
		log.Warnf("error getting the process connections, pid: %d, error: %v", p.pid, err)
	}
	hosts := make([]string, 0)
	for _, con := range connections {
		if con.Status == listenStatus {
			hosts = append(hosts, con.Laddr.IP)
		}
	}
	return hosts
}

func requiredNotNull(err error, key, value string) error {
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("the %s could not be null", key)
	}
	return nil
}
