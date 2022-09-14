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
	"bytes"
	"fmt"
	"text/template"

	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools"
)

type TemplateBuilder struct {
	Name     string
	Template string

	template *template.Template
}

func NewTemplateBuilder(name, content string) (*TemplateBuilder, error) {
	tmpl, err := template.New(name).Funcs(customFunctions).Parse(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template for %s, content: %s. reason: %v", name, content, err)
	}
	return &TemplateBuilder{Name: name, Template: content, template: tmpl}, nil
}

func (t *TemplateBuilder) Execute(data interface{}) (string, error) {
	var r bytes.Buffer
	if err := t.template.Execute(&r, data); err != nil {
		return "", err
	}
	return r.String(), nil
}

// NewTemplateRover is generated the Rover context for render
func NewTemplateRover(manager *module.Manager) *TemplateRover {
	operator := manager.FindModule(core.ModuleName).(core.Operator)
	return &TemplateRover{operator.InstanceID()}
}

// NewTemplateProcess is generated the process context for render
func NewTemplateProcess(manager *module.Manager, p *process.Process) *TemplateProcess {
	return &TemplateProcess{p}
}

type TemplateRover struct {
	instanceID string
}

// InstanceID of rover
func (t *TemplateRover) InstanceID() string {
	return t.instanceID
}

// HostIPV4 ip v4 address of local machine from appoint net interface name
func (t *TemplateRover) HostIPV4(name string) (string, error) {
	v4 := tools.HostIPAddressV4(name)
	if v4 == "" {
		return "", fmt.Errorf("could not found the ip v4 address from %s", name)
	}
	return v4, nil
}

// HostIPV6 ip v6 address of local machine from appoint net interface name
func (t *TemplateRover) HostIPV6(name string) (string, error) {
	v6 := tools.HostIPAddressV6(name)
	if v6 == "" {
		return "", fmt.Errorf("could not found the ip v6 address from %s", name)
	}
	return v6, nil
}

// HostName name of local machine
func (t *TemplateRover) HostName() string {
	return tools.Hostname()
}

type TemplateProcess struct {
	*process.Process
}

// ExeFilePath Execute file path
func (p *TemplateProcess) ExeFilePath() (string, error) {
	return p.Exe()
}

// ExeName Execute file name
func (p *TemplateProcess) ExeName() (string, error) {
	return p.Name()
}

// CommandLine command line of process
func (p *TemplateProcess) CommandLine() (string, error) {
	return p.Cmdline()
}

// Pid of process
func (p *TemplateProcess) Pid() int32 {
	return p.Process.Pid
}

// WorkDir means which directory to run the execute file
func (p *TemplateProcess) WorkDir() (string, error) {
	return p.Cwd()
}

// ExeNameInCommandLine means the executed file name in the command line string
func (p *TemplateProcess) ExeNameInCommandLine() (string, error) {
	cmdline, err := p.CmdlineSlice()
	if err != nil {
		return "", err
	}
	if len(cmdline) == 0 {
		return "", fmt.Errorf("cannot found the command line")
	}
	return cmdline[0], nil
}
