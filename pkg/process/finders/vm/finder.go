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
	"context"
	"fmt"
	"regexp"
	"time"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools"
)

var log = logger.GetLogger("process", "finder", "vm")

type ProcessFinder struct {
	conf *Config

	manager   base.ProcessManager
	ctx       context.Context
	cancelCtx context.CancelFunc

	period time.Duration
}

func (p *ProcessFinder) Init(ctx context.Context, conf base.FinderBaseConfig, manager base.ProcessManager) error {
	if err := validateConfig(conf.(*Config)); err != nil {
		return err
	}

	p.conf = conf.(*Config)
	p.manager = manager
	p.ctx, p.cancelCtx = context.WithCancel(ctx)

	period, err := time.ParseDuration(p.conf.Period)
	if err != nil {
		return err
	}
	p.period = period
	return nil
}

func (p *ProcessFinder) Start() {
	go p.startWatch()
}

func (p *ProcessFinder) Stop() error {
	p.cancelCtx()
	return nil
}

func (p *ProcessFinder) DetectType() api.ProcessDetectType {
	return api.VM
}

func (p *ProcessFinder) ValidateProcessIsSame(p1, p2 base.DetectedProcess) bool {
	vm1 := p1.(*Process)
	vm2 := p2.(*Process)
	return p1.Pid() == p2.Pid() && vm1.cmd == vm2.cmd && p1.Entity().SameWith(p2.Entity())
}

func (p *ProcessFinder) BuildEBPFProcess(ctx *base.BuildEBPFProcessContext, ps base.DetectedProcess) *v3.EBPFProcessProperties {
	hostProcess := &v3.EBPFHostProcessMetadata{}
	hostProcess.HostIP = ctx.HostIP
	hostProcess.Pid = ps.Pid()
	hostProcess.Cmd = ps.(*Process).cmd
	hostProcess.Entity = &v3.EBPFProcessEntityMetadata{
		Layer:        ps.Entity().Layer,
		ServiceName:  ps.Entity().ServiceName,
		InstanceName: ps.Entity().InstanceName,
		ProcessName:  ps.Entity().ProcessName,
	}
	properties := &v3.EBPFProcessProperties{Metadata: &v3.EBPFProcessProperties_HostProcess{
		HostProcess: hostProcess,
	}}
	return properties
}

func (p *ProcessFinder) ParseProcessID(ps base.DetectedProcess, downstream *v3.EBPFProcessDownstream) string {
	if downstream.GetHostProcess() == nil {
		return ""
	}
	if ps.Pid() == downstream.GetHostProcess().GetPid() {
		return downstream.ProcessId
	}
	return ""
}

func (p *ProcessFinder) startWatch() {
	// find one time
	if err := p.findAndReportProcesses(); err != nil {
		log.Warnf("list all process failure, %v", err)
	}
	// schedule
	ticker := time.NewTicker(p.period)
	for {
		select {
		case <-ticker.C:
			if err := p.findAndReportProcesses(); err != nil {
				log.Warnf("list all process failure, %v", err)
			}
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *ProcessFinder) findAndReportProcesses() error {
	// find all process
	processes, err := p.findMatchedProcesses()
	if err != nil {
		return err
	}

	// validate the process could be profiling
	processes = p.validateTheProcessesCouldProfiling(processes)

	// report to the manager
	psList := make([]base.DetectedProcess, 0)
	for _, ps := range processes {
		psList = append(psList, ps)
	}
	p.manager.SyncAllProcessInFinder(psList)
	return nil
}

func (p *ProcessFinder) validateTheProcessesCouldProfiling(processes []*Process) []*Process {
	result := make([]*Process, 0)
	for _, ps := range processes {
		exe, err := ps.original.Exe()
		if err != nil {
			log.Warnf("could not read process exe file path, pid: %d, reason: %v", ps.pid, err)
			continue
		}

		// check support profiling
		if pf, err := tools.ExecutableFileProfilingStat(exe); err != nil {
			log.Warnf("the process could not be profiling, so ignored. pid: %d, reason: %v", ps.pid, err)
			continue
		} else {
			ps.profiling = pf
		}

		result = append(result, ps)
	}
	return result
}

func (p *ProcessFinder) findMatchedProcesses() ([]*Process, error) {
	// all system processes
	processes, err := process.ProcessesWithContext(p.ctx)
	if err != nil {
		return nil, err
	}
	// find all matches processes
	findedProcesses := make([]*Process, 0)
	for _, pro := range processes {
		// TODO should we need verify the process must be in the root namespace? such as exclude the container processes
		// That's mean the same process would could only be detect by one finder?

		// find the matched process finder
		finderConfig, cmdline, err := p.findMatchesFinder(pro)
		if err != nil {
			log.Warnf("failed to match process %d, reason: %v", pro.Pid, err)
			continue
		}
		if finderConfig == nil {
			continue
		}

		// build the linux process and add to the list
		ps := NewProcess(pro, cmdline, finderConfig)
		ps.entity.Layer = finderConfig.Layer
		ps.entity.ServiceName, err = p.buildEntity(err, ps, finderConfig.serviceNameBuilder)
		ps.entity.InstanceName, err = p.buildEntity(err, ps, finderConfig.instanceNameBuilder)
		ps.entity.ProcessName, err = p.buildEntity(err, ps, finderConfig.processNameBuilder)
		if err != nil {
			log.Warnf("failed to build the process data for pid: %d, reason: %v", pro.Pid, err)
			continue
		} else {
			findedProcesses = append(findedProcesses, ps)
		}
	}
	if len(findedProcesses) == 0 {
		return nil, nil
	}
	// remove duplicated(identity) process
	identity2Processes := make(map[string][]*Process)
	for _, ps := range findedProcesses {
		id := ps.BuildIdentity()
		if identity2Processes[id] == nil {
			identity2Processes[id] = make([]*Process, 0)
		}
		identity2Processes[id] = append(identity2Processes[id], ps)
	}
	result := make([]*Process, 0)
	for _, psList := range identity2Processes {
		reportProcess := psList[0]
		if len(psList) > 1 {
			pidList := make([]int32, 0)
			for _, ps := range psList {
				pidList = append(pidList, ps.pid)
			}
			log.WithField("command_line", reportProcess.cmd).
				WithField("service_name", reportProcess.entity.ServiceName).
				WithField("instance_name", reportProcess.entity.InstanceName).
				WithField("process_name", reportProcess.entity.ProcessName).
				WithField("pid_list", pidList).
				Warnf("find multiple similar process in VM, " +
					"only report the first of these processes. " +
					"please update the name of process to identity them more clear.")
		}
		result = append(result, reportProcess)
	}
	return result, nil
}

func (p *ProcessFinder) buildEntity(err error, ps *Process, entity *base.TemplateBuilder) (string, error) {
	if err != nil {
		return "", err
	}
	return renderTemplate(entity, ps, p)
}

func (p *ProcessFinder) findMatchesFinder(ps *process.Process) (*ProcessFinderConfig, string, error) {
	// verify the process exists, if not exists just return
	if exists, err := process.PidExists(ps.Pid); err != nil {
		return nil, "", err
	} else if !exists {
		return nil, "", nil
	}

	cmdline, err := ps.Cmdline()
	if err != nil {
		return nil, "", fmt.Errorf("query command line failure: %v", err)
	}
	var matched *ProcessFinderConfig
	for _, finder := range p.conf.Finders {
		if finder.commandlineRegex.MatchString(cmdline) {
			if matched == nil {
				matched = finder
			} else {
				log.Warnf("found multiple finder for the process %d, command line: %s, choose the first one mached to build process",
					ps.Pid, cmdline)
				return matched, cmdline, nil
			}
		}
	}
	return matched, cmdline, nil
}

func validateConfig(conf *Config) error {
	if len(conf.Finders) == 0 {
		return fmt.Errorf("must have one VM process finder")
	}

	// validate config
	for _, f := range conf.Finders {
		var err error
		err = stringMustNotNull(err, "layer", f.Layer)
		f.commandlineRegex, err = regexMustNotNull(err, "match_cmd_regex", f.MatchCommandRegex)
		f.serviceNameBuilder, err = templateMustNotNull(err, "service_name", f.ServiceName)
		f.instanceNameBuilder, err = templateMustNotNull(err, "instance_name", f.InstanceName)
		f.processNameBuilder, err = templateMustNotNull(err, "process_name", f.ProcessName)

		if err != nil {
			return err
		}
	}

	return nil
}

func stringMustNotNull(err error, confKey, confValue string) error {
	if err != nil {
		return err
	}
	if confValue == "" {
		return fmt.Errorf("the %s of VM process must be set", confKey)
	}
	return nil
}

func templateMustNotNull(err error, confKey, confValue string) (*base.TemplateBuilder, error) {
	if err1 := stringMustNotNull(err, confKey, confValue); err1 != nil {
		return nil, err1
	}
	return base.NewTemplateBuilder(confKey, confValue)
}

func regexMustNotNull(err error, confKey, confValue string) (*regexp.Regexp, error) {
	if err1 := stringMustNotNull(err, confKey, confValue); err1 != nil {
		return nil, err1
	}
	return regexp.Compile(confValue)
}
