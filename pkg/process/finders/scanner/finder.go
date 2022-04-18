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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var log = logger.GetLogger("process", "finder", "scanner")

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
	return api.Scanner
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
		Labels:       ps.Entity().Labels,
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
	p.findAndReportProcesses()
	// schedule
	ticker := time.NewTicker(p.period)
	for {
		select {
		case <-ticker.C:
			p.findAndReportProcesses()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *ProcessFinder) findAndReportProcesses() {
	var detectFunc func() ([]base.DetectedProcess, error)
	if p.conf.ScanMode == Regex {
		detectFunc = p.regexFindProcesses
	} else if p.conf.ScanMode == Agent {
		detectFunc = p.agentFindProcesses
	}

	if processes, err := detectFunc(); err != nil {
		log.Warnf("list process failure, %v", err)
	} else {
		p.manager.SyncAllProcessInFinder(processes)
	}
}

func (p *ProcessFinder) regexFindProcesses() ([]base.DetectedProcess, error) {
	// find all process
	processes, err := p.regexFindMatchedProcesses()
	if err != nil {
		return nil, err
	}

	// validate the process could be profiling
	processes = p.validateTheProcessesCouldProfiling(processes)

	// report to the manager
	psList := make([]base.DetectedProcess, 0)
	for _, ps := range processes {
		psList = append(psList, ps)
	}
	return psList, nil
}

func (p *ProcessFinder) getProcessTempDir(pro *process.Process) (string, error) {
	tmpDir := host.GetFileInHost(fmt.Sprintf("/proc/%d/root/tmp", pro.Pid))
	environ, err := pro.Environ()
	if err != nil {
		log.Warnf("could not query the environments from the process, pid: %d, error: %v", pro.Pid, err)
	}

	prefix := "TMPDIR="
	for _, env := range environ {
		if strings.HasPrefix(env, prefix) {
			dir := host.GetFileInHost(fmt.Sprintf("/proc/%d/root/%s", pro.Pid, strings.TrimPrefix(env, prefix)))
			if pathExists(dir, nil) {
				return dir, nil
			}
		}
	}

	if pathExists(tmpDir, nil) {
		return tmpDir, nil
	}
	return "", fmt.Errorf("could not found tmp directory for pid: %d", pro.Pid)
}

func (p *ProcessFinder) agentFindProcesses() ([]base.DetectedProcess, error) {
	// all system processes
	processes, err := process.ProcessesWithContext(p.ctx)
	if err != nil {
		return nil, err
	}
	// find all matches processes
	findedProcesses := make([]base.DetectedProcess, 0)
	for _, pro := range processes {
		// already contains the processes
		pid := pro.Pid
		if detectProcess := p.manager.QueryProcess(pid); detectProcess != nil {
			findedProcesses = append(findedProcesses, detectProcess)
			continue
		}

		// if we cannot get temp directory, just ignore it
		// May have some system process
		tmpDir, err := p.getProcessTempDir(pro)
		if err != nil {
			continue
		}

		metadataFilePath, metadataFile, err := p.tryingToGetAgentMetadataFile(pro, tmpDir)
		if err != nil {
			log.Infof("found metadata file error, pid: %d, error: %v", pid, err)
			continue
		}

		// modify time + recent > now
		// means the metadata file is acceptable
		if !metadataFile.ModTime().Add(p.conf.Agent.RecentDuration).After(time.Now()) {
			continue
		}

		// build agent process
		agentProcess, err := p.buildProcessFromAgentMetadata(pro, metadataFilePath)
		if err != nil {
			log.Warnf("could not parsing metadata, pid: %d, error: %v", pid, err)
			continue
		}

		// could be profiling
		if err := p.validateProcessCouldProfiling(agentProcess); err != nil {
			log.Warnf("found agent process, but it could not profiling, so ignore, pid: %d, error: %v", pid, err)
			continue
		}

		findedProcesses = append(findedProcesses, agentProcess)
	}
	return findedProcesses, nil
}

func (p *ProcessFinder) tryingToGetAgentMetadataFile(pro *process.Process, tmpDir string) (string, os.FileInfo, error) {
	// get from the local machine
	if f, info, err := p.tryingToGetAgentMetadataFileByPid(int64(pro.Pid), tmpDir); err == nil {
		return f, info, nil
	}

	// get from the child ns(container)
	processStatusFilePath := host.GetFileInHost(fmt.Sprintf("/proc/%d/status", pro.Pid))
	processStatusFile, err := os.Open(processStatusFilePath)
	if err != nil {
		return "", nil, err
	}
	defer processStatusFile.Close()
	scanner := bufio.NewScanner(processStatusFile)
	for scanner.Scan() {
		infos := strings.SplitN(scanner.Text(), "\t", 2)
		if len(infos) < 2 {
			continue
		}
		if strings.TrimRight(infos[0], ":") == "NSpid" {
			pids := strings.Split(infos[1], "\t")
			if len(pids) <= 1 {
				break
			}
			nspidStr := pids[len(pids)-1]
			nspid, err := strconv.ParseInt(nspidStr, 10, 10)
			if err != nil {
				return "", nil, fmt.Errorf("could not parse the nspid: %s", nspidStr, err)
			}
			if f, info, err := p.tryingToGetAgentMetadataFileByPid(nspid, tmpDir); err == nil {
				return f, info, nil
			}
		}
	}

	return "", nil, fmt.Errorf("could not found")
}

func (p *ProcessFinder) tryingToGetAgentMetadataFileByPid(pid int64, tmpDir string) (string, os.FileInfo, error) {
	metadataFile := path.Join(tmpDir, "apache_skywalking", "process", strconv.FormatInt(pid, 10), "metadata.properties")
	f, err := os.Stat(metadataFile)
	if err != nil {
		return "", nil, err
	}
	return metadataFile, f, nil
}

func (p *ProcessFinder) buildProcessFromAgentMetadata(pro *process.Process, metaFilePath string) (*Process, error) {
	metadata, err := os.ReadFile(metaFilePath)
	if err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigType("properties")
	if err := v.ReadConfig(bytes.NewReader(metadata)); err != nil {
		return nil, err
	}

	// parse agent data
	agent := &AgentMetadata{}
	if err := v.Unmarshal(agent); err != nil {
		return nil, err
	}

	cmdline, err := pro.Cmdline()
	if err != nil {
		return nil, err
	}

	return NewProcessByAgent(pro, cmdline, agent)
}

func (p *ProcessFinder) validateTheProcessesCouldProfiling(processes []*Process) []*Process {
	result := make([]*Process, 0)
	for _, ps := range processes {
		if err := p.validateProcessCouldProfiling(ps); err != nil {
			log.Warnf("could not read process exe file path, pid: %d", ps.pid)
			continue
		}
		result = append(result, ps)
	}
	return result
}

func (p *ProcessFinder) validateProcessCouldProfiling(ps *Process) error {
	exe := p.tryToFindFileExecutePath(ps.original)
	if exe == "" {
		return fmt.Errorf("could not read process exe file path, pid: %d", ps.pid)
	}

	// check support profiling
	pf, err := tools.ExecutableFileProfilingStat(exe)
	if err != nil {
		return fmt.Errorf("the process could not be profiling, so ignored. pid: %d, reason: %v", ps.pid, err)
	}
	ps.profiling = pf
	return nil
}

func (p *ProcessFinder) agentFindMatchedProcesses() ([]*Process, error) {
	// all system processes
	processes, err := process.ProcessesWithContext(p.ctx)
	if err != nil {
		return nil, err
	}
	// find all matches processes
	findedProcesses := make([]*Process, 0)
	for _, pro := range processes {
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
		ps := NewProcessByRegex(pro, cmdline, finderConfig)
		ps.entity.Layer = finderConfig.Layer
		ps.entity.ServiceName, err = p.buildEntity(err, ps, finderConfig.serviceNameBuilder)
		ps.entity.InstanceName, err = p.buildEntity(err, ps, finderConfig.instanceNameBuilder)
		ps.entity.ProcessName, err = p.buildEntity(err, ps, finderConfig.processNameBuilder)
		ps.entity.Labels = finderConfig.ParsedLabels
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
				WithField("labels", reportProcess.entity.Labels).
				WithField("pid_list", pidList).
				Warnf("find multiple similar process in Scanner, " +
					"only report the first of these processes. " +
					"please update the name of process to identity them more clear.")
		}
		result = append(result, reportProcess)
	}
	return result, nil
}

func (p *ProcessFinder) regexFindMatchedProcesses() ([]*Process, error) {
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
		ps := NewProcessByRegex(pro, cmdline, finderConfig)
		ps.entity.Layer = finderConfig.Layer
		ps.entity.ServiceName, err = p.buildEntity(err, ps, finderConfig.serviceNameBuilder)
		ps.entity.InstanceName, err = p.buildEntity(err, ps, finderConfig.instanceNameBuilder)
		ps.entity.ProcessName, err = p.buildEntity(err, ps, finderConfig.processNameBuilder)
		ps.entity.Labels = finderConfig.ParsedLabels
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
				WithField("labels", reportProcess.entity.Labels).
				WithField("pid_list", pidList).
				Warnf("find multiple similar process in Scanner, " +
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

func (p *ProcessFinder) findMatchesFinder(ps *process.Process) (*RegexFinder, string, error) {
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
	var matched *RegexFinder
	for _, finder := range p.conf.RegexFinders {
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
	if conf.ScanMode == Agent {
		var err error
		conf.Agent.RecentDuration, err = durationMustNotNull(err, "recent", conf.Agent.Recent)
		return err
	} else if conf.ScanMode != Regex {
		return fmt.Errorf("could not found mode: %s", conf.ScanMode)
	}
	if len(conf.RegexFinders) == 0 {
		return fmt.Errorf("must have one Scanner process finder")
	}

	// validate config
	for _, f := range conf.RegexFinders {
		var err error
		err = stringMustNotNull(err, "layer", f.Layer)
		f.commandlineRegex, err = regexMustNotNull(err, "match_cmd_regex", f.MatchCommandRegex)
		f.serviceNameBuilder, err = templateMustNotNull(err, "service_name", f.ServiceName)
		f.instanceNameBuilder, err = templateMustNotNull(err, "instance_name", f.InstanceName)
		f.processNameBuilder, err = templateMustNotNull(err, "process_name", f.ProcessName)
		f.ParsedLabels = parseLabels(f.LabelsStr)

		if err != nil {
			return err
		}
	}

	return nil
}

func parseLabels(labelStr string) []string {
	tmp := strings.Split(labelStr, ",")
	result := make([]string, 0)
	for _, s := range tmp {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func stringMustNotNull(err error, confKey, confValue string) error {
	if err != nil {
		return err
	}
	if confValue == "" {
		return fmt.Errorf("the %s of Scanner process must be set", confKey)
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

func durationMustNotNull(err error, confKey, confValue string) (time.Duration, error) {
	if err1 := stringMustNotNull(err, confKey, confValue); err1 != nil {
		return 0, err1
	}
	return time.ParseDuration(confValue)
}

func (p *ProcessFinder) tryToFindFileExecutePath(ps *process.Process) string {
	exe, err := ps.Exe()
	if pathExists(exe, err) {
		return exe
	}
	cwd, err := ps.Cwd()
	if pathExists(cwd, err) && pathExists(cwd+"/"+exe, err) {
		return cwd + "/" + exe
	}
	linuxProcessRoot := host.GetFileInHost(fmt.Sprintf("/proc/%d/root", ps.Pid))
	if pathExists(linuxProcessRoot, nil) {
		if pathExists(linuxProcessRoot+"/"+exe, nil) {
			return linuxProcessRoot + "/" + exe
		} else if pathExists(linuxProcessRoot+"/"+cwd+"/"+exe, nil) {
			return linuxProcessRoot + "/" + cwd + "/" + exe
		}
	}
	return ""
}

func pathExists(exe string, err error) bool {
	if err != nil {
		return false
	}
	_, e := os.Stat(exe)
	return !os.IsNotExist(e)
}

type AgentMetadata struct {
	Layer        string `mapstructure:"layer"`
	ServiceName  string `mapstructure:"service_name"`
	InstanceName string `mapstructure:"instance_name"`
	ProcessName  string `mapstructure:"process_name"`
	Properties   string `mapstructure:"properties"`
	Labels       string `mapstructure:"labels"`
	Language     string `mapstructure:"language"`
}
