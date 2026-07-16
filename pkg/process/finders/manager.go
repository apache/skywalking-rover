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
	"fmt"
	"time"

	"github.com/apache/skywalking-rover/pkg/logger"

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
)

var log = logger.GetLogger("process", "finder")

// when there have process listener been registered, how often to confrim(recheck) the processes
var processListenerRecheckInterval = time.Minute

// ProcessManager means Manage all Process
type ProcessManager struct {
	moduleManager *module.Manager
	// finders
	finders map[base.FinderBaseConfig]base.ProcessFinder
	// process storage
	storage *ProcessStorage
}

type ProcessManagerWithFinder struct {
	*ProcessManager
	finderType api.ProcessDetectType
}

func NewProcessManager(ctx context.Context, moduleManager *module.Manager,
	reportInterval time.Duration, propertiesReportFactor int, configs ...base.FinderBaseConfig) (*ProcessManager, error) {
	// locate all finders
	confinedFinders := make(map[base.FinderBaseConfig]base.ProcessFinder)
	fsList := make([]base.ProcessFinder, 0)
	for _, conf := range configs {
		if conf == nil || !conf.ActiveFinder() {
			continue
		}
		finder := getFinder(conf)
		confinedFinders[conf] = finder
		fsList = append(fsList, finder)
	}
	if len(confinedFinders) == 0 {
		return nil, fmt.Errorf("no process finder found")
	}

	// start new storage
	storage, err := NewProcessStorage(ctx, moduleManager, reportInterval, propertiesReportFactor, fsList, processListenerRecheckInterval)
	if err != nil {
		return nil, err
	}

	// init all finders
	manager := &ProcessManager{
		finders:       confinedFinders,
		moduleManager: moduleManager,
		storage:       storage,
	}
	for conf, finder := range confinedFinders {
		processManager := &ProcessManagerWithFinder{ProcessManager: manager, finderType: finder.DetectType()}
		if err := finder.Init(ctx, conf, processManager); err != nil {
			return nil, fmt.Errorf("starting %s finder failure: %v", finder.DetectType().Name(), err)
		}
	}

	return manager, nil
}

func (m *ProcessManager) Start() {
	// start all finders
	for _, finder := range m.finders {
		finder.Start()
	}
	// start storage report with interval
	m.storage.StartReport()
}

func (m *ProcessManager) Shutdown() error {
	var result error
	// stop reporter
	if err := m.storage.StopReport(); err != nil {
		result = multierror.Append(result, err)
	}
	// stop finders
	for _, finder := range m.finders {
		if err := finder.Stop(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result
}

func (m *ProcessManager) Finder(finderType api.ProcessDetectType) (base.ProcessFinder, bool) {
	for _, finder := range m.finders {
		if finder.DetectType() == finderType {
			return finder, true
		}
	}
	return nil, false
}

func (p *ProcessManagerWithFinder) GetModuleManager() *module.Manager {
	return p.moduleManager
}

func (p *ProcessManagerWithFinder) SyncAllProcessInFinder(processes []api.DetectedProcess) {
	p.storage.SyncAllProcessInFinder(p.finderType, processes)
}

func (p *ProcessManagerWithFinder) AddDetectedProcess(processes []api.DetectedProcess) {
	p.storage.AddNewProcessInFinder(p.finderType, processes)
}

func (m *ProcessManager) GetAllProcesses() []api.ProcessInterface {
	return m.storage.GetAllProcesses()
}

func (m *ProcessManager) FindProcessByID(processID string) api.ProcessInterface {
	return m.storage.FindProcessByID(processID)
}

func (m *ProcessManager) FindProcessByPID(pid int32) []api.ProcessInterface {
	return m.storage.FindProcessByPID(pid)
}

func (m *ProcessManager) FindAllRegisteredProcesses() []api.ProcessInterface {
	return m.storage.FindAllRegisteredProcesses()
}

func (m *ProcessManager) AddListener(listener api.ProcessListener) {
	m.storage.AddListener(listener)
}

func (m *ProcessManager) DeleteListener(listener api.ProcessListener) {
	m.storage.DeleteListener(listener)
}

func (m *ProcessManager) ShouldMonitor(pid int32) bool {
	monitor := false
	for _, finder := range m.finders {
		if finder.ShouldMonitor(pid) {
			monitor = true
		}
	}
	return monitor
}

// cgroupResolvingFinder is what a finder must offer for cgroup ids to be resolvable; only the
// Kubernetes finder knows about containers, so only it implements this.
type cgroupResolvingFinder interface {
	CgroupResolvable() bool
	CgroupIDByContainer(containerID string) (uint64, bool)
}

// CgroupResolvable reports whether any finder can resolve cgroup ids on this host.
func (m *ProcessManager) CgroupResolvable() bool {
	for _, finder := range m.finders {
		if resolver, ok := finder.(cgroupResolvingFinder); ok && resolver.CgroupResolvable() {
			return true
		}
	}
	return false
}

// CgroupIDByContainer returns the cgroup id of a container as resolved by whichever finder knows it.
func (m *ProcessManager) CgroupIDByContainer(containerID string) (uint64, bool) {
	for _, finder := range m.finders {
		if resolver, ok := finder.(cgroupResolvingFinder); ok {
			if id, exist := resolver.CgroupIDByContainer(containerID); exist {
				return id, true
			}
		}
	}
	return 0, false
}

// ExecutingProcessesWanted reports whether any *active* finder implements ExecutingProcessFinder,
// which is what makes reporting a process the instant it starts worth its cost.
//
// Implementing that interface is the finder's way of saying it can act on a process that may
// already be gone; a finder without it can only fall back to the /proc based check, which for a
// short-lived process answers "no" after having paid for the lookup. m.finders holds only the
// active finders, so an inactive one cannot keep the reports switched on.
func (m *ProcessManager) ExecutingProcessesWanted() bool {
	for _, finder := range m.finders {
		if _, ok := finder.(base.ExecutingProcessFinder); ok {
			return true
		}
	}
	return false
}

// ShouldMonitorExecuting judges a process the kernel has just started. Finders that can use the
// kernel-side context take it; the rest fall back to the /proc based check, which is all they could
// have done anyway.
func (m *ProcessManager) ShouldMonitorExecuting(exec *api.ProcessExecuteContext) bool {
	monitor := false
	for _, finder := range m.finders {
		if executing, ok := finder.(base.ExecutingProcessFinder); ok {
			if executing.ShouldMonitorExecuting(exec) {
				monitor = true
			}
			continue
		}
		if finder.ShouldMonitor(exec.Pid) {
			monitor = true
		}
	}
	return monitor
}
