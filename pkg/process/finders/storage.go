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
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-multierror"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools"
)

type ProcessStorage struct {
	processes map[api.ProcessDetectType][]*ProcessContext
	mutex     sync.Mutex

	// process listeners
	listeners               []api.ProcessListener
	eventQueue              chan *processEvent
	initListenQueue         chan api.ProcessListener
	listenerRecheckInterval time.Duration

	// working with backend
	reportInterval         time.Duration
	propertiesReportFactor int
	roverID                string
	processClient          v3.EBPFProcessServiceClient
	finders                map[api.ProcessDetectType]base.ProcessFinder
	reportedCount          int64

	// report context
	ctx    context.Context
	cancel context.CancelFunc
}

func NewProcessStorage(ctx context.Context, moduleManager *module.Manager, reportInterval time.Duration,
	propertiesReportFactor int, finderList []base.ProcessFinder, listenerRecheckInterval time.Duration) (*ProcessStorage, error) {
	data := make(map[api.ProcessDetectType][]*ProcessContext)
	// working with core module
	coreOperator := moduleManager.FindModule(core.ModuleName).(core.Operator)
	roverID := coreOperator.InstanceID()
	backendConn := coreOperator.BackendOperator().GetConnection()
	processClient := v3.NewEBPFProcessServiceClient(backendConn)
	ctx, cancel := context.WithCancel(ctx)
	fs := make(map[api.ProcessDetectType]base.ProcessFinder)
	for _, f := range finderList {
		fs[f.DetectType()] = f
	}
	return &ProcessStorage{
		processes:               data,
		reportInterval:          reportInterval,
		propertiesReportFactor:  propertiesReportFactor,
		eventQueue:              make(chan *processEvent, 100),
		initListenQueue:         make(chan api.ProcessListener, 100),
		listenerRecheckInterval: listenerRecheckInterval,
		reportedCount:           0,
		roverID:                 roverID,
		processClient:           processClient,
		finders:                 fs,
		ctx:                     ctx,
		cancel:                  cancel,
	}, nil
}

func (s *ProcessStorage) StartReport() {
	// for report all processes
	go func() {
		timeTicker := time.NewTicker(s.reportInterval)
		for {
			select {
			case <-timeTicker.C:
				if err := s.reportAllProcesses(); err != nil {
					log.Errorf("report all processes error: %v", err)
				}
			case <-s.ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()

	// for start listener
	go func() {
		timeTicker := time.NewTicker(s.listenerRecheckInterval)
		for {
			select {
			case <-timeTicker.C:
				s.notifyToRecheckAllProcesses(s.listeners)
			case e := <-s.eventQueue:
				s.consumeProcessEvent(s.listeners, e)
			case l := <-s.initListenQueue:
				s.notifyToRecheckAllProcesses([]api.ProcessListener{l})
			case <-s.ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()
}

func (s *ProcessStorage) StopReport() error {
	s.cancel()
	return nil
}

func (s *ProcessStorage) reportAllProcesses() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if len(s.processes) == 0 {
		return nil
	}

	// build process list(wait report or keep alive)
	waitReportProcesses := make([]*ProcessContext, 0)
	keepAliveProcesses := make([]*ProcessContext, 0)
	for _, finderProcesses := range s.processes {
		for _, p := range finderProcesses {
			if p.syncStatus == NotReport {
				waitReportProcesses = append(waitReportProcesses, p)
			} else if p.syncStatus == ReportSuccess {
				keepAliveProcesses = append(keepAliveProcesses, p)
			}
		}
	}

	// if rover should report the properties, then need to force remove all keep alive processes to report
	shouldReportProperties := atomic.AddInt64(&s.reportedCount, 1)%int64(s.propertiesReportFactor) == 0
	if shouldReportProperties {
		log.Infof("detection has reached the properties report factor, forced to report all processes properties")
		waitReportProcesses = append(waitReportProcesses, keepAliveProcesses...)
		keepAliveProcesses = make([]*ProcessContext, 0)
	}
	var result error
	if err := s.processesReport(waitReportProcesses); err != nil {
		result = multierror.Append(result, err)
	}
	if err := s.processesKeepAlive(keepAliveProcesses); err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

func (s *ProcessStorage) processesKeepAlive(waitKeepAliveProcess []*ProcessContext) error {
	if len(waitKeepAliveProcess) == 0 {
		return nil
	}

	processIDList := make([]*v3.EBPFProcessPingPkg, 0)
	for _, ps := range waitKeepAliveProcess {
		if ps.id == "" {
			log.Warnf("the process id is not found before keep alive, need to report, pid: %d, process name: %s",
				ps.Pid(), ps.Entity().ProcessName)
			ps.syncStatus = NotReport
			continue
		}
		processIDList = append(processIDList, &v3.EBPFProcessPingPkg{
			EntityMetadata: &v3.EBPFProcessEntityMetadata{
				Layer:        ps.Entity().Layer,
				ServiceName:  ps.Entity().ServiceName,
				InstanceName: ps.Entity().InstanceName,
				ProcessName:  ps.Entity().ProcessName,
				Labels:       ps.Entity().Labels,
			},
			Properties: s.finders[ps.detectType].BuildNecessaryProperties(ps.detectProcess),
		})
	}

	_, err := s.processClient.KeepAlive(s.ctx, &v3.EBPFProcessPingPkgList{
		EbpfAgentID: s.roverID,
		Processes:   processIDList,
	})
	return err
}

func (s *ProcessStorage) processesReport(waitReportProcesses []*ProcessContext) error {
	if len(waitReportProcesses) == 0 {
		return nil
	}

	properties := make([]*v3.EBPFProcessProperties, 0)
	buildContext := &base.BuildEBPFProcessContext{}
	buildContext.HostIP = tools.DefaultHostIPAddress()
	for _, ps := range waitReportProcesses {
		properties = append(properties, s.finders[ps.DetectType()].BuildEBPFProcess(buildContext, ps.detectProcess))
	}
	processes, err := s.processClient.ReportProcesses(s.ctx, &v3.EBPFProcessReportList{Processes: properties, EbpfAgentID: s.roverID})
	if err != nil {
		return err
	}

	eventBuilder := s.newProcessEventBuilder(ProcessOperateAdd)
	for _, waitProcess := range waitReportProcesses {
		found := false
		for _, reportedProcess := range processes.GetProcesses() {
			id := s.finders[waitProcess.DetectType()].ParseProcessID(waitProcess.detectProcess, reportedProcess)
			if id == "" {
				continue
			}

			s.updateProcessToUploadSuccess(waitProcess, id)
			found = true
			eventBuilder.AddProcess(waitProcess.Pid(), waitProcess)
			break
		}

		if !found {
			s.updateProcessToUploadIgnored(waitProcess)
		}
	}

	eventBuilder.Send()
	return nil
}

func (s *ProcessStorage) SyncAllProcessInFinder(finder api.ProcessDetectType, processes []base.DetectedProcess) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	newProcesses := make([]*ProcessContext, 0)

	existingProcesses := s.processes[finder]
	existingProcessHasFounded := make(map[*ProcessContext]bool)
	for _, p := range existingProcesses {
		existingProcessHasFounded[p] = false
	}

	for _, syncProcess := range processes {
		founded := false
		for _, existingProcess := range existingProcesses {
			if syncProcess.Pid() == existingProcess.Pid() && syncProcess.Entity().SameWith(existingProcess.Entity()) {
				newProcesses = append(newProcesses, existingProcess)
				existingProcessHasFounded[existingProcess] = true
				founded = true
				break
			}
		}

		// if not found in existing processes, need to add this process
		if !founded {
			newProcesses = append(newProcesses, s.constructNewProcessContext(finder, syncProcess))
			log.Infof("detected new process: pid: %d, entity: %s", syncProcess.Pid(), syncProcess.Entity())
		}
	}

	// log the dead processes
	eventBuilder := s.newProcessEventBuilder(ProcessOperateDelete)
	for p, found := range existingProcessHasFounded {
		if found {
			continue
		}
		log.Infof("the process has been recognized as dead, so deleted. pid: %d, entity: %s, id: %s", p.Pid(), p.Entity(), p.id)
		eventBuilder.AddProcess(p.Pid(), p)
	}

	s.processes[finder] = newProcesses
	eventBuilder.Send()
}

func (s *ProcessStorage) constructNewProcessContext(finder api.ProcessDetectType, process base.DetectedProcess) *ProcessContext {
	exporsedPorts := make(map[int]bool)
	for _, p := range process.ExposePorts() {
		exporsedPorts[p] = true
	}
	return &ProcessContext{
		syncStatus:    NotReport,
		detectProcess: process,
		detectType:    finder,
		exposedPorts:  exporsedPorts,
	}
}

func (s *ProcessStorage) updateProcessToUploadSuccess(pc *ProcessContext, id string) {
	reported := pc.id == id
	pc.id = id
	pc.syncStatus = ReportSuccess
	if !reported {
		log.Infof("uploaded process pid: %d, name: %s, id: %s", pc.detectProcess.Pid(), pc.detectProcess.Entity().ProcessName, id)
	}
}

func (s *ProcessStorage) updateProcessToUploadIgnored(pc *ProcessContext) {
	pc.syncStatus = Ignore
	log.Infof("could not found the process id from upstream, pid: %d, entity: %v", pc.Pid(), pc.Entity())
}

func (s *ProcessStorage) FindProcessByID(processID string) api.ProcessInterface {
	for _, finderProcesses := range s.processes {
		for _, p := range finderProcesses {
			if p.id == processID {
				return p
			}
		}
	}
	return nil
}

func (s *ProcessStorage) FindProcessByPID(pid int32) []api.ProcessInterface {
	result := make([]api.ProcessInterface, 0)
	for _, finderProcesses := range s.processes {
		for _, p := range finderProcesses {
			if p.Pid() == pid {
				result = append(result, p)
			}
		}
	}
	return result
}

func (s *ProcessStorage) AddListener(listener api.ProcessListener) {
	s.listeners = append(s.listeners, listener)
	s.initListenQueue <- listener
}

func (s *ProcessStorage) DeleteListener(listener api.ProcessListener) {
	result := make([]api.ProcessListener, 0)
	for _, l := range s.listeners {
		if l != listener {
			result = append(result, l)
		}
	}
	s.listeners = result
}

type ProcessOperate int

const (
	ProcessOperateAdd    = 1
	ProcessOperateDelete = 2
)

type processEventBuilder struct {
	processes map[int32][]api.ProcessInterface
	operate   ProcessOperate
	storage   *ProcessStorage
}

func (s *ProcessStorage) newProcessEventBuilder(operate ProcessOperate) *processEventBuilder {
	return &processEventBuilder{
		processes: make(map[int32][]api.ProcessInterface),
		operate:   operate,
		storage:   s,
	}
}

func (p *processEventBuilder) AddProcess(pid int32, pi api.ProcessInterface) {
	ps := p.processes[pid]
	ps = append(ps, pi)
	p.processes[pid] = ps
}

func (p *processEventBuilder) Send() {
	for pid, processes := range p.processes {
		p.storage.eventQueue <- &processEvent{
			pid:       pid,
			processes: processes,
			operate:   p.operate,
		}
	}
}

type processEvent struct {
	pid       int32
	processes []api.ProcessInterface
	operate   ProcessOperate
}

func (s *ProcessStorage) consumeProcessEvent(listeners []api.ProcessListener, e *processEvent) {
	for _, l := range listeners {
		if e.operate == ProcessOperateAdd {
			l.AddNewProcess(e.pid, e.processes)
		} else {
			l.RemoveProcess(e.pid, e.processes)
		}
	}
}

func (s *ProcessStorage) notifyToRecheckAllProcesses(listeners []api.ProcessListener) {
	if len(listeners) == 0 {
		return
	}
	// build all processes
	events := s.newProcessEventBuilder(ProcessOperateAdd)
	for _, pcs := range s.processes {
		for _, pc := range pcs {
			events.AddProcess(pc.Pid(), pc)
		}
	}
	for _, l := range listeners {
		l.RecheckAllProcesses(events.processes)
	}
}
