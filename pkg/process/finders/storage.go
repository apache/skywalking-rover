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
	processes map[int32]*ProcessContext
	mutex     sync.Mutex

	// working with backend
	reportInterval time.Duration
	roverID        string
	processClient  v3.EBPFProcessServiceClient
	finders        map[api.ProcessDetectType]base.ProcessFinder

	// report context
	ctx    context.Context
	cancel context.CancelFunc
}

func NewProcessStorage(ctx context.Context, moduleManager *module.Manager,
	reportInterval time.Duration, finderList []base.ProcessFinder) (*ProcessStorage, error) {
	data := make(map[int32]*ProcessContext)
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
		processes:      data,
		reportInterval: reportInterval,
		roverID:        roverID,
		processClient:  processClient,
		finders:        fs,
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

func (s *ProcessStorage) StartReport() {
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
	for _, p := range s.processes {
		if p.syncStatus == NotReport {
			waitReportProcesses = append(waitReportProcesses, p)
		} else if p.syncStatus == ReportSuccess {
			keepAliveProcesses = append(keepAliveProcesses, p)
		}
	}

	// process with backend
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
		if ps.id != "" {
			processIDList = append(processIDList, &v3.EBPFProcessPingPkg{EntityMetadata: &v3.EBPFProcessEntityMetadata{
				Layer:        ps.Entity().Layer,
				ServiceName:  ps.Entity().ServiceName,
				InstanceName: ps.Entity().InstanceName,
				ProcessName:  ps.Entity().ProcessName,
			}})
		}
	}

	_, err := s.processClient.KeepAlive(s.ctx, &v3.EBPFProcessPingPkgList{Processes: processIDList})
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

	for _, waitProcess := range waitReportProcesses {
		found := false
		for _, reportedProcess := range processes.GetProcesses() {
			id := s.finders[waitProcess.DetectType()].ParseProcessID(waitProcess.detectProcess, reportedProcess)
			if id == "" {
				continue
			}

			s.updateProcessToUploadSuccess(waitProcess, id)
			found = true
			break
		}

		if !found {
			s.updateProcessToUploadIgnored(waitProcess)
		}
	}
	return nil
}

func (s *ProcessStorage) SyncAllProcessInFinder(finder api.ProcessDetectType, processes []base.DetectedProcess) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	pidToProcess := make(map[int32]base.DetectedProcess)
	for _, ps := range processes {
		pidToProcess[ps.Pid()] = ps
	}

	// for each all process in the manager
	for pid, managedProcess := range s.processes {
		needToSyncProcess := pidToProcess[pid]
		// remove it from the list of need to sync
		pidToProcess[pid] = nil

		// The process to be synchronized is not found in all process list
		// And this process is same with finder type
		// So we need to remove this process
		if needToSyncProcess == nil {
			if managedProcess.DetectType() == finder {
				s.processes[pid] = nil
			}
			continue
		}

		// they are the not same detect type
		// TODO we just implement the VM mode process for now, so continue
		if needToSyncProcess.DetectType() != managedProcess.DetectType() {
			continue
		}

		// check the entity is the same
		if s.finders[needToSyncProcess.DetectType()].ValidateProcessIsSame(needToSyncProcess, managedProcess.detectProcess) {
			continue
		}

		// different entity, so we need to remove oldest and add the new process
		s.processes[pid] = s.constructNewProcessContext(finder, needToSyncProcess)
	}

	// other processes are need to be added
	for pid, ps := range pidToProcess {
		if ps != nil {
			s.processes[pid] = s.constructNewProcessContext(finder, ps)
		}
	}
}

func (s *ProcessStorage) constructNewProcessContext(finder api.ProcessDetectType, process base.DetectedProcess) *ProcessContext {
	return &ProcessContext{
		syncStatus:    NotReport,
		detectProcess: process,
		detectType:    finder,
	}
}

func (s *ProcessStorage) updateProcessToUploadSuccess(pc *ProcessContext, id string) {
	pc.id = id
	pc.syncStatus = ReportSuccess
}

func (s *ProcessStorage) updateProcessToUploadIgnored(pc *ProcessContext) {
	pc.syncStatus = Ignore
}
