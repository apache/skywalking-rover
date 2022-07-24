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
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

type ProcessUploadStatus int8

const (
	_ ProcessUploadStatus = iota
	// NotReport is detected the process, but not report to the backend
	NotReport
	// ReportSuccess mean backend has informed, so it could have id
	ReportSuccess
	// Ignore by the backend
	Ignore
)

type ProcessContext struct {
	// process ID from backed
	id string

	// sync with backend status
	syncStatus ProcessUploadStatus

	// detectProcess from finder
	detectProcess base.DetectedProcess
	detectType    api.ProcessDetectType

	// cache
	exeName      string
	exposedPorts map[int]bool
}

func (p *ProcessContext) ID() string {
	return p.id
}

func (p *ProcessContext) Pid() int32 {
	return p.detectProcess.Pid()
}

func (p *ProcessContext) DetectType() api.ProcessDetectType {
	return p.detectType
}

func (p *ProcessContext) Entity() *api.ProcessEntity {
	return p.detectProcess.Entity()
}

func (p *ProcessContext) ProfilingStat() *profiling.Info {
	return p.detectProcess.ProfilingStat()
}

func (p *ProcessContext) ExeName() (string, error) {
	if p.exeName == "" {
		exe, err := p.detectProcess.OriginalProcess().Name()
		if err != nil {
			return "", err
		}
		p.exeName = exe
	}
	return p.exeName, nil
}

func (p *ProcessContext) PortIsExpose(port int) bool {
	return p.exposedPorts[port]
}

func (p *ProcessContext) DetectNewExposePort(port int) {
	p.exposedPorts[port] = true
}
