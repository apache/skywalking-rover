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

package api

import (
	"encoding/json"
	"fmt"

	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

type ProcessDetectType int8

const (
	_ ProcessDetectType = iota
	Kubernetes
)

func (d ProcessDetectType) Name() string {
	if d == Kubernetes {
		return "Kubernetes"
	}
	return "not matched"
}

type ProcessInterface interface {
	// ID of process, it's provide by backend
	ID() string
	// Pid of process
	Pid() int32
	// DetectType of process, it decide how to find this process
	DetectType() ProcessDetectType
	// Entity of process in backend
	Entity() *ProcessEntity
	// ProfilingStat of process
	ProfilingStat() *profiling.Info
	// ExeName get execute file name
	ExeName() (string, error)
	// OriginalProcess from process library
	OriginalProcess() *process.Process
	// DetectProcess from finder
	DetectProcess() DetectedProcess

	// PortIsExpose check the port is exposed
	PortIsExpose(port int) bool
	// DetectNewExposePort add a new detected expose port
	DetectNewExposePort(port int)
	// ExposeHosts get all exposed hosts
	ExposeHosts() []string
}

// DetectedProcess from the finder
type DetectedProcess interface {
	// Pid of process in host
	Pid() int32
	// OriginalProcess is works for query the process data
	OriginalProcess() *process.Process
	// Entity of process, is related with backend entity
	Entity() *ProcessEntity
	// DetectType define the process find type
	DetectType() ProcessDetectType
	// ProfilingStat of process
	ProfilingStat() *profiling.Info
	// ExposePorts define which ports are exposed
	ExposePorts() []int
	// ExposeHosts define which hosts are exposed
	ExposeHosts() []string
}

// ProcessEntity is related to backend entity concept
type ProcessEntity struct {
	Layer        string
	ServiceName  string
	InstanceName string
	ProcessName  string
	Labels       []string
}

func (e *ProcessEntity) SameWith(other *ProcessEntity) bool {
	if e == nil || other == nil {
		return false
	}
	return e.Layer == other.Layer && e.ServiceName == other.ServiceName && e.InstanceName == other.InstanceName &&
		e.ProcessName == other.ProcessName
}

func (e *ProcessEntity) String() string {
	marshal, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("layer: %s, service: %s, instance: %s, process: %s, labels: %v",
			e.Labels, e.ServiceName, e.InstanceName, e.ProcessName, e.Labels)
	}
	return string(marshal)
}
