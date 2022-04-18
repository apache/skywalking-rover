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

import "github.com/apache/skywalking-rover/pkg/tools/profiling"

type ProcessDetectType int8

const (
	_ ProcessDetectType = iota
	Scanner
	Kubernetes
)

func (d ProcessDetectType) Name() string {
	if d == Scanner {
		return "Scanner"
	} else if d == Kubernetes {
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
