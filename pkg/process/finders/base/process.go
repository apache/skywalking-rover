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
	"github.com/shirou/gopsutil/process"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

// DetectedProcess from the finder
type DetectedProcess interface {
	// Pid of process in host
	Pid() int32
	// OriginalProcess is works for query the process data
	OriginalProcess() *process.Process
	// Entity of process, is related with backend entity
	Entity() *api.ProcessEntity
	// DetectType define the process find type
	DetectType() api.ProcessDetectType
	// ProfilingStat of process
	ProfilingStat() *profiling.Info
	// ExposePorts define which ports are exposed
	ExposePorts() []int
}
