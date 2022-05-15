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
	"fmt"
	"reflect"
	"sort"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/path"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"

	"github.com/shirou/gopsutil/process"
)

// BuildProfilingStat use to build the profiling info for profiling
func BuildProfilingStat(ps *process.Process) (*profiling.Info, error) {
	exePath := tryToFindFileExecutePath(ps)
	if exePath == "" {
		return nil, fmt.Errorf("could not found executable file")
	}

	// check support profiling
	return tools.ProcessProfilingStat(ps.Pid, exePath)
}

func tryToFindFileExecutePath(ps *process.Process) string {
	exe, err := ps.Exe()
	if err != nil {
		return ""
	}
	if path.Exists(exe) {
		return exe
	}
	pathInNs := host.GetFileInHost(fmt.Sprintf("/proc/%d/root%s", ps.Pid, exe))
	if path.Exists(pathInNs) {
		return pathInNs
	}
	return ""
}

func EntityIsSameWithProtocol(processEntity *api.ProcessEntity, protocolEntity *v3.EBPFProcessEntityMetadata) bool {
	if processEntity == nil || protocolEntity == nil {
		return false
	}

	if !reflect.DeepEqual(sortLabelArray(processEntity.Labels), sortLabelArray(protocolEntity.Labels)) {
		return false
	}
	return processEntity.Layer == protocolEntity.Layer &&
		processEntity.ServiceName == protocolEntity.ServiceName &&
		processEntity.InstanceName == protocolEntity.InstanceName &&
		processEntity.ProcessName == protocolEntity.ProcessName
}

func sortLabelArray(a []string) []string {
	if a == nil {
		return make([]string, 0)
	}
	sort.SliceStable(a, func(i, j int) bool {
		return a[i] > a[j]
	})
	return a
}
