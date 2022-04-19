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
	"os"

	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"

	"github.com/shirou/gopsutil/process"
)

// BuildProfilingStat use to build the profiling info for profiling
func BuildProfilingStat(ps *process.Process) (*profiling.Info, error) {
	path := tryToFindFileExecutePath(ps)
	if path == "" {
		return nil, fmt.Errorf("could not found executable file")
	}

	// check support profiling
	return tools.ExecutableFileProfilingStat(path)
}

func tryToFindFileExecutePath(ps *process.Process) string {
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
