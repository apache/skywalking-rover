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

package network

import (
	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/tools/btf"

	"github.com/hashicorp/go-multierror"
)

type monitoringProcessInfo struct {
	pid    int32
	linker *btf.Linker
	source map[string]bool
}

func newMonitoringProcessInfo(pid int32) *monitoringProcessInfo {
	return &monitoringProcessInfo{
		pid:    pid,
		linker: btf.NewLinker(),
		source: make(map[string]bool),
	}
}

func (m *monitoringProcessInfo) AddSource(from string) error {
	// if already have source, then just added
	if len(m.source) != 0 {
		m.source[from] = true
	}

	// start the TLS first
	if err := addSSLProcess(int(m.pid), m.linker, bpf); err != nil {
		return err
	}

	// add to the process control
	if e := bpf.ProcessMonitorControl.Update(uint32(m.pid), uint32(1), ebpf.UpdateAny); e != nil {
		return e
	}
	m.source[from] = true
	return nil
}

func (m *monitoringProcessInfo) RemoveSource(from string) (bool, error) {
	delete(m.source, from)

	// if still have source monitoring, then just ignore to shut down process monitoring
	if len(m.source) > 0 {
		return false, nil
	}

	var err error
	if e := m.linker.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	if e := bpf.ProcessMonitorControl.Delete(uint32(m.pid)); e != nil {
		err = multierror.Append(err, e)
	}

	return true, err
}

func (m *monitoringProcessInfo) Shutdown() error {
	return m.linker.Close()
}
