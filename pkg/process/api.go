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

package process

import "github.com/apache/skywalking-rover/pkg/process/api"

type Operator interface {
	// FindProcessById the processID is received from the backend, if not found then return nil
	FindProcessByID(processID string) api.ProcessInterface
	// FindProcessByPID get all processes with difference entity through process PID
	FindProcessByPID(pid int32) []api.ProcessInterface
	// FindAllRegisteredProcesses find all registered processes
	FindAllRegisteredProcesses() []api.ProcessInterface
	// AddListener add new process listener
	AddListener(listener api.ProcessListener)
	// DeleteListener delete the process listener
	DeleteListener(listener api.ProcessListener)
	// ShouldMonitor check the process should be monitored
	ShouldMonitor(pid int32) bool
	// ShouldMonitorExecuting check a process the kernel has just started should be monitored,
	// using what the kernel captured about it so the answer does not depend on /proc/<pid> still
	// existing - a short-lived process may already be gone by the time it is asked.
	ShouldMonitorExecuting(exec *api.ProcessExecuteContext) bool
	// ExecutingProcessesWanted reports whether any active finder can act on a process reported the
	// moment it starts, and therefore whether reporting them is worth its cost at all.
	//
	// It is false when every active finder only ever monitors long-lived processes: the VM finder,
	// for instance, takes a process only if it holds a listening port, which a process that lives
	// for milliseconds never does. Reporting to such a finder buys nothing and costs a /proc read
	// per process, so the caller must not ask the kernel for the reports in the first place.
	ExecutingProcessesWanted() bool
}

// CgroupOperator is an optional interface the process module satisfies when it can resolve the
// cgroup of a container, which lets a caller filter processes in kernel space by cgroup id.
//
// It is optional because it needs a cgroup v2 tree the agent can read; a caller must handle a
// missing implementation, or a CgroupResolvable of false, by filtering some other way rather than
// by monitoring nothing.
type CgroupOperator interface {
	// CgroupResolvable reports whether cgroup ids can be resolved on this host at all
	CgroupResolvable() bool
	// CgroupIDByContainer returns the cgroup id of a container, false when it is not(yet) known
	CgroupIDByContainer(containerID string) (uint64, bool)
}

type K8sOperator interface {
	// NodeName get the node name
	NodeName() string
	// IsPodIP check the ip is pod ip
	IsPodIP(ip string) (bool, error)
}
