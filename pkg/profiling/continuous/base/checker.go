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
	"github.com/apache/skywalking-rover/pkg/process/api"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type CheckType string

const (
	CheckTypeProcessCPU          CheckType = "PROCESS_CPU"
	CheckTypeProcessThreadCount  CheckType = "PROCESS_THREAD_COUNT"
	CheckTypeSystemLoad          CheckType = "SYSTEM_LOAD"
	CheckTypeHTTPErrorRate       CheckType = "HTTP_ERROR_RATE"
	CheckTypeHTTPAvgResponseTime CheckType = "HTTP_AVG_RESPONSE_TIME"
)

type Checker interface {
	// Init the checker with basic configs
	Init(config *ContinuousConfig) error
	// SyncPolicies from all service policies and processes
	SyncPolicies(policies []*SyncPolicyWithProcesses)
	// Fetch the policies data and save to the time windows
	Fetch() error
	// Check the policies are reached
	// Each policy with process should use CheckContext.ShouldCheck to validate the policy should be checked or not
	Check(ctx CheckContext, metricsAppender *MetricsAppender) []ThresholdCause
	// Close the checker
	Close() error
}

type CheckContext interface {
	// ShouldCheck validate the process with policy item should be checked or ignore
	// Usually if the process already start profiling with specific process, the check should be ignored
	ShouldCheck(p api.ProcessInterface, item *PolicyItem) bool
}

type SyncPolicyWithProcesses struct {
	Policy    *Policy
	Processes map[string]api.ProcessInterface
}

type ThresholdCause interface {
	// Process is over threshold
	Process() api.ProcessInterface
	// FromPolicy current from which policy
	FromPolicy() *PolicyItem
	// GenerateTransferCause transmit to the backend
	GenerateTransferCause() *v3.ContinuousProfilingCause
}
