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
	"context"

	"github.com/apache/skywalking-rover/pkg/process/api"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

const MissingSymbol = "[MISSING]"

type ProfilingRunningSuccessNotify func()

// ProfileTaskRunner is use to running different type of profiling task, such as on-cpu profiling task
type ProfileTaskRunner interface {
	// Init runner with profiling task and process
	Init(task *ProfilingTask, process api.ProcessInterface) error
	// Run profiling, if throw error or method finish means the profiling task finished
	Run(ctx context.Context, notify ProfilingRunningSuccessNotify) error
	// Stop the runner initiative, is typically used to specify the profiling duration
	Stop() error
	// FlushData means dump the exists profiling data and flush them to the backend protocol format
	FlushData() ([]*v3.EBPFProfilingData, error)
}
