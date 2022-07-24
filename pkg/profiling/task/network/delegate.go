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
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

// the realRunner only existing when have profiling task
// if no process need profiling then set to null
var realRunner = NewGlobalRunnerContext()

type DelegateRunner struct {
	base *base.Runner

	processes []api.ProcessInterface

	ctx    context.Context
	cancel context.CancelFunc
}

func NewRunner(config *base.TaskConfig, moduleMgr *module.Manager) (base.ProfileTaskRunner, error) {
	if err := realRunner.init(config, moduleMgr); err != nil {
		return nil, err
	}
	return &DelegateRunner{
		base: base.NewBaseRunner(),
	}, nil
}

func (r *DelegateRunner) Init(task *base.ProfilingTask, processes []api.ProcessInterface) error {
	if len(processes) == 0 {
		return fmt.Errorf("please provide one process at least")
	}
	r.processes = processes
	return nil
}

func (r *DelegateRunner) Run(ctx context.Context, notify base.ProfilingRunningSuccessNotify) error {
	r.ctx, r.cancel = context.WithCancel(ctx)
	if err := realRunner.Start(ctx, r.processes); err != nil {
		return err
	}
	notify()
	<-r.ctx.Done()
	return nil
}

func (r *DelegateRunner) Stop() error {
	var result error
	r.base.ShutdownOnce.Do(func() {
		// remove processes
		noProcessAreRunning, err := realRunner.DeleteProcesses(r.processes)
		if err != nil {
			result = multierror.Append(result, err)
		}
		// if no process are running, then stop and clean the runner
		if noProcessAreRunning {
			if err := realRunner.Stop(); err != nil {
				result = multierror.Append(result, err)
			}
			// recreate the runner
			realRunner = NewGlobalRunnerContext()
		}
		r.cancel()
	})
	return result
}

func (r *DelegateRunner) FlushData() ([]*v3.EBPFProfilingData, error) {
	// ignore the profiling data, use the meter protocol to upload
	return nil, nil
}
