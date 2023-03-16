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

//go:build linux

package offcpu

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/cilium/ebpf/link"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/process"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// nolint
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf $REPO_ROOT/bpf/profiling/offcpu.c -- -I$REPO_ROOT/bpf/include

var log = logger.GetLogger("profiling", "task", "offcpu")
var defaultKernelSymbol = "finish_task_switch"

type ProcessStack struct {
	UserStackID   uint32
	KernelStackID uint32
}

type StackCounter struct {
	Times  uint64 // total execute count
	Deltas uint64 // total execute delta duration(nanoseconds)
}

type Runner struct {
	base             *base.Runner
	pid              int32
	processProfiling *profiling.Info
	kernelProfiling  *profiling.Info

	// runtime
	previousStacks  map[ProcessStack]StackCounter
	bpf             *bpfObjects
	kprobe          link.Link
	stopChan        chan bool
	flushDataNotify context.CancelFunc
}

func NewRunner(config *base.TaskConfig, moduleMgr *module.Manager) (base.ProfileTaskRunner, error) {
	return &Runner{
		base: base.NewBaseRunner(),
	}, nil
}

func (r *Runner) Init(task *base.ProfilingTask, processes []api.ProcessInterface) error {
	if len(processes) != 1 {
		return fmt.Errorf("the processes count must be 1, current is: %d", len(processes))
	}
	curProcess := processes[0]
	r.pid = curProcess.Pid()
	r.processProfiling = curProcess.ProfilingStat()
	kernelProfiling, err := process.KernelFileProfilingStat()
	if err != nil {
		log.Warnf("could not analyze kernel profiling stats: %v", err)
	}
	r.kernelProfiling = kernelProfiling
	r.previousStacks = make(map[ProcessStack]StackCounter)
	r.stopChan = make(chan bool, 1)
	return nil
}

func (r *Runner) Run(ctx context.Context, notify base.ProfilingRunningSuccessNotify) error {
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	// update the monitor pid
	funcName := "do_finish_task_switch"
	replacedPid := false
	for i, ins := range spec.Programs[funcName].Instructions {
		if ins.Reference() == "MONITOR_PID" {
			spec.Programs[funcName].Instructions[i].Constant = int64(r.pid)
			spec.Programs[funcName].Instructions[i].Offset = 0
			replacedPid = true
		}
	}
	if !replacedPid {
		return fmt.Errorf("replace the monitor pid failure")
	}
	if err1 := spec.LoadAndAssign(&objs, btf.GetEBPFCollectionOptionsIfNeed()); err1 != nil {
		return err1
	}
	r.bpf = &objs

	kprobe, err := link.Kprobe(r.findMatchesSymbol(), objs.DoFinishTaskSwitch, nil)
	if err != nil {
		return fmt.Errorf("link to finish task swtich failure: %v", err)
	}
	r.kprobe = kprobe

	notify()
	<-r.stopChan
	return nil
}

func (r *Runner) findMatchesSymbol() string {
	if r.kernelProfiling == nil {
		return defaultKernelSymbol
	}
	res, err := r.kernelProfiling.FindSymbolByRegex(`finish_task_switch(\.\w+\.\d+)?`)
	if err != nil {
		log.Warnf("found symbol error: %v", err)
		return defaultKernelSymbol
	}
	return res
}

func (r *Runner) Stop() error {
	var err error
	r.base.ShutdownOnce.Do(func() {
		// wait for all profiling data been consumed finished
		cancel, cancelFunc := context.WithCancel(context.Background())
		r.flushDataNotify = cancelFunc
		select {
		case <-cancel.Done():
		case <-time.After(10 * time.Second):
		}

		if r.bpf != nil {
			if err1 := r.bpf.Close(); err1 != nil {
				err = multierror.Append(err, err1)
			}
			r.bpf = nil
		}
		if r.kprobe != nil {
			if err1 := r.kprobe.Close(); err1 != nil {
				err = multierror.Append(err, err1)
			}
		}
		close(r.stopChan)
	})
	return err
}

func (r *Runner) FlushData() ([]*v3.EBPFProfilingData, error) {
	if r.bpf == nil {
		return nil, nil
	}
	var stack ProcessStack
	var counter StackCounter
	iterate := r.bpf.Counts.Iterate()
	stacks := r.bpf.Stacks
	result := make([]*v3.EBPFProfilingData, 0)
	stackSymbols := make([]uint64, 100)
	for iterate.Next(&stack, &counter) {
		metadatas := make([]*v3.EBPFProfilingStackMetadata, 0)
		// kernel stack
		if d := r.base.GenerateProfilingData(r.kernelProfiling, stack.KernelStackID, stacks,
			v3.EBPFProfilingStackType_PROCESS_KERNEL_SPACE, stackSymbols); d != nil {
			metadatas = append(metadatas, d)
		}
		// user stack
		if d := r.base.GenerateProfilingData(r.processProfiling, stack.UserStackID, stacks,
			v3.EBPFProfilingStackType_PROCESS_USER_SPACE, stackSymbols); d != nil {
			metadatas = append(metadatas, d)
		}

		if len(metadatas) == 0 {
			continue
		}

		// update the counters in memory
		switchCount := int32(counter.Times)
		duration := int64(counter.Deltas)
		existCounter := r.previousStacks[stack]
		if existCounter.Times > 0 && existCounter.Deltas > 0 {
			switchCount -= int32(existCounter.Times)
			duration -= int64(existCounter.Deltas)
		}
		r.previousStacks[stack] = counter
		if switchCount <= 0 {
			continue
		}

		result = append(result, &v3.EBPFProfilingData{
			Profiling: &v3.EBPFProfilingData_OffCPU{
				OffCPU: &v3.EBPFOffCPUProfiling{
					Stacks:      metadatas,
					SwitchCount: switchCount,
					Duration:    duration,
				},
			},
		})
	}

	if r.flushDataNotify != nil {
		r.flushDataNotify()
	}
	return result, nil
}
