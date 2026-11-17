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
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/cilium/ebpf"
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

// profilingObjects is the eBPF objects used by the frame pointer program
type profilingObjects struct {
	Counts             *ebpf.Map     `ebpf:"counts"`
	Stacks             *ebpf.Map     `ebpf:"stacks"`
	Starts             *ebpf.Map     `ebpf:"starts"`
	DoFinishTaskSwitch *ebpf.Program `ebpf:"do_finish_task_switch"`
}

// loadedObjects is the loaded eBPF objects, the program is the frame pointer or the user stack copying program,
// the user stack events map only exists when the user stack copying program is loaded
type loadedObjects struct {
	profilingObjects
	UserStackEvents *ebpf.Map `ebpf:"user_stack_events"`
}

func (o *loadedObjects) Close() error {
	return _BpfClose(o.DoFinishTaskSwitch, o.Counts, o.Stacks, o.Starts, o.UserStackEvents)
}

type Runner struct {
	base             *base.Runner
	config           *base.TaskConfig
	pid              int32
	processProfiling *profiling.Info
	kernelProfiling  *profiling.Info

	// runtime
	previousStacks map[ProcessStack]StackCounter
	bpf            *loadedObjects
	userStacks     *base.UserStackCollector
	// runtimeLock protects the runtime eBPF objects, user stack collector and the flush data notify,
	// which are shared between the Run, FlushData and Stop
	runtimeLock     sync.Mutex
	kprobe          *btf.Linker
	stopChan        chan bool
	flushDataNotify context.CancelFunc
}

func NewRunner(config *base.TaskConfig, _ *module.Manager) (base.ProfileTaskRunner, error) {
	return &Runner{
		base:   base.NewBaseRunner(),
		config: config,
	}, nil
}

func (r *Runner) Init(_ *base.ProfilingTask, processes []api.ProcessInterface) error {
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

func (r *Runner) Run(_ context.Context, notify base.ProfilingRunningSuccessNotify) (err error) {
	objs := loadedObjects{}
	copyUserStack, reason := base.ShouldCopyUserStack(r.config, r.pid, r.processProfiling)
	log.Infof("the user stack of process %d would be unwound by %s, reason: %s", r.pid, base.UserStackUnwindWay(copyUserStack), reason)
	copyUserStack, err = base.LoadProfilingObjects(loadBpf, "do_finish_task_switch", "do_finish_task_switch_user_stack",
		copyUserStack, func(program *ebpf.ProgramSpec) error {
			return base.ReplaceMonitorPid(program, r.pid)
		}, &objs.profilingObjects, &objs)
	if err != nil {
		return err
	}
	var userStacks *base.UserStackCollector
	if copyUserStack {
		userStacks = base.StartUserStackCollector(r.processProfiling, objs.UserStackEvents)
	}
	linker := btf.NewLinker()
	defer func() {
		// the Stop is not called when running failure
		if err != nil {
			r.runtimeLock.Lock()
			r.bpf, r.userStacks = nil, nil
			r.runtimeLock.Unlock()
			_ = linker.Close()
			if userStacks != nil {
				_ = userStacks.Close()
			}
			_ = objs.Close()
		}
	}()
	r.runtimeLock.Lock()
	r.userStacks = userStacks
	r.bpf = &objs
	r.runtimeLock.Unlock()

	symbols := r.findMatchesSymbol()
	linkedCount := 0
	for _, symbol := range symbols {
		switchers := make(map[string]*ebpf.Program)
		switchers[symbol] = objs.DoFinishTaskSwitch
		err = linker.AddLinkOrError(link.Kprobe, switchers)
		if err != nil {
			log.Warnf("link to finish task swtich(%s) failure: %v", symbol, err)
			continue
		}
		linkedCount++
	}

	if linkedCount == 0 {
		return fmt.Errorf("link to finish task swtich failure: no symbol linked")
	}

	if err := linker.HasError(); err != nil {
		return fmt.Errorf("link to finish task swtich failure: %v", err)
	}
	r.kprobe = linker

	notify()
	<-r.stopChan
	return nil
}

func (r *Runner) findMatchesSymbol() []string {
	if r.kernelProfiling == nil {
		return []string{defaultKernelSymbol}
	}
	res, err := r.kernelProfiling.FindMultipleSymbolByRegex(`^finish_task_switch$|^finish_task_switch\.isra\.\d$`)
	if err != nil {
		log.Warnf("found symbol error: %v", err)
		return []string{defaultKernelSymbol}
	}
	log.Debugf("total found %d off cpu symbols: %v", len(res), res)
	return res
}

func (r *Runner) Stop() error {
	var err error
	r.base.ShutdownOnce.Do(func() {
		// wait for all profiling data been consumed finished
		cancel, cancelFunc := context.WithCancel(context.Background())
		r.runtimeLock.Lock()
		r.flushDataNotify = cancelFunc
		r.runtimeLock.Unlock()
		select {
		case <-cancel.Done():
		case <-time.After(10 * time.Second):
		}

		r.runtimeLock.Lock()
		if r.userStacks != nil {
			if err1 := r.userStacks.Close(); err1 != nil {
				err = multierror.Append(err, err1)
			}
			r.userStacks = nil
		}
		if r.bpf != nil {
			if err1 := r.bpf.Close(); err1 != nil {
				err = multierror.Append(err, err1)
			}
			r.bpf = nil
		}
		r.runtimeLock.Unlock()
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
	r.runtimeLock.Lock()
	defer r.runtimeLock.Unlock()
	if r.bpf == nil {
		return nil, nil
	}
	var stack ProcessStack
	var counter StackCounter
	iterate := r.bpf.Counts.Iterate()
	stacks := r.bpf.Stacks
	result := make([]*v3.EBPFProfilingData, 0)
	stackSymbols := make([]uint64, 100)
	count := 0
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
			log.Debugf("the dump count is 0 for stack: %v", stack)
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
	log.Debugf("total found stacks: %d", count)
	result = append(result, r.flushUserStacks(stacks, stackSymbols)...)

	if r.flushDataNotify != nil {
		r.flushDataNotify()
	}
	return result, nil
}

func (r *Runner) flushUserStacks(stacks *ebpf.Map, stackSymbols []uint64) []*v3.EBPFProfilingData {
	if r.userStacks == nil {
		return nil
	}
	result := make([]*v3.EBPFProfilingData, 0)
	for _, stack := range r.userStacks.Flush() {
		metadatas := r.base.GenerateUserStackData(r.processProfiling, r.kernelProfiling, stack, stacks, stackSymbols)
		if len(metadatas) == 0 {
			continue
		}
		result = append(result, &v3.EBPFProfilingData{
			Profiling: &v3.EBPFProfilingData_OffCPU{
				OffCPU: &v3.EBPFOffCPUProfiling{
					Stacks:      metadatas,
					SwitchCount: int32(stack.Count),
					Duration:    int64(stack.Deltas),
				},
			},
		})
	}
	return result
}
