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

package oncpu

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/tools/process"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"

	"golang.org/x/sys/unix"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// nolint
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf $REPO_ROOT/bpf/profiling/oncpu.c -- -I$REPO_ROOT/bpf/include

var log = logger.GetLogger("profiling", "task", "oncpu")

type Event struct {
	UserStackID   uint32
	KernelStackID uint32
}

// profilingObjects is the eBPF objects used by the frame pointer program
type profilingObjects struct {
	Counts      *ebpf.Map     `ebpf:"counts"`
	Stacks      *ebpf.Map     `ebpf:"stacks"`
	DoPerfEvent *ebpf.Program `ebpf:"do_perf_event"`
}

// loadedObjects is the loaded eBPF objects, the program is the frame pointer or the user stack copying program,
// the user stack events map only exists when the user stack copying program is loaded
type loadedObjects struct {
	profilingObjects
	UserStackEvents *ebpf.Map `ebpf:"user_stack_events"`
}

func (o *loadedObjects) Close() error {
	return _BpfClose(o.DoPerfEvent, o.Counts, o.Stacks, o.UserStackEvents)
}

type Runner struct {
	base             *base.Runner
	config           *base.TaskConfig
	pid              int32
	processProfiling *profiling.Info
	kernelProfiling  *profiling.Info
	dumpFrequency    int64

	// runtime
	perfEventFds []int
	bpf          *loadedObjects
	userStacks   *base.UserStackCollector
	// runtimeLock protects the runtime eBPF objects, user stack collector and the flush data notify,
	// which are shared between the Run, FlushData and Stop
	runtimeLock     sync.Mutex
	stackCounter    map[Event]uint32
	flushDataNotify context.CancelFunc
	stopChan        chan bool
}

func NewRunner(config *base.TaskConfig, _ *module.Manager) (base.ProfileTaskRunner, error) {
	if config.OnCPU.Period == "" {
		return nil, fmt.Errorf("please provide the ON_CPU dump period")
	}
	dumpPeriod, err := time.ParseDuration(config.OnCPU.Period)
	if err != nil {
		return nil, fmt.Errorf("the ON_CPU dump period format not right, current value: %s", config.OnCPU.Period)
	}
	if dumpPeriod < time.Millisecond {
		return nil, fmt.Errorf("the ON_CPU dump period could not be smaller than 1ms")
	}
	return &Runner{
		base:          base.NewBaseRunner(),
		config:        config,
		dumpFrequency: time.Second.Milliseconds() / dumpPeriod.Milliseconds(),
	}, nil
}

func (r *Runner) Init(_ *base.ProfilingTask, processes []api.ProcessInterface) error {
	if len(processes) != 1 {
		return fmt.Errorf("the processes count must be 1, current is: %d", len(processes))
	}
	curProcess := processes[0]
	r.pid = curProcess.Pid()
	// process profiling stat
	if r.processProfiling = curProcess.ProfilingStat(); r.processProfiling == nil {
		return fmt.Errorf("this process could not be profiling")
	}
	// kernel profiling stat
	kernelProfiling, err := process.KernelFileProfilingStat()
	if err != nil {
		log.Warnf("could not analyze kernel profiling stats: %v", err)
	}
	r.kernelProfiling = kernelProfiling
	r.stackCounter = make(map[Event]uint32)
	r.stopChan = make(chan bool, 1)
	return nil
}

func (r *Runner) Run(_ context.Context, notify base.ProfilingRunningSuccessNotify) (err error) {
	// load bpf
	objs := loadedObjects{}
	copyUserStack, reason := base.ShouldCopyUserStack(r.config, r.pid, r.processProfiling)
	log.Infof("the user stack of process %d would be unwound by %s, reason: %s", r.pid, base.UserStackUnwindWay(copyUserStack), reason)
	copyUserStack, err = base.LoadProfilingObjects(loadBpf, "do_perf_event", "do_perf_event_user_stack",
		copyUserStack, func(program *ebpf.ProgramSpec) error {
			return base.ReplaceMonitorPid(program, r.pid)
		}, &objs.profilingObjects, &objs)
	if err != nil {
		return fmt.Errorf("loading objects: %s", err)
	}
	defer objs.Close()
	var userStacks *base.UserStackCollector
	if copyUserStack {
		userStacks = base.StartUserStackCollector(r.processProfiling, objs.UserStackEvents)
	}
	defer func() {
		// the Stop is not called when running failure
		if err == nil {
			return
		}
		r.runtimeLock.Lock()
		r.bpf, r.userStacks = nil, nil
		r.runtimeLock.Unlock()
		if userStacks != nil {
			_ = userStacks.Close()
		}
	}()
	r.runtimeLock.Lock()
	r.userStacks = userStacks
	r.bpf = &objs
	r.runtimeLock.Unlock()

	// opened perf events
	perfEvents, err := r.openPerfEvent(objs.DoPerfEvent.FD())
	r.perfEventFds = perfEvents
	if err != nil {
		for _, fd := range perfEvents {
			_ = r.closePerfEvent(fd)
		}
		return err
	}
	log.Debugf("success running on cpu profiling, perf event fds: %v", perfEvents)

	// notify start success
	notify()
	runtime.SetFinalizer(r, (*Runner).Stop)
	<-r.stopChan
	return nil
}

func (r *Runner) openPerfEvent(perfFd int) ([]int, error) {
	eventAttr := &unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitFreq,
		Sample: uint64(r.dumpFrequency),
		Wakeup: 1,
	}

	fds := make([]int, 0)
	for cpuNum := 0; cpuNum < runtime.NumCPU(); cpuNum++ {
		fd, err := unix.PerfEventOpen(
			eventAttr,
			-1,
			cpuNum,
			-1,
			0,
		)
		if err != nil {
			return fds, err
		}

		// attach ebpf to perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, perfFd); err != nil {
			_ = unix.Close(fd)
			return fds, err
		}

		// enable perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			_ = unix.Close(fd)
			return fds, err
		}
		fds = append(fds, fd)
	}

	return fds, nil
}

func (r *Runner) Stop() error {
	var result error
	r.base.ShutdownOnce.Do(func() {
		for _, fd := range r.perfEventFds {
			if err := r.closePerfEvent(fd); err != nil {
				result = multierror.Append(result, err)
			}
		}

		// wait for all profiling data been consume finished
		cancel, cancelFunc := context.WithCancel(context.Background())
		r.runtimeLock.Lock()
		r.flushDataNotify = cancelFunc
		r.runtimeLock.Unlock()
		select {
		case <-cancel.Done():
		case <-time.After(5 * time.Second):
		}

		r.runtimeLock.Lock()
		if r.userStacks != nil {
			if err := r.userStacks.Close(); err != nil {
				result = multierror.Append(result, err)
			}
			r.userStacks = nil
		}
		if r.bpf != nil {
			if err := r.bpf.Close(); err != nil {
				result = multierror.Append(result, err)
			}
			r.bpf = nil
		}
		r.runtimeLock.Unlock()

		close(r.stopChan)
	})
	return result
}

func (r *Runner) FlushData() ([]*v3.EBPFProfilingData, error) {
	r.runtimeLock.Lock()
	defer r.runtimeLock.Unlock()
	if r.bpf == nil {
		return nil, nil
	}
	var stack Event
	var counter uint32
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
		dumpCount := int32(counter)
		existCounter := r.stackCounter[stack]
		if existCounter > 0 {
			dumpCount -= int32(existCounter)
		}
		r.stackCounter[stack] = counter
		if dumpCount <= 0 {
			log.Debugf("the dump count is 0 for stack: %v", stack)
			continue
		}

		result = append(result, &v3.EBPFProfilingData{
			Profiling: &v3.EBPFProfilingData_OnCPU{
				OnCPU: &v3.EBPFOnCPUProfiling{
					Stacks:    metadatas,
					DumpCount: dumpCount,
				},
			},
		})
		count++
	}
	log.Debugf("total found stacks: %d", count)
	result = append(result, r.flushUserStacks(stacks, stackSymbols)...)

	// close the flush data notify if exists
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
			Profiling: &v3.EBPFProfilingData_OnCPU{
				OnCPU: &v3.EBPFOnCPUProfiling{
					Stacks:    metadatas,
					DumpCount: int32(stack.Count),
				},
			},
		})
	}
	return result
}

func (r *Runner) closePerfEvent(fd int) error {
	if fd <= 0 {
		return nil
	}
	var result error
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
		result = multierror.Append(result, fmt.Errorf("closing perf event reader: %s", err))
	}
	// the perf event holds the reference of the eBPF program until the fd is closed
	if err := unix.Close(fd); err != nil {
		result = multierror.Append(result, fmt.Errorf("closing perf event fd: %s", err))
	}
	return result
}
