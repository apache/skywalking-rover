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
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"

	"golang.org/x/sys/unix"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// nolint
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf $REPO_ROOT/bpf/profiling/oncpu.c -- -I$REPO_ROOT/bpf/include

var log = logger.GetLogger("profiling", "task", "oncpu")

type Event struct {
	UserStackID   uint32
	KernelStackID uint32
}

type Runner struct {
	base             *base.Runner
	pid              int32
	processProfiling *profiling.Info
	kernelProfiling  *profiling.Info
	dumpFrequency    int64

	// runtime
	perfEventFds    []int
	bpf             *bpfObjects
	stackCounter    map[Event]uint32
	flushDataNotify context.CancelFunc
	stopChan        chan bool
}

func NewRunner(config *base.TaskConfig) (base.ProfileTaskRunner, error) {
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
		dumpFrequency: time.Second.Milliseconds() / dumpPeriod.Milliseconds(),
	}, nil
}

func (r *Runner) Init(task *base.ProfilingTask, process api.ProcessInterface) error {
	r.pid = process.Pid()
	// process profiling stat
	if r.processProfiling = process.ProfilingStat(); r.processProfiling == nil {
		return fmt.Errorf("this process could not be profiling")
	}
	// kernel profiling stat
	kernelProfiling, err := tools.KernelFileProfilingStat()
	if err != nil {
		log.Warnf("could not analyze kernel profiling stats: %v", err)
	}
	r.kernelProfiling = kernelProfiling
	r.stackCounter = make(map[Event]uint32)
	r.stopChan = make(chan bool, 1)
	return nil
}

func (r *Runner) Run(ctx context.Context, notify base.ProfilingRunningSuccessNotify) error {
	// load bpf
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	// update the monitor pid
	funcName := "do_perf_event"
	replacedPid := false
	for i, ins := range spec.Programs[funcName].Instructions {
		if ins.Reference == "MONITOR_PID" {
			spec.Programs[funcName].Instructions[i].Constant = int64(r.pid)
			spec.Programs[funcName].Instructions[i].Offset = 0
			replacedPid = true
		}
	}
	if !replacedPid {
		return fmt.Errorf("replace the monitor pid failure")
	}
	if err1 := spec.LoadAndAssign(&objs, nil); err1 != nil {
		log.Fatalf("loading objects: %s", err1)
	}
	defer objs.Close()
	r.bpf = &objs

	// opened perf events
	perfEvents, err := r.openPerfEvent(objs.DoPerfEvent.FD())
	r.perfEventFds = perfEvents
	if err != nil {
		return err
	}

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
			return fds, err
		}

		// enable perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
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
		r.flushDataNotify = cancelFunc
		select {
		case <-cancel.Done():
		case <-time.After(5 * time.Second):
		}

		if r.bpf != nil {
			if err := r.bpf.Close(); err != nil {
				result = multierror.Append(result, err)
			}
		}

		close(r.stopChan)
	})
	return result
}

func (r *Runner) FlushData() ([]*v3.EBPFProfilingData, error) {
	var stack Event
	var counter uint32
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
		dumpCount := int32(counter)
		existCounter := r.stackCounter[stack]
		if existCounter > 0 {
			dumpCount -= int32(existCounter)
		}
		r.stackCounter[stack] = counter
		if dumpCount <= 0 {
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
	}

	// close the flush data notify if exists
	if r.flushDataNotify != nil {
		r.flushDataNotify()
	}

	return result, nil
}

func (r *Runner) closePerfEvent(fd int) error {
	if fd <= 0 {
		return nil
	}
	var result error
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
		result = multierror.Append(result, fmt.Errorf("closing perf event reader: %s", err))
	}
	return result
}
