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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf $REPO_ROOT/bpf/profiling/oncpu.c -- -I$REPO_ROOT/bpf/include

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
	dumpPeriod       time.Duration

	// runtime
	perfEventFds    []int
	countReader     *perf.Reader
	stackCounter    map[Event]int
	stackMap        *ebpf.Map
	flushDataNotify context.CancelFunc
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
		base:         base.NewBaseRunner(),
		dumpPeriod:   dumpPeriod,
		stackCounter: make(map[Event]int),
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
	r.stackCounter = make(map[Event]int)
	return nil
}

func (r *Runner) Run(ctx context.Context, notify base.ProfilingRunningSuccessNotify) error {
	// load bpf
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()
	r.stackMap = objs.Stacks

	// init profiling data reader
	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf event reader: %s", err)
	}
	r.countReader = rd

	// opened perf events
	perfEvents, err := r.openPerfEvent(objs.DoPerfEvent.FD())
	r.perfEventFds = perfEvents
	if err != nil {
		return err
	}

	// notify start success
	notify()
	runtime.SetFinalizer(r, (*Runner).Stop)

	// read content
	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			log.Warnf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Warnf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// parse perf event data
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Errorf("parsing perf event error: %s", err)
			continue
		}

		r.stackCounter[event]++
	}
}

func (r *Runner) openPerfEvent(perfFd int) ([]int, error) {
	eventAttr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      uint64(r.dumpPeriod.Nanoseconds()),
		Wakeup:      1,
	}

	fds := make([]int, 0)
	for cpuNum := 0; cpuNum < runtime.NumCPU(); cpuNum++ {
		fd, err := unix.PerfEventOpen(
			eventAttr,
			int(r.pid),
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

		if r.countReader != nil {
			if err := r.countReader.Close(); err != nil {
				result = multierror.Append(result, err)
			}
		}
	})
	return result
}

func (r *Runner) FlushData() ([]*v3.EBPFProfilingData, error) {
	existsCounters := r.flushStackCounter()

	result := make([]*v3.EBPFProfilingData, 0)
	stackSymbols := make([]uint64, 100)
	for event, count := range existsCounters {
		metadatas := make([]*v3.EBPFProfilingStackMetadata, 0)
		// kernel stack
		if d := r.base.GenerateProfilingData(r.kernelProfiling, event.KernelStackID, r.stackMap,
			v3.EBPFProfilingStackType_PROCESS_KERNEL_SPACE, stackSymbols); d != nil {
			metadatas = append(metadatas, d)
		}

		// user stack
		if d := r.base.GenerateProfilingData(r.processProfiling, event.UserStackID, r.stackMap,
			v3.EBPFProfilingStackType_PROCESS_USER_SPACE, stackSymbols); d != nil {
			metadatas = append(metadatas, d)
		}

		// close the flush data notify if exists
		if r.flushDataNotify != nil {
			r.flushDataNotify()
		}

		if len(metadatas) == 0 {
			continue
		}

		result = append(result, &v3.EBPFProfilingData{
			Profiling: &v3.EBPFProfilingData_OnCPU{
				OnCPU: &v3.EBPFOnCPUProfiling{
					Stacks:    metadatas,
					DumpCount: int32(count),
				},
			},
		})
	}

	return result, nil
}

func (r *Runner) flushStackCounter() map[Event]int {
	updateTo := make(map[Event]int)
	updateToP := &updateTo

	older := &r.stackCounter
	*older, *updateToP = *updateToP, *older
	return updateTo
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
