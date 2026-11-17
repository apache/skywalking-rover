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
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
	"github.com/apache/skywalking-rover/pkg/tools/profiling/unwind"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

const (
	// UserStackUnwindAuto decides the unwinding way by the process automatically:
	// using the frame pointer when all the native modules keep the frame pointer, otherwise using the dwarf
	UserStackUnwindAuto = "auto"
	// UserStackUnwindFramePointer only unwinds the user stack by the frame pointer in the kernel
	UserStackUnwindFramePointer = "frame_pointer"
	// UserStackUnwindDWARF copies the user stack to the user space and unwinds it by the call frame information
	UserStackUnwindDWARF = "dwarf"

	userStackMaxDepth = 127
	// userStackPerCPUBuffer is the perf buffer size of each CPU, when the buffer is full,
	// the eBPF program falls back to the frame pointer stack, so the samples would not be lost
	userStackPerCPUBuffer = 256 * 1024
	// userStackWatermark is the written bytes in the per CPU buffer to wake up the reader, reduce the wakeup times
	userStackWatermark = userStackPerCPUBuffer / 4
	// userStackFlushTimeout is the max time to wait for the pending events to be read when flushing
	userStackFlushTimeout = time.Second
	// userStackEventHeaderSize is the size of the fields before the stack data in "struct user_stack_event"
	userStackEventHeaderSize = 60
)

var (
	frameTableCacheOnce sync.Once
	frameTableCache     *unwind.TableCache
)

func getFrameTableCache() *unwind.TableCache {
	frameTableCacheOnce.Do(func() {
		frameTableCache = unwind.NewTableCache(unwind.CurrentArch())
	})
	return frameTableCache
}

// UserStackCount is the aggregated count of the same user and kernel stack
type UserStackCount struct {
	// Frames is the unwound user stack, empty means the unwinding only got the top frame,
	// then should use the frame pointer stack(UserStackID) which captured in the same event
	Frames        []uint64
	UserStackID   uint32
	KernelStackID uint32
	Count         uint64
	Deltas        uint64
}

// UserStackCollector receives the raw user stacks from the eBPF program and unwinds them by the call frame information
type UserStackCollector struct {
	unwinder *unwind.Unwinder
	info     *profiling.Info
	reader   *perf.Reader
	flushed  chan struct{}

	// the buffers reused in the reader goroutine
	frames []uint64
	key    []byte

	lock   sync.Mutex
	stacks map[string]*UserStackCount
}

// ShouldCopyUserStack checks the process should copy the user stack for unwinding by the call frame information,
// returns the decision and the reason
func ShouldCopyUserStack(config *TaskConfig, pid int32, info *profiling.Info) (copyStack bool, reason string) {
	mode := UserStackUnwindAuto
	if config != nil && config.UserStackUnwind != "" {
		mode = config.UserStackUnwind
	}
	if mode == UserStackUnwindFramePointer {
		return false, "configured as frame_pointer"
	}
	if info == nil {
		return false, "no profiling info of the process"
	}
	if unwind.CurrentArch() == nil {
		return false, "the architecture is not supported"
	}
	exe, err := elf.Open(host.GetHostProcInHost(fmt.Sprintf("%d/exe", pid)))
	if err != nil {
		return false, fmt.Sprintf("could not read the executable file: %v", err)
	}
	defer exe.Close()
	// the golang binary always keeps the frame pointer, and it has no .eh_frame section for the golang code
	if exe.Section(".go.buildinfo") != nil || exe.Section(".gopclntab") != nil {
		return false, "golang process always keeps the frame pointer"
	}
	if exe.Class != elf.ELFCLASS64 {
		return false, "only support the 64-bit process"
	}
	if mode == UserStackUnwindDWARF {
		return true, "configured as dwarf"
	}
	if module := findModuleWithoutFramePointer(info); module != "" {
		return true, fmt.Sprintf("the module %s is built without the frame pointer", module)
	}
	return false, "no module needs the call frame information unwinding"
}

// findModuleWithoutFramePointer returns the first module which built without the frame pointer,
// the module without call frame information is ignored, because the dwarf unwinding couldn't help it
func findModuleWithoutFramePointer(info *profiling.Info) string {
	cache := getFrameTableCache()
	for _, module := range info.Modules {
		if module.Type != profiling.ModuleTypeExec && module.Type != profiling.ModuleTypeSo {
			continue
		}
		if cache.NeedsUnwinding(module.Path) {
			return module.Name
		}
	}
	return ""
}

// UserStackUnwindWay returns the description of the user stack unwinding way
func UserStackUnwindWay(copyUserStack bool) string {
	if copyUserStack {
		return "the call frame information(dwarf)"
	}
	return "the frame pointer"
}

// ReplaceMonitorPid updates the MONITOR_PID constant in the eBPF program
func ReplaceMonitorPid(program *ebpf.ProgramSpec, pid int32) error {
	replaced := false
	for i, ins := range program.Instructions {
		if ins.Reference() == "MONITOR_PID" {
			program.Instructions[i].Constant = int64(pid)
			program.Instructions[i].Offset = 0
			replaced = true
		}
	}
	if !replaced {
		return fmt.Errorf("replace the monitor pid failure")
	}
	return nil
}

// LoadProfilingObjects loads the eBPF objects of the profiling, the program is assigned by the frame pointer program name.
// When copyUserStack is true, it loads the user stack program into the userStackObjs first,
// and falls back to the frame pointer program(into the fpObjs) when loading failure(such as the kernel is too old or no BTF),
// returns the user stack program is loaded or not.
// The fpObjs should only contain the objects used by the frame pointer program, so the user stack maps are not created.
func LoadProfilingObjects(loadSpec func() (*ebpf.CollectionSpec, error), fpProgram, userStackProgram string,
	copyUserStack bool, prepare func(*ebpf.ProgramSpec) error, fpObjs, userStackObjs interface{}) (bool, error) {
	if copyUserStack {
		err := loadProfilingObjects(loadSpec, fpProgram, userStackProgram, prepare, userStackObjs)
		if err == nil {
			return true, nil
		}
		log.Warnf("could not load the user stack copying program, fallback to the frame pointer unwinding: %v", err)
	}
	return false, loadProfilingObjects(loadSpec, fpProgram, fpProgram, prepare, fpObjs)
}

func loadProfilingObjects(loadSpec func() (*ebpf.CollectionSpec, error), fpProgram, useProgram string,
	prepare func(*ebpf.ProgramSpec) error, objs interface{}) error {
	spec, err := loadSpec()
	if err != nil {
		return err
	}
	program := spec.Programs[useProgram]
	if program == nil {
		return fmt.Errorf("could not found the program: %s", useProgram)
	}
	if err := prepare(program); err != nil {
		return err
	}
	for name := range spec.Programs {
		delete(spec.Programs, name)
	}
	spec.Programs[fpProgram] = program
	return spec.LoadAndAssign(objs, btf.GetEBPFCollectionOptionsIfNeed(spec))
}

// NewUserStackCollector creates the collector of the process
func NewUserStackCollector(info *profiling.Info) *UserStackCollector {
	tables := &processFrameTables{global: getFrameTableCache(), local: make(map[string]*unwind.FrameTable)}
	return &UserStackCollector{
		unwinder: unwind.NewUnwinder(unwind.CurrentArch(), tables, userStackMaxDepth),
		info:     info,
		flushed:  make(chan struct{}, 1),
		stacks:   make(map[string]*UserStackCount),
	}
}

// StartUserStackCollector creates and starts the collector, returns nil when starting failure,
// then the eBPF program falls back to the frame pointer stack because there is no reader of the events
func StartUserStackCollector(info *profiling.Info, events *ebpf.Map) *UserStackCollector {
	collector := NewUserStackCollector(info)
	if err := collector.Start(events); err != nil {
		log.Warnf("could not start the user stack collector, fallback to the frame pointer unwinding: %v", err)
		return nil
	}
	return collector
}

// Start reading the user stack events from the perf event array
func (c *UserStackCollector) Start(events *ebpf.Map) error {
	reader, err := perf.NewReaderWithOptions(events, userStackPerCPUBuffer, perf.ReaderOptions{Watermark: userStackWatermark})
	if err != nil {
		return fmt.Errorf("open the user stack reader failure: %v", err)
	}
	c.reader = reader
	go func() {
		var record perf.Record
		for {
			err := reader.ReadInto(&record)
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				if errors.Is(err, perf.ErrFlushed) {
					select {
					case c.flushed <- struct{}{}:
					default:
					}
					continue
				}
				log.Warnf("read the user stack event failure: %v", err)
				continue
			}
			if record.LostSamples > 0 {
				log.Debugf("lost %d user stack events", record.LostSamples)
				continue
			}
			c.safeHandleEvent(record.RawSample)
		}
	}()
	return nil
}

// safeHandleEvent protects rover from the unexpected data of the profiled process, only drop the event when panic
func (c *UserStackCollector) safeHandleEvent(data []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Warnf("unwinding the user stack failure: %v", err)
		}
	}()
	c.handleEvent(data)
}

func (c *UserStackCollector) handleEvent(data []byte) {
	if len(data) < userStackEventHeaderSize {
		return
	}
	order := binary.LittleEndian
	kernelStackID := order.Uint32(data[0:4])
	userStackID := order.Uint32(data[4:8])
	deltas := order.Uint64(data[8:16])
	regs := unwind.Registers{
		PC: order.Uint64(data[16:24]),
		SP: order.Uint64(data[24:32]),
		FP: order.Uint64(data[32:40]),
		LR: order.Uint64(data[40:48]),
	}
	// the copied stack could start below the stack pointer, such as the red zone in x86_64
	stackBase := order.Uint64(data[48:56])
	stackSize := int(order.Uint32(data[56:60]))
	if stackSize > len(data)-userStackEventHeaderSize {
		stackSize = len(data) - userStackEventHeaderSize
	}
	stack := &unwind.StackMemory{Base: stackBase, Data: data[userStackEventHeaderSize : userStackEventHeaderSize+stackSize]}
	c.frames = c.unwinder.UnwindInto(regs, stack, c.info, c.frames)
	if len(c.frames) <= 1 {
		// could not unwind any caller, the frame pointer stack is better(or the same)
		c.frames = c.frames[:0]
	}
	c.key = buildUserStackKey(c.key[:0], c.frames, userStackID, kernelStackID)

	c.lock.Lock()
	defer c.lock.Unlock()
	// the map lookup by the converted bytes would not allocate the string
	count := c.stacks[string(c.key)]
	if count == nil {
		count = &UserStackCount{KernelStackID: kernelStackID}
		if len(c.frames) > 0 {
			count.Frames = append([]uint64(nil), c.frames...)
		} else {
			count.UserStackID = userStackID
		}
		c.stacks[string(c.key)] = count
	}
	count.Count++
	count.Deltas += deltas
}

func buildUserStackKey(buf []byte, frames []uint64, userStackID, kernelStackID uint32) []byte {
	buf = binary.LittleEndian.AppendUint32(buf, kernelStackID)
	if len(frames) == 0 {
		return binary.LittleEndian.AppendUint32(buf, userStackID)
	}
	for _, f := range frames {
		buf = binary.LittleEndian.AppendUint64(buf, f)
	}
	return buf
}

// Flush returns the aggregated stacks since the last flush,
// the pending events in the perf buffer(less than the watermark) would be read before returning
func (c *UserStackCollector) Flush() []*UserStackCount {
	if c.reader != nil {
		// drop the signal of the previous timeout flush
		select {
		case <-c.flushed:
		default:
		}
		if err := c.reader.Flush(); err == nil {
			select {
			case <-c.flushed:
			case <-time.After(userStackFlushTimeout):
			}
		}
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if len(c.stacks) == 0 {
		return nil
	}
	result := make([]*UserStackCount, 0, len(c.stacks))
	for _, s := range c.stacks {
		result = append(result, s)
	}
	c.stacks = make(map[string]*UserStackCount)
	return result
}

// Close the event reader
func (c *UserStackCollector) Close() error {
	if c.reader == nil {
		return nil
	}
	return c.reader.Close()
}

// processFrameTables caches the frame tables of the process without validating the file again,
// it's only used in the reader goroutine of the collector
type processFrameTables struct {
	global *unwind.TableCache
	local  map[string]*unwind.FrameTable
}

func (p *processFrameTables) Get(path string) *unwind.FrameTable {
	if table, exist := p.local[path]; exist {
		return table
	}
	table := p.global.Get(path)
	p.local[path] = table
	return table
}

// GenerateUserStackData generates the kernel and user stack metadata of the unwound stack
func (r *Runner) GenerateUserStackData(processProfiling, kernelProfiling *profiling.Info, stack *UserStackCount,
	stackMap *ebpf.Map, symbolArray []uint64) []*v3.EBPFProfilingStackMetadata {
	metadatas := make([]*v3.EBPFProfilingStackMetadata, 0, 2)
	if d := r.GenerateProfilingData(kernelProfiling, stack.KernelStackID, stackMap,
		v3.EBPFProfilingStackType_PROCESS_KERNEL_SPACE, symbolArray); d != nil {
		metadatas = append(metadatas, d)
	}
	if len(stack.Frames) == 0 {
		if d := r.GenerateProfilingData(processProfiling, stack.UserStackID, stackMap,
			v3.EBPFProfilingStackType_PROCESS_USER_SPACE, symbolArray); d != nil {
			metadatas = append(metadatas, d)
		}
		return metadatas
	}
	if processProfiling == nil {
		return metadatas
	}
	symbols := processProfiling.FindSymbols(stack.Frames, MissingSymbol)
	if len(symbols) == 0 {
		return metadatas
	}
	return append(metadatas, &v3.EBPFProfilingStackMetadata{
		StackType:    v3.EBPFProfilingStackType_PROCESS_USER_SPACE,
		StackId:      userStackHashID(stack.Frames),
		StackSymbols: symbols,
	})
}

func userStackHashID(frames []uint64) int32 {
	hash := fnv.New32a()
	buf := make([]byte, 8)
	for _, f := range frames {
		binary.LittleEndian.PutUint64(buf, f)
		_, _ = hash.Write(buf)
	}
	return int32(hash.Sum32() & math.MaxInt32)
}
