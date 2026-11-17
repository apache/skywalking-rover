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

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

var log = logger.GetLogger("accesslog", "bpf")

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile. $BPF_ACCESSLOG_CFLAGS (empty unless set) comes in front of the
// include directories of the object: an agent that overlays the product hooks of the access log
// (protocol_analyzer_ext.h, connection_filter_rule.h) passes -I<its include directory> there, searched before
// bpf/accesslog/include and bpf/include, instead of copying its headers into this tree.
// nolint
// (two lines for the line length: the flags in the bpf2go command, the compiler and the sources in its call)
//go:generate -command bpf2go go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET -cflags "$BPF_CFLAGS $BPF_ACCESSLOG_CFLAGS"
//go:generate bpf2go -cc $BPF_CLANG bpf $REPO_ROOT/bpf/accesslog/accesslog.c -- -I$REPO_ROOT/bpf/accesslog/include -I$REPO_ROOT/bpf/include

type Loader struct {
	*btf.Linker
	*bpfObjects
	// what each hook attaches (attach.go)
	plan *attachPlan
	// how the NAT address of a connect is read (nat.go)
	nat *natPlan
	// the L2 to L4 details of the socket calls (l24.go)
	l24 *l24Plan
}

// LoaderOptions selects how the access log programs attach
type LoaderOptions struct {
	// AttachMode: auto (the default, also when empty), trampoline or tracepoint, see attach.go
	AttachMode string
	// NATHook: auto (the default, also when empty), confirm, kprobe or legacy, see nat.go
	NATHook string
	// KernelMetricsL2L3 loads the programs of the L2 to L4 details of the socket calls, see l24.go
	KernelMetricsL2L3 bool
}

func NewLoader() (*Loader, error) {
	return NewLoaderWithOptions(LoaderOptions{})
}

// NewLoaderWithAttach is NewLoader with the attach mode given (auto, trampoline, tracepoint; auto when empty)
func NewLoaderWithAttach(mode string) (*Loader, error) {
	return NewLoaderWithOptions(LoaderOptions{AttachMode: mode})
}

// NewLoaderWithOptions loads the access log programs with the attach of the options
func NewLoaderWithOptions(opts LoaderOptions) (*Loader, error) {
	spec, err := loadSpecWithOptions(opts)
	if err != nil {
		return nil, err
	}
	nat := planNATHook(opts.NATHook, spec)
	plan := planAttach(opts.AttachMode, spec, nat.unusedHooks())
	l24 := newL24Plan(opts.KernelMetricsL2L3)
	objs := bpfObjects{}
	err = loadObjects(spec, opts, plan, nat, l24, &objs)
	if err != nil && (plan.anyFast() || nat.fexit) {
		// (the error of the trampoline attach is kept: err is the one of the tracepoint attach from here on)
		fastErr := err
		log.Warnf("the access log programs do not load with the trampoline attach, loading them with the tracepoints: %v", fastErr)
		if spec, err = loadSpecWithOptions(opts); err != nil {
			return nil, err
		}
		plan = tracepointPlan(fmt.Sprintf("the trampoline programs did not load: %v", fastErr))
		plan.unused = nat.unusedHooks()
		nat = &natPlan{mode: nat.mode, reason: "the trampoline programs did not load"}
		objs = bpfObjects{}
		err = loadObjects(spec, opts, plan, nat, l24, &objs)
	}
	if err != nil {
		return nil, err
	}
	log.Infof("access log BPF attach: %s", plan)
	log.Infof("access log NAT address: %s", nat)
	if l24.enabled {
		log.Infof("access log L2 to L4 kernel metrics: on (%d programs refused by the kernel)", len(l24.stubbed))
	}

	return &Loader{
		bpfObjects: &objs,
		Linker:     btf.NewLinker(),
		plan:       plan,
		nat:        nat,
		l24:        l24,
	}, nil
}

// loadObjects loads the spec with the plans into objs. An l24 program the kernel refuses (l24.go) is loaded as a stub
// and the object loaded again, from a new spec: the plans change the spec they are applied to.
func loadObjects(spec *ebpf.CollectionSpec, opts LoaderOptions, plan *attachPlan, nat *natPlan, l24 *l24Plan,
	objs *bpfObjects) error {
	for {
		err := btf.LoadBPFAndAssign(func() (*ebpf.CollectionSpec, error) {
			applyAttachPlan(spec, plan)
			applyNATPlan(spec, nat)
			l24.apply(spec)
			return spec, nil
		}, objs)
		name := l24.refused(spec, err)
		if name == "" {
			return err
		}
		log.Warnf("the kernel refuses the L2 to L4 kernel metrics program %s, its metrics stay 0: %v", name, err)
		l24.stubbed[name] = err
		*objs = bpfObjects{}
		if spec, err = loadSpecWithOptions(opts); err != nil {
			return err
		}
	}
}

func (l *Loader) Close() error {
	var err error
	if e := l.bpfObjects.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	if e := l.Linker.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	return err
}

// loadSpecWithOptions is loadBpf with the atomic exchange of the upload chain turned on where the kernel has it, and
// the load-time constant of the L2 to L4 details (l24.go) of the options
func loadSpecWithOptions(opts LoaderOptions) (*ebpf.CollectionSpec, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	if err := setL24Constant(spec, opts.KernelMetricsL2L3); err != nil {
		return nil, err
	}
	// the upload chain by atomic exchange where the kernel has the instruction (bpf/include/socket_data.h)
	if v, ok := spec.Variables["upload_xchg_on"]; ok {
		if err := haveAtomicXchg(); err == nil {
			if err := v.Set(uint32(1)); err != nil {
				return nil, err
			}
		} else {
			log.Infof("the upload chain claims its places (no atomic exchange in BPF: %v)", err)
		}
	}
	// without the exchange the instruction must not be in the programs at all: the kernels before 5.12 refuse it in
	// their first pass over the instructions ("BPF_STX uses reserved fields"), dead or not
	var xchg uint32
	if v, ok := spec.Variables["upload_xchg_on"]; ok {
		_ = v.Get(&xchg)
	}
	if xchg == 0 {
		StripAtomicFetch(spec)
	}
	return spec, nil
}

// haveAtomicXchg tells whether the kernel runs BPF_XCHG (BPF_ATOMIC with BPF_FETCH, 5.12): a program that exchanges a
// word of an array map value loads
func haveAtomicXchg() error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return err
	}
	defer m.Close()
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, m.FD()),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.Mov.Imm(asm.R1, 1),
		atomicXchgInsn(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SocketFilter, License: bpfLicense, Instructions: insns})
	if err != nil {
		return err
	}
	return prog.Close()
}

// atomicXchgInsn is r1 = xchg(*(u64 *)(r0 + 0), r1): BPF_STX | BPF_ATOMIC | BPF_DW, imm BPF_XCHG (0xe0) | BPF_FETCH
// (0x01). The immediate is set explicitly: cilium/ebpf v0.22 encodes it from Constant, which Xchg.Mem leaves 0, so
// the probe would otherwise be a plain atomic add that every kernel loads
func atomicXchgInsn() asm.Instruction {
	ins := asm.Xchg.Mem(asm.R0, asm.R1, asm.DWord, 0)
	ins.Constant = int64(asm.Xchg >> 8)
	return ins
}

// StripAtomicFetch replaces every atomic instruction with a result (BPF_FETCH, BPF_XCHG, BPF_CMPXCHG: an atomic store
// whose immediate is not 0, 5.12+) by a move of its source register onto itself. They are only in the branches of
// upload_xchg_on (bpf/include/socket_data.h), which are dead when it is 0; the instruction count stays the same.
func StripAtomicFetch(spec *ebpf.CollectionSpec) int {
	n := 0
	for _, p := range spec.Programs {
		for i, ins := range p.Instructions {
			// the kind of an atomic is part of its opcode (the immediate of the instruction): anything but a plain add
			if op := ins.OpCode.AtomicOp(); op != asm.InvalidAtomic && op != asm.AddAtomic {
				repl := asm.Mov.Reg(ins.Src, ins.Src)
				repl.Metadata = ins.Metadata
				p.Instructions[i] = repl
				n++
			}
		}
	}
	return n
}
