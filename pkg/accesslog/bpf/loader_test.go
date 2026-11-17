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
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestAtomicXchgInsnEncoding: the probe of the atomic exchange encodes BPF_XCHG | BPF_FETCH in its immediate, as the
// kernel reads it; with the immediate 0 it would be a plain atomic add that every kernel loads
func TestAtomicXchgInsnEncoding(t *testing.T) {
	var buf bytes.Buffer
	if _, err := atomicXchgInsn().Marshal(&buf, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if raw[0] != 0xdb {
		t.Errorf("opcode %#x, want BPF_STX | BPF_ATOMIC | BPF_DW (0xdb)", raw[0])
	}
	if imm := binary.LittleEndian.Uint32(raw[4:8]); imm != 0xe1 {
		t.Errorf("immediate %#x, want BPF_XCHG | BPF_FETCH (0xe1)", imm)
	}
}

// TestStripAtomicFetch: the atomics with a result (fetch-add 0x01, xchg 0xe1, cmpxchg 0xf1) become moves, a plain
// atomic add (0x00) stays, and the instruction count does not change
func TestStripAtomicFetch(t *testing.T) {
	atomic := func(op asm.AtomicOp) asm.Instruction {
		return op.Mem(asm.R1, asm.R2, asm.DWord, 0)
	}
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"p": {Instructions: asm.Instructions{
		atomic(asm.AddAtomic), atomic(asm.FetchAdd), atomic(asm.Xchg), atomic(asm.CmpXchg), asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}}}}
	if n := StripAtomicFetch(spec); n != 3 {
		t.Fatalf("stripped %d, want 3", n)
	}
	insns := spec.Programs["p"].Instructions
	if len(insns) != 6 {
		t.Fatalf("%d instructions", len(insns))
	}
	if insns[0].OpCode.AtomicOp() != asm.AddAtomic {
		t.Errorf("the plain atomic add was stripped: %v", insns[0])
	}
	for i := 1; i <= 3; i++ {
		if insns[i].OpCode.Class() != asm.ALU64Class || insns[i].Dst != asm.R2 || insns[i].Src != asm.R2 {
			t.Errorf("instruction %d is %v, want r2 = r2", i, insns[i])
		}
	}
}

// TestL24PlanOff: with the switch off the l24 programs are stubs, their maps have one entry and the constant is 0;
// with it on they stay as built and the constant is 1
func TestL24PlanOff(t *testing.T) {
	for _, on := range []bool{false, true} {
		spec, err := loadSpecWithOptions(LoaderOptions{KernelMetricsL2L3: on})
		if err != nil {
			t.Fatal(err)
		}
		var constant uint32
		if err := spec.Variables[l24Variable].Get(&constant); err != nil || constant != map[bool]uint32{false: 0, true: 1}[on] {
			t.Fatalf("on=%t: the constant is %d (%v)", on, constant, err)
		}
		plan := newL24Plan(on)
		plan.apply(spec)
		programs := 0
		for name, p := range spec.Programs {
			if !isL24Program(name) {
				if p.Type == ebpf.SocketFilter && len(p.Instructions) == 2 {
					t.Fatalf("on=%t: %s is stubbed", on, name)
				}
				continue
			}
			programs++
			stub := p.Type == ebpf.SocketFilter && len(p.Instructions) == 2
			if stub == on || plan.Loaded(name) != on {
				t.Fatalf("on=%t: %s is a stub: %t, loaded: %t", on, name, stub, plan.Loaded(name))
			}
		}
		if programs < 30 {
			t.Fatalf("%d l24 programs in the object", programs)
		}
		for _, name := range l24Maps {
			m := spec.Maps[name]
			if m == nil || (m.MaxEntries == 1) == on {
				t.Fatalf("on=%t: map %s: %+v", on, name, m)
			}
		}
	}
}

// TestL24PlanRefused: an l24 program named by a load error is the one stubbed on the next load; an error of another
// program, or with the switch off, is not one of the plan
func TestL24PlanRefused(t *testing.T) {
	spec, err := loadSpecWithOptions(LoaderOptions{KernelMetricsL2L3: true})
	if err != nil {
		t.Fatal(err)
	}
	plan := newL24Plan(true)
	refused := errors.New("program l24_ip_list_rcv: load program: permission denied: invalid indirect read from stack")
	if name := plan.refused(spec, refused); name != "l24_ip_list_rcv" {
		t.Fatalf("refused %q", name)
	}
	plan.stubbed["l24_ip_list_rcv"] = refused
	if name := plan.refused(spec, refused); name != "" {
		t.Fatalf("a stubbed program refused again: %q", name)
	}
	if name := plan.refused(spec, errors.New("program fexit_exit_read: load program: too large")); name != "" {
		t.Fatalf("another program's error taken for an l24 one: %q", name)
	}
	if name := newL24Plan(false).refused(spec, refused); name != "" {
		t.Fatalf("switch off: %q", name)
	}
	plan.apply(spec)
	if p := spec.Programs["l24_ip_list_rcv"]; p.Type != ebpf.SocketFilter || plan.Loaded("l24_ip_list_rcv") {
		t.Fatal("the refused program is not a stub")
	}
	if p := spec.Programs["l24_ip_rcv"]; p.Type == ebpf.SocketFilter || !plan.Loaded("l24_ip_rcv") {
		t.Fatal("another program is a stub")
	}
}
