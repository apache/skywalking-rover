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

package unwind

import "encoding/binary"

const pointerSize = 8

// Registers is the user space registers when the stack is captured
type Registers struct {
	PC, SP, FP, LR uint64
}

// StackMemory is the copied user stack memory, which starts from the stack pointer
type StackMemory struct {
	Base uint64
	Data []byte
}

// ReadUint64 reads a pointer from the copied stack, returns false when the address is out of the copied range
func (m *StackMemory) ReadUint64(addr uint64) (uint64, bool) {
	// avoid the overflow when the address is near the max value
	if addr < m.Base || uint64(len(m.Data)) < pointerSize || addr-m.Base > uint64(len(m.Data))-pointerSize {
		return 0, false
	}
	offset := addr - m.Base
	return binary.LittleEndian.Uint64(m.Data[offset : offset+pointerSize]), true
}

// ModuleResolver resolves the runtime address to the ELF file and the virtual address in the file
type ModuleResolver interface {
	ResolveFileAddress(addr uint64) (path string, fileAddr uint64, ok bool)
}

// TableProvider provides the frame table of the ELF file
type TableProvider interface {
	// Get the frame table of the ELF file, returns nil when the file has no call frame information
	Get(path string) *FrameTable
}

// Unwinder unwinds the user space stack by the call frame information(.eh_frame),
// and fallback to the frame pointer when the call frame information is not found
type Unwinder struct {
	arch     *Arch
	tables   TableProvider
	maxDepth int
}

// NewUnwinder creates a new unwinder
func NewUnwinder(arch *Arch, tables TableProvider, maxDepth int) *Unwinder {
	return &Unwinder{arch: arch, tables: tables, maxDepth: maxDepth}
}

type frameState struct {
	mem   *StackMemory
	regs  [maxRegisters]uint64
	valid [maxRegisters]bool
}

func (f *frameState) register(reg int) (uint64, bool) {
	if reg < 0 || reg >= maxRegisters || !f.valid[reg] {
		return 0, false
	}
	return f.regs[reg], true
}

func (f *frameState) readMemory(addr uint64) (uint64, bool) {
	return f.mem.ReadUint64(addr)
}

func (f *frameState) set(reg int, value uint64) {
	if reg < 0 || reg >= maxRegisters {
		return
	}
	f.regs[reg] = value
	f.valid[reg] = true
}

// UnwindInto unwinds the stack and stores the program counters(from the top frame to the bottom frame)
// into the buffer, the buffer is reused to reduce the allocation
func (u *Unwinder) UnwindInto(regs Registers, mem *StackMemory, resolver ModuleResolver, buf []uint64) []uint64 {
	// only two frame states are used(current and next), and swap them after each step
	var states [2]frameState
	state, next := &states[0], &states[1]
	state.reset(mem)
	state.set(u.arch.SP, regs.SP)
	state.set(u.arch.FP, regs.FP)
	if u.arch.LR >= 0 {
		state.set(u.arch.LR, regs.LR)
	}
	pc := regs.PC
	result := buf[:0]
	signalFrame := true
	for len(result) < u.maxDepth && pc != 0 {
		result = append(result, pc)
		// the return address points to the next instruction of the call,
		// so use the previous address to find the caller's rule except the top frame and signal frame
		lookup := pc
		if !signalFrame {
			lookup--
		}
		var row *Row
		if path, fileAddr, ok := resolver.ResolveFileAddress(lookup); ok {
			if table := u.tables.Get(path); table != nil {
				row = table.FindRow(fileAddr)
			}
		}

		next.reset(mem)
		var ok bool
		if row != nil {
			pc, ok = u.stepByRow(state, next, row, pc)
			signalFrame = row.SignalFrame
		} else {
			pc, ok = u.stepByFramePointer(state, next)
			signalFrame = false
		}
		if !ok {
			break
		}
		state, next = next, state
	}
	return result
}

func (f *frameState) reset(mem *StackMemory) {
	f.mem = mem
	f.valid = [maxRegisters]bool{}
}

// stepByRow recovers the caller registers into the next state, returns the return address
func (u *Unwinder) stepByRow(state, next *frameState, row *Row, pc uint64) (ra uint64, ok bool) {
	if u.arch.PC >= 0 {
		// the expression could reference the program counter, such as the PLT entries in x86_64
		state.set(u.arch.PC, pc)
	}
	var cfa uint64
	if row.CFA.Expr != nil {
		cfa, ok = evaluateExpression(state, row.CFA.Expr)
	} else {
		var base uint64
		base, ok = state.register(row.CFA.Reg)
		cfa = base + uint64(row.CFA.Offset)
	}
	if !ok {
		return 0, false
	}

	for reg := 0; reg < maxRegisters; reg++ {
		if value, valid := recoverRegister(state, &row.Regs[reg], reg, cfa); valid {
			next.set(reg, value)
		}
	}
	ra, ok = next.register(row.RA)
	if !ok {
		// the return address is undefined, it's the outermost frame
		return 0, false
	}
	ra &= u.arch.AddressMask
	// the stack must not shrink, otherwise the data must be invalid.
	// the CFA could equal the SP in the leaf function(or before the prologue) on arm64,
	// the return address is in the link register, then the frame must make progress
	sp, _ := state.register(u.arch.SP)
	if cfa < sp || (cfa == sp && ra == pc) {
		return 0, false
	}
	next.set(u.arch.SP, cfa)
	return ra, true
}

func recoverRegister(state *frameState, rule *RegisterRule, reg int, cfa uint64) (uint64, bool) {
	switch rule.Type {
	case RuleUnspecified, RuleSameValue:
		return state.register(reg)
	case RuleOffset:
		return state.readMemory(cfa + uint64(rule.Offset))
	case RuleValOffset:
		return cfa + uint64(rule.Offset), true
	case RuleRegister:
		return state.register(rule.Reg)
	case RuleExpression:
		addr, ok := evaluateExpression(state, rule.Expr, cfa)
		if !ok {
			return 0, false
		}
		return state.readMemory(addr)
	case RuleValExpression:
		return evaluateExpression(state, rule.Expr, cfa)
	}
	return 0, false
}

// stepByFramePointer unwinds the frame by the frame pointer chain, used when the call frame information not found
func (u *Unwinder) stepByFramePointer(state, next *frameState) (ra uint64, ok bool) {
	fp, valid := state.register(u.arch.FP)
	if !valid {
		return 0, false
	}
	sp, _ := state.register(u.arch.SP)
	if fp < sp {
		return 0, false
	}
	prevFP, ok1 := state.readMemory(fp)
	ra, ok2 := state.readMemory(fp + pointerSize)
	if !ok1 || !ok2 {
		return 0, false
	}
	next.set(u.arch.SP, fp+2*pointerSize)
	next.set(u.arch.FP, prevFP)
	return ra & u.arch.AddressMask, true
}
