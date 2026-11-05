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

import (
	"encoding/binary"
	"reflect"
	"testing"
)

const (
	testSectionAddr = 0x400
	testStackBase   = 0x7ffd0000
	testModulePath  = "test-module"
)

// amd64CIE is the CIE body of x86_64: CFA=rsp+8, RA=CFA-8
var amd64CIE = []byte{
	0, 0, 0, 0, // CIE id
	1,           // version
	'z', 'R', 0, // augmentation
	1,               // code alignment
	0x78,            // data alignment: -8
	16,              // return address register
	1,               // augmentation data length
	0x1b,            // FDE pointer encoding: pcrel|sdata4
	cfaDefCFA, 7, 8, // CFA = rsp+8
	cfaOffset | 16, 1, // RA at CFA-8
	0, // padding
}

// arm64CIE is the CIE body of aarch64: CFA=sp+0, RA is in the x30(LR)
var arm64CIE = []byte{
	0, 0, 0, 0, // CIE id
	1,           // version
	'z', 'R', 0, // augmentation
	4,                // code alignment
	0x78,             // data alignment: -8
	30,               // return address register
	1,                // augmentation data length
	0x1b,             // FDE pointer encoding: pcrel|sdata4
	cfaDefCFA, 31, 0, // CFA = sp+0
	0, 0, 0, 0, // padding
}

// buildTestEHFrame builds an .eh_frame section with the x86_64 CIE and the FDEs,
// each FDE is described by the start, length and the call frame instructions
func buildTestEHFrame(fdes ...testFDE) []byte {
	return buildTestEHFrameWithCIE(amd64CIE, fdes...)
}

func buildTestEHFrameWithCIE(cieBody []byte, fdes ...testFDE) []byte {
	return buildTestEHFrameWithCIEs([][]byte{cieBody}, fdes...)
}

// buildTestEHFrameWithCIEs builds an .eh_frame section with multiple CIEs, the FDE references the CIE by its index
func buildTestEHFrameWithCIEs(cieBodies [][]byte, fdes ...testFDE) []byte {
	var data []byte
	cieOffsets := make([]int, 0, len(cieBodies))
	for _, body := range cieBodies {
		cieOffsets = append(cieOffsets, len(data))
		data = binary.LittleEndian.AppendUint32(data, uint32(len(body)))
		data = append(data, body...)
	}
	for _, f := range fdes {
		entryStart := len(data) + 4
		body := binary.LittleEndian.AppendUint32(nil, uint32(entryStart-cieOffsets[f.cie])) // CIE pointer
		pcFieldAddr := uint32(testSectionAddr + len(data) + 8)
		body = binary.LittleEndian.AppendUint32(body, f.start-pcFieldAddr)
		body = binary.LittleEndian.AppendUint32(body, f.length)
		body = append(body, 0) // augmentation data length
		body = append(body, f.instructions...)
		for len(body)%4 != 0 {
			body = append(body, cfaNop)
		}
		data = binary.LittleEndian.AppendUint32(data, uint32(len(body)))
		data = append(data, body...)
	}
	return binary.LittleEndian.AppendUint32(data, 0)
}

type testFDE = struct {
	start, length uint32
	instructions  []byte
	// the index of the CIE, only used by buildTestEHFrameWithCIEs
	cie int
}

type staticResolver struct {
	start, end uint64
}

func (s *staticResolver) ResolveFileAddress(addr uint64) (path string, fileAddr uint64, ok bool) {
	if addr >= s.start && addr < s.end {
		return testModulePath, addr, true
	}
	return "", 0, false
}

type staticTables map[string]*FrameTable

func (s staticTables) Get(path string) *FrameTable {
	return s[path]
}

func newTestUnwinder(t *testing.T, data []byte) *Unwinder {
	table, err := ParseEHFrame(ArchAMD64, data, testSectionAddr)
	if err != nil {
		t.Fatalf("parsing eh_frame failure: %v", err)
	}
	return NewUnwinder(ArchAMD64, staticTables{testModulePath: table}, 32)
}

type testStack struct {
	data []byte
}

func (s *testStack) put(addr, value uint64) {
	offset := addr - testStackBase
	for uint64(len(s.data)) < offset+8 {
		s.data = append(s.data, 0)
	}
	binary.LittleEndian.PutUint64(s.data[offset:], value)
}

func TestUnwindByCallFrameInformation(t *testing.T) {
	// leaf(0x1000): no frame pointer, CFA=rsp+16 after the first instruction
	// middle(0x2000): push rbp, CFA=rsp+16, rbp saved at CFA-16
	// root(0x3000): RA undefined, it's the outermost frame
	data := buildTestEHFrame(
		testFDE{start: 0x1000, length: 0x100, instructions: []byte{cfaAdvanceLoc | 1, cfaDefCFAOffset, 16}},
		testFDE{start: 0x2000, length: 0x100, instructions: []byte{cfaAdvanceLoc | 1, cfaDefCFAOffset, 16, cfaOffset | 6, 2}},
		testFDE{start: 0x3000, length: 0x100, instructions: []byte{cfaUndefined, 16}},
	)
	unwinder := newTestUnwinder(t, data)

	stack := &testStack{}
	// leaf frame: sp=base, CFA=base+16, RA at base+8
	stack.put(testStackBase+8, 0x2050)
	// middle frame: sp=base+16, CFA=base+32, rbp saved at base+16, RA at base+24
	stack.put(testStackBase+16, 0xdead)
	stack.put(testStackBase+24, 0x3010)
	stack.put(testStackBase+32, 0)

	// a fake rbp which not point to the stack, means the frame pointer is not available
	frames := unwinder.UnwindInto(Registers{PC: 0x1010, SP: testStackBase, FP: 0x1234},
		&StackMemory{Base: testStackBase, Data: stack.data}, &staticResolver{start: 0x1000, end: 0x4000}, nil)
	expected := []uint64{0x1010, 0x2050, 0x3010}
	if !reflect.DeepEqual(frames, expected) {
		t.Fatalf("expected frames %x, actual %x", expected, frames)
	}
}

func TestUnwindFallbackToFramePointer(t *testing.T) {
	unwinder := newTestUnwinder(t, buildTestEHFrame())
	stack := &testStack{}
	// frame record: [fp]=previous fp, [fp+8]=return address
	stack.put(testStackBase+16, testStackBase+48)
	stack.put(testStackBase+24, 0x5010)
	stack.put(testStackBase+48, 0)
	stack.put(testStackBase+56, 0x6010)

	frames := unwinder.UnwindInto(Registers{PC: 0x4010, SP: testStackBase, FP: testStackBase + 16},
		&StackMemory{Base: testStackBase, Data: stack.data}, &staticResolver{}, nil)
	expected := []uint64{0x4010, 0x5010, 0x6010}
	if !reflect.DeepEqual(frames, expected) {
		t.Fatalf("expected frames %x, actual %x", expected, frames)
	}
}

type testExprContext struct {
	regs map[int]uint64
}

func (c *testExprContext) register(reg int) (uint64, bool) {
	v, ok := c.regs[reg]
	return v, ok
}

func (c *testExprContext) readMemory(uint64) (uint64, bool) {
	return 0, false
}

func TestEvaluatePLTExpression(t *testing.T) {
	// the CFA expression of the x86_64 PLT: rsp + 8 + ((rip & 15) >= 11) << 3
	expr := []byte{opBreg0 + 7, 8, opBreg0 + 16, 0, opLit0 + 15, opAnd, opLit0 + 11, opGe, opLit0 + 3, opShl, opPlus}
	tests := []struct {
		rip, expected uint64
	}{
		{rip: 0x1000, expected: 0x7f08},
		{rip: 0x100b, expected: 0x7f10},
	}
	for _, tt := range tests {
		ctx := &testExprContext{regs: map[int]uint64{7: 0x7f00, 16: tt.rip}}
		v, ok := evaluateExpression(ctx, expr)
		if !ok || v != tt.expected {
			t.Fatalf("rip 0x%x: expected 0x%x, actual 0x%x(%v)", tt.rip, tt.expected, v, ok)
		}
	}
}

func TestStackMemoryOutOfRange(t *testing.T) {
	mem := &StackMemory{Base: testStackBase, Data: make([]byte, 16)}
	if _, ok := mem.ReadUint64(testStackBase + 8); !ok {
		t.Fatalf("should read the last pointer")
	}
	for _, addr := range []uint64{testStackBase - 8, testStackBase + 9, testStackBase + 16} {
		if _, ok := mem.ReadUint64(addr); ok {
			t.Fatalf("should not read the address 0x%x", addr)
		}
	}
}

func TestKeepsFramePointer(t *testing.T) {
	// push rbp; mov rbp, rsp: CFA=rsp+16, rbp saved at CFA-16, then CFA=rbp+16
	withFP := []byte{cfaAdvanceLoc | 1, cfaDefCFAOffset, 16, cfaOffset | 6, 2, cfaAdvanceLoc | 3, cfaDefCFARegister, 6}
	// sub rsp, 24: CFA=rsp+32
	withoutFP := []byte{cfaAdvanceLoc | 4, cfaDefCFAOffset, 32}
	tests := []struct {
		name     string
		fdes     []testFDE
		expected bool
	}{
		{name: "all with frame pointer", expected: true, fdes: []testFDE{
			{start: 0x1000, length: 0x10, instructions: withFP},
			{start: 0x2000, length: 0x10, instructions: withFP},
		}},
		{name: "all without frame pointer", expected: false, fdes: []testFDE{
			{start: 0x1000, length: 0x10, instructions: withoutFP},
			{start: 0x2000, length: 0x10, instructions: withoutFP},
		}},
		{name: "mostly without frame pointer", expected: false, fdes: []testFDE{
			{start: 0x1000, length: 0x10, instructions: withFP},
			{start: 0x2000, length: 0x10, instructions: withoutFP},
			{start: 0x3000, length: 0x10, instructions: withoutFP},
			{start: 0x4000, length: 0x10, instructions: withoutFP},
			{start: 0x5000, length: 0x10, instructions: withoutFP},
			{start: 0x6000, length: 0x10, instructions: withoutFP},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, err := ParseEHFrame(ArchAMD64, buildTestEHFrame(tt.fdes...), testSectionAddr)
			if err != nil {
				t.Fatal(err)
			}
			if actual := table.KeepsFramePointer(); actual != tt.expected {
				t.Fatalf("expected %v, actual %v", tt.expected, actual)
			}
		})
	}
}

func TestHasCallFrameInformation(t *testing.T) {
	table, err := ParseEHFrame(ArchAMD64, buildTestEHFrame(testFDE{start: 0x1000, length: 0x100}), testSectionAddr)
	if err != nil {
		t.Fatal(err)
	}
	table.codeSize = 0x180
	if !table.HasCallFrameInformation() {
		t.Fatalf("the code should be covered by the call frame information")
	}
	table.codeSize = 0x10000
	if table.HasCallFrameInformation() {
		t.Fatalf("the code should not be covered by the call frame information")
	}
}

func TestUnwindARM64LeafFrame(t *testing.T) {
	// leaf(0x1000): no frame, CFA=sp+0, the return address is in the LR
	// middle(0x2000): "stp x29, x30, [sp, #-16]!", CFA=sp+16, x29 at CFA-16, x30 at CFA-8
	// root(0x3000): RA undefined, it's the outermost frame
	data := buildTestEHFrameWithCIE(arm64CIE,
		testFDE{start: 0x1000, length: 0x100},
		testFDE{start: 0x2000, length: 0x100, instructions: []byte{cfaAdvanceLoc | 1, cfaDefCFAOffset, 16, cfaOffset | 29, 2, cfaOffset | 30, 1}},
		testFDE{start: 0x3000, length: 0x100, instructions: []byte{cfaUndefined, 30}},
	)
	table, err := ParseEHFrame(ArchARM64, data, testSectionAddr)
	if err != nil {
		t.Fatal(err)
	}
	unwinder := NewUnwinder(ArchARM64, staticTables{testModulePath: table}, 32)
	stack := &testStack{}
	stack.put(testStackBase, 0)
	// the return address signed by the pointer authentication
	stack.put(testStackBase+8, 0x00ab000000003010)

	frames := unwinder.UnwindInto(Registers{PC: 0x1010, SP: testStackBase, LR: 0x2050},
		&StackMemory{Base: testStackBase, Data: stack.data}, &staticResolver{start: 0x1000, end: 0x4000}, nil)
	expected := []uint64{0x1010, 0x2050, 0x3010}
	if !reflect.DeepEqual(frames, expected) {
		t.Fatalf("expected frames %x, actual %x", expected, frames)
	}
}

func TestUnwindStopsWithoutProgress(t *testing.T) {
	// CFA=sp+0 and the return address is the same as the current address, the frame never makes progress
	data := buildTestEHFrameWithCIE(arm64CIE, testFDE{start: 0x1000, length: 0x100})
	table, err := ParseEHFrame(ArchARM64, data, testSectionAddr)
	if err != nil {
		t.Fatal(err)
	}
	unwinder := NewUnwinder(ArchARM64, staticTables{testModulePath: table}, 32)
	frames := unwinder.UnwindInto(Registers{PC: 0x1010, SP: testStackBase, LR: 0x1010},
		&StackMemory{Base: testStackBase, Data: make([]byte, 16)}, &staticResolver{start: 0x1000, end: 0x2000}, nil)
	if len(frames) != 1 {
		t.Fatalf("the unwinding should stop, actual frames %x", frames)
	}
}

func TestARM64KeepsFramePointer(t *testing.T) {
	// GCC: "stp x29, x30, [sp, #-32]!; mov x29, sp", the CFA keeps based on the SP
	withFrameRecord := []byte{cfaAdvanceLoc | 1, cfaDefCFAOffset, 32, cfaOffset | 29, 4, cfaOffset | 30, 3}
	// only save the LR with the other callee saved register
	withoutFrameRecord := []byte{cfaAdvanceLoc | 1, cfaDefCFAOffset, 32, cfaOffset | 19, 4, cfaOffset | 30, 3}
	for _, tt := range []struct {
		instructions []byte
		expected     bool
	}{{withFrameRecord, true}, {withoutFrameRecord, false}} {
		data := buildTestEHFrameWithCIE(arm64CIE, testFDE{start: 0x1000, length: 0x10, instructions: tt.instructions})
		table, err := ParseEHFrame(ArchARM64, data, testSectionAddr)
		if err != nil {
			t.Fatal(err)
		}
		if actual := table.KeepsFramePointer(); actual != tt.expected {
			t.Fatalf("expected %v, actual %v", tt.expected, actual)
		}
	}
}

func TestRememberAndRestoreState(t *testing.T) {
	// CFA=rsp+16 at 0x1001, remember, CFA=rsp+32 at 0x1002, restore at 0x1003
	instructions := []byte{
		cfaAdvanceLoc | 1, cfaDefCFAOffset, 16, cfaRememberState,
		cfaAdvanceLoc | 1, cfaDefCFAOffset, 32, cfaOffset | 6, 4,
		cfaAdvanceLoc | 1, cfaRestoreState,
	}
	table, err := ParseEHFrame(ArchAMD64, buildTestEHFrame(testFDE{start: 0x1000, length: 0x10, instructions: instructions}), testSectionAddr)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		pc        uint64
		cfaOffset int64
		rbpSaved  bool
	}{{0x1000, 8, false}, {0x1001, 16, false}, {0x1002, 32, true}, {0x1003, 16, false}, {0x100f, 16, false}} {
		row := table.FindRow(tt.pc)
		if row == nil || row.CFA.Offset != tt.cfaOffset || (row.Regs[6].Type == RuleOffset) != tt.rbpSaved {
			t.Fatalf("unexpected row at 0x%x: %+v", tt.pc, row)
		}
	}
	if row := table.FindRow(0x1010); row != nil {
		t.Fatalf("the address out of the FDE should not have the row")
	}
}

func TestSkipBadFDE(t *testing.T) {
	// the unknown instruction(0x3f) makes the FDE could not be executed, but the other FDEs are still available
	data := buildTestEHFrame(
		testFDE{start: 0x1000, length: 0x10, instructions: []byte{0x3f}},
		testFDE{start: 0x2000, length: 0x10, instructions: []byte{cfaAdvanceLoc | 1, cfaDefCFAOffset, 16}},
	)
	table, err := ParseEHFrame(ArchAMD64, data, testSectionAddr)
	if err != nil {
		t.Fatal(err)
	}
	if table.FindRow(0x1001) != nil {
		t.Fatalf("the bad FDE should not have the row")
	}
	if row := table.FindRow(0x2001); row == nil || row.CFA.Offset != 16 {
		t.Fatalf("unexpected row: %+v", row)
	}
}

func TestStackMemoryOverflow(t *testing.T) {
	mem := &StackMemory{Base: 0, Data: make([]byte, 64)}
	if _, ok := mem.ReadUint64(0xfffffffffffffff9); ok {
		t.Fatalf("should not read the overflow address")
	}
}

// amd64SignalCIE is the x86_64 CIE with the "S" augmentation, such as the __restore_rt of glibc
var amd64SignalCIE = []byte{
	0, 0, 0, 0, // CIE id
	1,                // version
	'z', 'R', 'S', 0, // augmentation
	1,               // code alignment
	0x78,            // data alignment: -8
	16,              // return address register
	1,               // augmentation data length
	0x1b,            // FDE pointer encoding: pcrel|sdata4
	cfaDefCFA, 7, 8, // CFA = rsp+8
	cfaOffset | 16, 1, // RA at CFA-8
	0, 0, 0, // padding
}

func TestUnwindThroughSignalFrame(t *testing.T) {
	// handler(0x1000): CFA=rsp+8, returns to the signal trampoline
	// trampoline(0x1fff): signal frame, the FDE starts one byte before the symbol like glibc,
	// 	the restored PC is the interrupted instruction, not a return address
	// before(0x2f00): the function before the interrupted one, only found when looking up by PC-1
	// interrupted(0x3000): interrupted at the first instruction, RA undefined
	data := buildTestEHFrameWithCIEs([][]byte{amd64CIE, amd64SignalCIE},
		testFDE{start: 0x1000, length: 0x100},
		testFDE{start: 0x1fff, length: 0x10, cie: 1},
		testFDE{start: 0x2f00, length: 0x100},
		testFDE{start: 0x3000, length: 0x100, instructions: []byte{cfaUndefined, 16}},
	)
	table, err := ParseEHFrame(ArchAMD64, data, testSectionAddr)
	if err != nil {
		t.Fatalf("parsing eh_frame failure: %v", err)
	}
	if row := table.FindRow(0x2000); row == nil || !row.SignalFrame {
		t.Fatalf("the trampoline should be a signal frame, row: %+v", row)
	}
	if row := table.FindRow(0x1010); row == nil || row.SignalFrame {
		t.Fatalf("the handler should not be a signal frame, row: %+v", row)
	}
	unwinder := NewUnwinder(ArchAMD64, staticTables{testModulePath: table}, 32)

	stack := &testStack{}
	// handler: sp=base, RA at base
	stack.put(testStackBase, 0x2000)
	// trampoline: sp=base+8, RA(interrupted PC) at base+8
	stack.put(testStackBase+8, 0x3000)
	// would be read as the RA only when the interrupted frame is wrongly looked up by PC-1
	stack.put(testStackBase+16, 0x2f50)

	frames := unwinder.UnwindInto(Registers{PC: 0x1010, SP: testStackBase},
		&StackMemory{Base: testStackBase, Data: stack.data}, &staticResolver{start: 0x1000, end: 0x4000}, nil)
	expected := []uint64{0x1010, 0x2000, 0x3000}
	if !reflect.DeepEqual(frames, expected) {
		t.Fatalf("expected frames %x, actual %x", expected, frames)
	}
}
