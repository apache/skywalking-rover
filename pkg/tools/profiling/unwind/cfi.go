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

// RuleType is how to recover the register value of the caller frame
type RuleType uint8

const (
	// RuleUnspecified means no rule declared, the register keeps the same value
	RuleUnspecified RuleType = iota
	// RuleUndefined means the register value could not be recovered
	RuleUndefined
	// RuleSameValue means the register keeps the same value
	RuleSameValue
	// RuleOffset means the register is saved at the address CFA+N
	RuleOffset
	// RuleValOffset means the register value is CFA+N
	RuleValOffset
	// RuleRegister means the register value is saved in another register
	RuleRegister
	// RuleExpression means the register is saved at the address computed by the expression
	RuleExpression
	// RuleValExpression means the register value is computed by the expression
	RuleValExpression
)

// RegisterRule is the rule to recover a register
type RegisterRule struct {
	Type   RuleType
	Offset int64
	Reg    int
	Expr   []byte
}

// CFARule is the rule to compute the Canonical Frame Address
// when the Expr is not empty, the CFA is computed by the expression, otherwise it is Reg+Offset
type CFARule struct {
	Reg    int
	Offset int64
	Expr   []byte
}

// Row is the unwind rules at an instruction address
type Row struct {
	CFA         CFARule
	Regs        [maxRegisters]RegisterRule
	RA          int
	SignalFrame bool
}

// DWARF call frame instructions
const (
	cfaAdvanceLoc       = 0x40
	cfaOffset           = 0x80
	cfaRestore          = 0xc0
	cfaNop              = 0x00
	cfaSetLoc           = 0x01
	cfaAdvanceLoc1      = 0x02
	cfaAdvanceLoc2      = 0x03
	cfaAdvanceLoc4      = 0x04
	cfaOffsetExtended   = 0x05
	cfaRestoreExtended  = 0x06
	cfaUndefined        = 0x07
	cfaSameValue        = 0x08
	cfaRegister         = 0x09
	cfaRememberState    = 0x0a
	cfaRestoreState     = 0x0b
	cfaDefCFA           = 0x0c
	cfaDefCFARegister   = 0x0d
	cfaDefCFAOffset     = 0x0e
	cfaDefCFAExpression = 0x0f
	cfaExpression       = 0x10
	cfaOffsetExtendedSF = 0x11
	cfaDefCFASF         = 0x12
	cfaDefCFAOffsetSF   = 0x13
	cfaValOffset        = 0x14
	cfaValOffsetSF      = 0x15
	cfaValExpression    = 0x16
	// DW_CFA_AARCH64_negate_ra_state_with_pc, emitted for the PAuth_LR(-mbranch-protection=pac-ret+pc)
	cfaAArch64NegateRAWithPC = 0x2c
	cfaAArch64NegateRA       = 0x2d
	cfaGNUArgsSize           = 0x2e
	cfaGNUNegOffsetExtSF     = 0x2f

	primaryOpcodeMask  = 0xc0
	primaryOperandMask = 0x3f
	// maxRememberStates is the max depth of remember state stack, protect from the bad data
	maxRememberStates = 16
)

type cfiState struct {
	table *FrameTable
	cie   *cie
	row   Row
	// initial is the rules after the CIE initial instructions, used by the restore instructions
	initial *Row
	stack   []Row
	loc     uint64
	target  uint64
	done    bool
	// fpBased marks the function keeps the frame pointer
	fpBased bool
}

type cfiHandler func(s *cfiState, r *byteReader)

var cfiHandlers = [0x30]cfiHandler{
	cfaNop:            func(*cfiState, *byteReader) {},
	cfaSetLoc:         func(s *cfiState, r *byteReader) { s.setLoc(r.encodedPointer(s.cie.fdeEnc, s.table.sectionAddr)) },
	cfaAdvanceLoc1:    func(s *cfiState, r *byteReader) { s.advance(uint64(r.u8())) },
	cfaAdvanceLoc2:    func(s *cfiState, r *byteReader) { s.advance(uint64(r.u16())) },
	cfaAdvanceLoc4:    func(s *cfiState, r *byteReader) { s.advance(uint64(r.u32())) },
	cfaOffsetExtended: handleOffsetExtended,
	cfaRestoreExtended: func(s *cfiState, r *byteReader) {
		s.restore(r.uleb())
	},
	cfaUndefined:        func(s *cfiState, r *byteReader) { s.setRule(r.uleb(), RegisterRule{Type: RuleUndefined}) },
	cfaSameValue:        func(s *cfiState, r *byteReader) { s.setRule(r.uleb(), RegisterRule{Type: RuleSameValue}) },
	cfaRegister:         handleRegister,
	cfaRememberState:    handleRememberState,
	cfaRestoreState:     handleRestoreState,
	cfaDefCFA:           handleDefCFA,
	cfaDefCFARegister:   handleDefCFARegister,
	cfaDefCFAOffset:     handleDefCFAOffset,
	cfaDefCFAExpression: func(s *cfiState, r *byteReader) { s.row.CFA = CFARule{Expr: r.bytes(int(r.uleb()))} },
	cfaExpression:       handleExpression,
	cfaOffsetExtendedSF: handleOffsetExtendedSF,
	cfaDefCFASF:         handleDefCFASF,
	cfaDefCFAOffsetSF:   handleDefCFAOffsetSF,
	cfaValOffset:        handleValOffset,
	cfaValOffsetSF:      handleValOffsetSF,
	cfaValExpression:    handleValExpression,
	// pointer authentication state on arm64, the return address is stripped by the address mask
	cfaAArch64NegateRAWithPC: func(*cfiState, *byteReader) {},
	cfaAArch64NegateRA:       func(*cfiState, *byteReader) {},
	cfaGNUArgsSize:           func(_ *cfiState, r *byteReader) { r.uleb() },
	cfaGNUNegOffsetExtSF:     handleGNUNegOffsetExtSF,
}

func handleOffsetExtended(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleOffset, Offset: int64(r.uleb()) * s.cie.dataAlign})
}

func handleRegister(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleRegister, Reg: int(r.uleb())})
}

func handleRememberState(s *cfiState, _ *byteReader) {
	if len(s.stack) < maxRememberStates {
		s.stack = append(s.stack, s.row)
	}
}

func handleRestoreState(s *cfiState, _ *byteReader) {
	if len(s.stack) == 0 {
		return
	}
	s.row = s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
}

func handleDefCFA(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.row.CFA = CFARule{Reg: int(reg), Offset: int64(r.uleb())}
}

func handleDefCFARegister(s *cfiState, r *byteReader) {
	s.row.CFA.Reg = int(r.uleb())
	s.row.CFA.Expr = nil
}

func handleDefCFAOffset(s *cfiState, r *byteReader) {
	s.row.CFA.Offset = int64(r.uleb())
	s.row.CFA.Expr = nil
}

func handleExpression(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleExpression, Expr: r.bytes(int(r.uleb()))})
}

func handleOffsetExtendedSF(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleOffset, Offset: r.sleb() * s.cie.dataAlign})
}

func handleDefCFASF(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.row.CFA = CFARule{Reg: int(reg), Offset: r.sleb() * s.cie.dataAlign}
}

func handleDefCFAOffsetSF(s *cfiState, r *byteReader) {
	s.row.CFA.Offset = r.sleb() * s.cie.dataAlign
	s.row.CFA.Expr = nil
}

func handleValOffset(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleValOffset, Offset: int64(r.uleb()) * s.cie.dataAlign})
}

func handleValOffsetSF(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleValOffset, Offset: r.sleb() * s.cie.dataAlign})
}

func handleValExpression(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleValExpression, Expr: r.bytes(int(r.uleb()))})
}

func handleGNUNegOffsetExtSF(s *cfiState, r *byteReader) {
	reg := r.uleb()
	s.setRule(reg, RegisterRule{Type: RuleOffset, Offset: -int64(r.uleb()) * s.cie.dataAlign})
}

// initCIE executes the CIE initial instructions once, the result is shared by all the FDEs of the CIE
func initCIE(table *FrameTable, c *cie) bool {
	s := &cfiState{table: table, cie: c, target: ^uint64(0), initial: &Row{}}
	s.row.RA = c.raReg
	s.row.SignalFrame = c.signalFrame
	if c.raReg < 0 || c.raReg >= maxRegisters || !s.execute(c.insStart, c.insEnd) {
		return false
	}
	c.initial = s.row
	c.initialFPBased = s.fpBased
	return true
}

func newFDEState(table *FrameTable, f *fde, target uint64) *cfiState {
	return &cfiState{
		table:   table,
		cie:     f.cie,
		row:     f.cie.initial,
		initial: &f.cie.initial,
		loc:     f.start,
		target:  target,
		fpBased: f.cie.initialFPBased,
	}
}

// executeCFI executes the FDE instructions to build the unwind rules row of the target address,
// returns the row and the start address of the row, the row is the same for all addresses in [start, the next row)
func executeCFI(table *FrameTable, f *fde, target uint64) (row *Row, start uint64) {
	s := newFDEState(table, f, target)
	if !s.execute(f.insStart, f.insEnd) {
		return nil, 0
	}
	if s.row.RA < 0 || s.row.RA >= maxRegisters {
		return nil, 0
	}
	result := s.row
	return &result, s.loc
}

func (s *cfiState) execute(start, end int) bool {
	if start < 0 || end > len(s.table.data) || start > end {
		return false
	}
	r := newByteReader(s.table.data[:end], start)
	for !s.done && r.remaining() > 0 {
		op := r.u8()
		switch op & primaryOpcodeMask {
		case cfaAdvanceLoc:
			s.advance(uint64(op & primaryOperandMask))
		case cfaOffset:
			s.setRule(uint64(op&primaryOperandMask), RegisterRule{Type: RuleOffset, Offset: int64(r.uleb()) * s.cie.dataAlign})
		case cfaRestore:
			s.restore(uint64(op & primaryOperandMask))
		default:
			if int(op) >= len(cfiHandlers) || cfiHandlers[op] == nil {
				// unknown instruction, could not continue
				return false
			}
			cfiHandlers[op](s, r)
		}
		if r.err != nil {
			return false
		}
		if !s.fpBased {
			s.fpBased = keepsFrameRecord(&s.row, s.table.arch)
		}
	}
	return true
}

// keepsFrameRecord checks the row defines the CFA by the frame pointer or saves the frame record
func keepsFrameRecord(row *Row, arch *Arch) bool {
	return (row.CFA.Expr == nil && row.CFA.Reg == arch.FP) || savesFrameRecord(row, arch)
}

// savesFrameRecord checks the function saves the frame record(the frame pointer and the link register are adjacent),
// GCC on arm64 keeps the CFA based on SP even the function keeps the frame pointer, such as:
// "stp x29, x30, [sp, #-16]!; mov x29, sp" with ".cfi_offset 29, -16; .cfi_offset 30, -8"
func savesFrameRecord(row *Row, arch *Arch) bool {
	if arch.LR < 0 {
		return false
	}
	fp, lr := &row.Regs[arch.FP], &row.Regs[arch.LR]
	return fp.Type == RuleOffset && lr.Type == RuleOffset && lr.Offset == fp.Offset+pointerSize
}

// usesFramePointer checks the function keeps the frame pointer in any instruction
func usesFramePointer(table *FrameTable, f *fde) bool {
	s := newFDEState(table, f, f.end)
	return s.execute(f.insStart, f.insEnd) && s.fpBased
}

func (s *cfiState) advance(delta uint64) {
	s.setLoc(s.loc + delta*s.cie.codeAlign)
}

func (s *cfiState) setLoc(loc uint64) {
	if loc > s.target {
		s.done = true
		return
	}
	s.loc = loc
}

func (s *cfiState) setRule(reg uint64, rule RegisterRule) {
	if reg >= maxRegisters {
		return
	}
	s.row.Regs[reg] = rule
}

func (s *cfiState) restore(reg uint64) {
	if reg >= maxRegisters {
		return
	}
	s.row.Regs[reg] = s.initial.Regs[reg]
}
