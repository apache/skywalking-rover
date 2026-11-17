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

// DWARF expression operations, only the operations which used in the call frame information are supported
const (
	opDeref      = 0x06
	opConst1u    = 0x08
	opConst1s    = 0x09
	opConst2u    = 0x0a
	opConst2s    = 0x0b
	opConst4u    = 0x0c
	opConst4s    = 0x0d
	opConst8u    = 0x0e
	opConst8s    = 0x0f
	opConstu     = 0x10
	opConsts     = 0x11
	opDup        = 0x12
	opDrop       = 0x13
	opOver       = 0x14
	opSwap       = 0x16
	opAnd        = 0x1a
	opMinus      = 0x1c
	opMul        = 0x1e
	opNeg        = 0x1f
	opNot        = 0x20
	opOr         = 0x21
	opPlus       = 0x22
	opPlusUconst = 0x23
	opShl        = 0x24
	opShr        = 0x25
	opShra       = 0x26
	opXor        = 0x27
	opEq         = 0x29
	opGe         = 0x2a
	opGt         = 0x2b
	opLe         = 0x2c
	opLt         = 0x2d
	opNe         = 0x2e
	opLit0       = 0x30
	opLit31      = 0x4f
	opBreg0      = 0x70
	opBreg31     = 0x8f
	opBregx      = 0x92
	opNop        = 0x96

	maxExprStack = 64
)

// exprContext provides the registers and memory for evaluating the expression
type exprContext interface {
	register(reg int) (uint64, bool)
	readMemory(addr uint64) (uint64, bool)
}

type exprMachine struct {
	ctx   exprContext
	stack []uint64
	ok    bool
}

func (m *exprMachine) push(v uint64) {
	if len(m.stack) >= maxExprStack {
		m.ok = false
		return
	}
	m.stack = append(m.stack, v)
}

func (m *exprMachine) pop() uint64 {
	if len(m.stack) == 0 {
		m.ok = false
		return 0
	}
	v := m.stack[len(m.stack)-1]
	m.stack = m.stack[:len(m.stack)-1]
	return v
}

func boolValue(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

var binaryOperations = map[uint8]func(a, b uint64) uint64{
	opAnd:   func(a, b uint64) uint64 { return a & b },
	opMinus: func(a, b uint64) uint64 { return a - b },
	opMul:   func(a, b uint64) uint64 { return a * b },
	opOr:    func(a, b uint64) uint64 { return a | b },
	opPlus:  func(a, b uint64) uint64 { return a + b },
	opShl:   func(a, b uint64) uint64 { return a << b },
	opShr:   func(a, b uint64) uint64 { return a >> b },
	opShra:  func(a, b uint64) uint64 { return uint64(int64(a) >> b) },
	opXor:   func(a, b uint64) uint64 { return a ^ b },
	opEq:    func(a, b uint64) uint64 { return boolValue(a == b) },
	opGe:    func(a, b uint64) uint64 { return boolValue(int64(a) >= int64(b)) },
	opGt:    func(a, b uint64) uint64 { return boolValue(int64(a) > int64(b)) },
	opLe:    func(a, b uint64) uint64 { return boolValue(int64(a) <= int64(b)) },
	opLt:    func(a, b uint64) uint64 { return boolValue(int64(a) < int64(b)) },
	opNe:    func(a, b uint64) uint64 { return boolValue(a != b) },
}

// evaluateExpression evaluates the DWARF expression, the initial values are pushed into the stack first
func evaluateExpression(ctx exprContext, expr []byte, initial ...uint64) (uint64, bool) {
	m := &exprMachine{ctx: ctx, ok: true, stack: make([]uint64, 0, 8)}
	for _, v := range initial {
		m.push(v)
	}
	r := newByteReader(expr, 0)
	for m.ok && r.remaining() > 0 {
		op := r.u8()
		if fn := binaryOperations[op]; fn != nil {
			b, a := m.pop(), m.pop()
			m.push(fn(a, b))
		} else if !m.executeOperation(op, r) {
			return 0, false
		}
		if r.err != nil {
			return 0, false
		}
	}
	if !m.ok || len(m.stack) == 0 {
		return 0, false
	}
	return m.stack[len(m.stack)-1], true
}

func (m *exprMachine) executeOperation(op uint8, r *byteReader) bool {
	switch {
	case op >= opLit0 && op <= opLit31:
		m.push(uint64(op - opLit0))
		return true
	case op >= opBreg0 && op <= opBreg31:
		m.pushRegister(int(op-opBreg0), r.sleb())
		return true
	case op == opBregx:
		reg := r.uleb()
		m.pushRegister(int(reg), r.sleb())
		return true
	}
	if v, ok := readConstant(op, r); ok {
		m.push(v)
		return true
	}
	return m.executeStackOperation(op, r)
}

func (m *exprMachine) executeStackOperation(op uint8, r *byteReader) bool {
	switch op {
	case opDeref:
		v, ok := m.ctx.readMemory(m.pop())
		if !ok {
			return false
		}
		m.push(v)
	case opDup:
		v := m.pop()
		m.push(v)
		m.push(v)
	case opDrop:
		m.pop()
	case opOver:
		if len(m.stack) < 2 {
			return false
		}
		m.push(m.stack[len(m.stack)-2])
	case opSwap:
		b, a := m.pop(), m.pop()
		m.push(b)
		m.push(a)
	case opNeg:
		m.push(uint64(-int64(m.pop())))
	case opNot:
		m.push(^m.pop())
	case opPlusUconst:
		m.push(m.pop() + r.uleb())
	case opNop:
	default:
		return false
	}
	return true
}

func (m *exprMachine) pushRegister(reg int, offset int64) {
	v, ok := m.ctx.register(reg)
	if !ok {
		m.ok = false
		return
	}
	m.push(v + uint64(offset))
}

func readConstant(op uint8, r *byteReader) (uint64, bool) {
	switch op {
	case opConst1u:
		return uint64(r.u8()), true
	case opConst1s:
		return uint64(int64(int8(r.u8()))), true
	case opConst2u:
		return uint64(r.u16()), true
	case opConst2s:
		return uint64(int64(int16(r.u16()))), true
	case opConst4u:
		return uint64(r.u32()), true
	case opConst4s:
		return uint64(int64(int32(r.u32()))), true
	case opConst8u, opConst8s:
		return r.u64(), true
	case opConstu:
		return r.uleb(), true
	case opConsts:
		return uint64(r.sleb()), true
	}
	return 0, false
}
