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

import "runtime"

// maxRegisters is the size of the register file tracked while unwinding,
// it covers all the DWARF registers which are used by the CFI on x86_64(0-16) and arm64(0-31)
const maxRegisters = 34

// Arch describes the DWARF register numbers of the architecture
type Arch struct {
	Name string
	// SP is the DWARF register number of the stack pointer
	SP int
	// FP is the DWARF register number of the frame pointer
	FP int
	// LR is the DWARF register number of the link register, -1 if the architecture doesn't have it
	LR int
	// PC is the DWARF register number of the program counter which could be referenced by the expression,
	// -1 if the architecture doesn't have it
	PC int
	// AddressMask is used to strip the non-address bits (such as pointer authentication) from the return address
	AddressMask uint64
}

var (
	// ArchAMD64 is the x86_64 architecture, the return address column is the pseudo register 16(RIP)
	ArchAMD64 = &Arch{Name: "amd64", SP: 7, FP: 6, LR: -1, PC: 16, AddressMask: ^uint64(0)}
	// ArchARM64 is the aarch64 architecture, the return address is stored in the X30(LR)
	ArchARM64 = &Arch{Name: "arm64", SP: 31, FP: 29, LR: 30, PC: -1, AddressMask: (uint64(1) << 48) - 1}
)

// CurrentArch returns the architecture of the running rover, nil if it is not supported
func CurrentArch() *Arch {
	for _, arch := range []*Arch{ArchAMD64, ArchARM64} {
		if arch.Name == runtime.GOARCH {
			return arch
		}
	}
	return nil
}
