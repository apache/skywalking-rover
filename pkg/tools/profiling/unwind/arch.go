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
	"runtime"
	"sync"
)

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
	// FrameRecordAtCFA is true when the frame record(previous frame pointer and return address) is always
	// saved right below the CFA, then the caller's stack pointer could be recovered by the frame pointer
	FrameRecordAtCFA bool
}

var (
	// ArchAMD64 is the x86_64 architecture, the return address column is the pseudo register 16(RIP)
	ArchAMD64 = &Arch{Name: "amd64", SP: 7, FP: 6, LR: -1, PC: 16, AddressMask: ^uint64(0), FrameRecordAtCFA: true}
	// ArchARM64 is the aarch64 architecture with 48-bit user virtual address, the return address is stored in the X30(LR),
	// the pointer authentication code is stored in the bits above the virtual address size
	ArchARM64 = newARM64Arch(48)

	currentArchOnce sync.Once
	currentArch     *Arch
)

func newARM64Arch(vaBits uint) *Arch {
	return &Arch{Name: "arm64", SP: 31, FP: 29, LR: 30, PC: -1, AddressMask: (uint64(1) << vaBits) - 1}
}

// CurrentArch returns the architecture of the running rover, nil if it is not supported
func CurrentArch() *Arch {
	currentArchOnce.Do(func() {
		switch runtime.GOARCH {
		case ArchAMD64.Name:
			currentArch = ArchAMD64
		case "arm64":
			// the pointer authentication mask depends on the user virtual address size of the kernel(48 or 52 bits)
			currentArch = newARM64Arch(userAddressBits())
		}
	})
	return currentArch
}
