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
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	extendedLengthMark = 0xffffffff
	// maxInstructionsSize is the max size of the call frame instructions of a CIE/FDE, protect from the bad data,
	// the real toolchains only generate dozens of bytes for each function
	maxInstructionsSize = 64 * 1024
	// pcCacheLimit is the max count of the cached addresses in the frame table
	pcCacheLimit = 8192
	// rowCacheLimit is the max count of the cached rows in the frame table, the addresses in the same row share it
	rowCacheLimit = 512
	// framePointerRatioThreshold is the min ratio of the functions which define the CFA by the frame pointer,
	// the ELF file built with the frame pointer is about 0.4-0.7, and less than 0.05 when built without the frame pointer
	framePointerRatioThreshold = 0.2
	// cfiCoverageThreshold is the min ratio of the code covered by the call frame information,
	// some libraries only have a few entries(such as the musl libc built with -fno-asynchronous-unwind-tables)
	cfiCoverageThreshold = 0.5
)

// cie is the Common Information Entry of the call frame information
type cie struct {
	codeAlign   uint64
	dataAlign   int64
	raReg       int
	fdeEnc      uint8
	hasAugData  bool
	signalFrame bool
	// the range of the initial instructions in the section data
	insStart, insEnd int
	// initial is the rules after executing the initial instructions
	initial        Row
	initialFPBased bool
}

// fde is the Frame Description Entry, which describe how to unwind a function
type fde struct {
	start, end uint64
	cie        *cie
	// the range of the call frame instructions in the section data
	insStart, insEnd int
}

// FrameTable is the parsed .eh_frame section of an ELF file
type FrameTable struct {
	arch        *Arch
	data        []byte
	sectionAddr uint64
	fdes        []*fde

	// pcRows caches the rule row of the addresses, the addresses in the same row share the same instance in rows
	rowLock sync.Mutex
	pcRows  map[uint64]*Row
	rows    map[uint64]*Row

	keepsFramePointerOnce sync.Once
	keepsFramePointer     bool

	// codeSize is the total size of the executable sections, zero means unknown
	codeSize uint64
}

// ParseEHFrame parsing the .eh_frame section data, the sectionAddr is the virtual address of the section
func ParseEHFrame(arch *Arch, data []byte, sectionAddr uint64) (*FrameTable, error) {
	table := &FrameTable{
		arch:        arch,
		data:        data,
		sectionAddr: sectionAddr,
		pcRows:      make(map[uint64]*Row),
		rows:        make(map[uint64]*Row),
	}
	cies := make(map[int]*cie)
	offset := 0
	for offset+4 <= len(data) {
		r := newByteReader(data, offset)
		length := uint64(r.u32())
		if length == 0 {
			// zero terminator
			break
		}
		if length == extendedLengthMark {
			length = r.u64()
		}
		entryStart := r.pos
		if r.err != nil || length > uint64(len(data)-entryStart) {
			return nil, fmt.Errorf("invalid entry length at offset 0x%x", offset)
		}
		entryEnd := entryStart + int(length)
		if id := r.u32(); id != 0 {
			// FDE, the id is the relative offset from the current position back to the CIE,
			// only skip the bad entry, the other entries are still useful
			if f, err := table.loadFDE(r, cies, entryStart-int(id), entryEnd); err != nil {
				log.Debugf("skip the bad FDE at offset 0x%x: %v", offset, err)
			} else if f != nil {
				table.fdes = append(table.fdes, f)
			}
		}
		offset = entryEnd
	}

	sort.Slice(table.fdes, func(i, j int) bool {
		return table.fdes[i].start < table.fdes[j].start
	})
	return table, nil
}

func (t *FrameTable) loadFDE(r *byteReader, cies map[int]*cie, cieOffset, entryEnd int) (*fde, error) {
	c, err := t.loadCIE(cies, cieOffset)
	if err != nil {
		return nil, fmt.Errorf("parsing CIE(0x%x) failure: %v", cieOffset, err)
	}
	return t.parseFDE(r, c, entryEnd)
}

// loadCIE parses the CIE once, the bad CIE is cached as nil
func (t *FrameTable) loadCIE(cies map[int]*cie, offset int) (*cie, error) {
	if c, exist := cies[offset]; exist {
		if c == nil {
			return nil, errBadCIE
		}
		return c, nil
	}
	c, err := t.parseCIE(offset)
	if err == nil && !initCIE(t, c) {
		err = errBadCIE
	}
	if err != nil {
		cies[offset] = nil
		return nil, err
	}
	cies[offset] = c
	return c, nil
}

func (t *FrameTable) parseCIE(offset int) (*cie, error) {
	if offset < 0 || offset >= len(t.data) {
		return nil, errOutOfRange
	}
	r := newByteReader(t.data, offset)
	length := uint64(r.u32())
	if length == extendedLengthMark {
		length = r.u64()
	}
	entryStart := r.pos
	if r.err != nil || length > uint64(len(t.data)-entryStart) {
		return nil, errOutOfRange
	}
	entryEnd := entryStart + int(length)
	if id := r.u32(); id != 0 {
		return nil, fmt.Errorf("the entry is not a CIE")
	}
	version := r.u8()
	augmentation := r.cstring()
	if strings.Contains(augmentation, "eh") {
		r.u64()
	}
	if version >= 4 {
		// address size and segment selector size
		r.u8()
		r.u8()
	}
	c := &cie{fdeEnc: pePtrAbs}
	c.codeAlign = r.uleb()
	c.dataAlign = r.sleb()
	if version == 1 {
		c.raReg = int(r.u8())
	} else {
		c.raReg = int(r.uleb())
	}
	if strings.HasPrefix(augmentation, "z") {
		c.hasAugData = true
		augLength := int(r.uleb())
		augEnd := r.pos + augLength
		parseAugmentation(r, c, augmentation[1:])
		r.pos = augEnd
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.pos > entryEnd || entryEnd-r.pos > maxInstructionsSize {
		return nil, errOutOfRange
	}
	c.insStart, c.insEnd = r.pos, entryEnd
	return c, nil
}

func parseAugmentation(r *byteReader, c *cie, augmentation string) {
	for _, ch := range augmentation {
		switch ch {
		case 'L':
			r.u8()
		case 'P':
			// the personality routine is never used for unwinding, only skip its value
			r.encodedValue(r.u8())
		case 'R':
			c.fdeEnc = r.u8()
		case 'S':
			c.signalFrame = true
		case 'B', 'G':
			// no data
		default:
			// unknown augmentation, the remaining data would be skipped by the augmentation length
			return
		}
	}
}

func (t *FrameTable) parseFDE(r *byteReader, c *cie, entryEnd int) (*fde, error) {
	start := r.encodedPointer(c.fdeEnc, t.sectionAddr)
	length := r.encodedValue(c.fdeEnc)
	if c.hasAugData {
		augLength := int(r.uleb())
		r.pos += augLength
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.pos > entryEnd || entryEnd-r.pos > maxInstructionsSize {
		return nil, errOutOfRange
	}
	// ignore the discarded functions
	if start == 0 || length == 0 {
		return nil, nil
	}
	return &fde{start: start, end: start + length, cie: c, insStart: r.pos, insEnd: entryEnd}, nil
}

func (t *FrameTable) findFDE(pc uint64) *fde {
	idx := sort.Search(len(t.fdes), func(i int) bool {
		return t.fdes[i].start > pc
	}) - 1
	if idx < 0 {
		return nil
	}
	f := t.fdes[idx]
	if pc >= f.end {
		return nil
	}
	return f
}

// FindRow finds the unwind rule row of the address(ELF virtual address), returns nil if not found
func (t *FrameTable) FindRow(pc uint64) *Row {
	t.rowLock.Lock()
	row, exist := t.pcRows[pc]
	t.rowLock.Unlock()
	if exist {
		return row
	}

	var rowStart uint64
	if f := t.findFDE(pc); f != nil {
		row, rowStart = executeCFI(t, f, pc)
	}

	t.rowLock.Lock()
	defer t.rowLock.Unlock()
	if len(t.pcRows) >= pcCacheLimit || len(t.rows) >= rowCacheLimit {
		t.pcRows = make(map[uint64]*Row)
		t.rows = make(map[uint64]*Row)
	}
	if row != nil {
		// the rows of different FDEs never start at the same address
		if shared := t.rows[rowStart]; shared != nil {
			row = shared
		} else {
			t.rows[rowStart] = row
		}
	}
	t.pcRows[pc] = row
	return row
}

// KeepsFramePointer checks the ELF file is built with the frame pointer,
// by the ratio of the functions which define the CFA by the frame pointer
func (t *FrameTable) KeepsFramePointer() bool {
	t.keepsFramePointerOnce.Do(func() {
		fpBased := 0
		for _, f := range t.fdes {
			if usesFramePointer(t, f) {
				fpBased++
			}
		}
		total := len(t.fdes)
		t.keepsFramePointer = total > 0 && float64(fpBased)/float64(total) >= framePointerRatioThreshold
	})
	return t.keepsFramePointer
}

// HasCallFrameInformation checks most of the code is covered by the call frame information,
// otherwise unwinding by the call frame information couldn't help this ELF file
func (t *FrameTable) HasCallFrameInformation() bool {
	if len(t.fdes) == 0 {
		return false
	}
	if t.codeSize == 0 {
		return true
	}
	var covered uint64
	for _, f := range t.fdes {
		covered += f.end - f.start
	}
	return float64(covered)/float64(t.codeSize) >= cfiCoverageThreshold
}
