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

package profiling

import (
	"github.com/ianlancetaylor/demangle"
)

type ModuleType int8

var (
	KernelSymbolFilePath = "/proc/kallsyms"
)

const (
	ModuleTypeExec ModuleType = iota
	ModuleTypeSo
	ModuleTypePerfMap
	ModuleTypeVDSO
	ModuleTypeUnknown
)

// Info of profiling process
type Info struct {
	Modules           []*Module
	cacheAddrToSymbol map[uint64]string
}

type Module struct {
	Ranges           []*ModuleRange
	Name             string
	Path             string
	Type             ModuleType
	SoOffset, SoAddr uint64
	Symbols          []*Symbol
}

type ModuleRange struct {
	StartAddr, EndAddr, FileOffset uint64
}

// Symbol of executable file
type Symbol struct {
	Name     string
	Location uint64
}

type StatFinder interface {
	// IsSupport to stat the executable file for profiling
	IsSupport(filePath string) bool
	// AnalyzeSymbols in the file
	AnalyzeSymbols(filePath string) ([]*Symbol, error)
	// ToModule to init a new module
	ToModule(pid int32, modName, modPath string, moduleRange []*ModuleRange) (*Module, error)
}

func NewInfo(modules map[string]*Module) *Info {
	ls := make([]*Module, 0)
	for _, m := range modules {
		ls = append(ls, m)
	}
	return &Info{Modules: ls, cacheAddrToSymbol: make(map[uint64]string)}
}

// FindSymbols from address list, if could not found symbol name then append default symbol to array
func (i *Info) FindSymbols(addresses []uint64, defaultSymbol string) []string {
	if len(addresses) == 0 {
		return nil
	}
	result := make([]string, 0)
	for _, addr := range addresses {
		if addr <= 0 {
			continue
		}
		s := i.FindSymbolName(addr)
		if s == "" {
			s = defaultSymbol
		}
		result = append(result, s)
	}
	return result
}

// FindSymbolName by address
func (i *Info) FindSymbolName(address uint64) string {
	if d := i.cacheAddrToSymbol[address]; d != "" {
		return d
	}
	for _, mod := range i.Modules {
		offset, c := mod.contains(address)
		if !c {
			continue
		}

		if sym := mod.findAddr(offset); sym != nil {
			name := processSymbolName(sym.Name)
			i.cacheAddrToSymbol[address] = name
			return name
		}
	}
	return ""
}

func (m *Module) contains(addr uint64) (uint64, bool) {
	for _, r := range m.Ranges {
		if addr >= r.StartAddr && addr < r.EndAddr {
			if m.Type == ModuleTypeSo || m.Type == ModuleTypeVDSO {
				offset := addr - r.StartAddr + r.FileOffset
				offset += m.SoAddr - m.SoOffset
				return offset, true
			}
			return addr, true
		}
	}
	return 0, false
}

func (m *Module) findAddr(offset uint64) *Symbol {
	start := 0
	end := len(m.Symbols) - 1
	for start < end {
		mid := start + (end-start)/2
		result := int64(offset) - int64(m.Symbols[mid].Location)

		if result < 0 {
			end = mid
		} else if result > 0 {
			start = mid + 1
		} else {
			return m.Symbols[mid]
		}
	}

	if start >= 1 && m.Symbols[start-1].Location < offset && offset < m.Symbols[start].Location {
		return m.Symbols[start-1]
	}

	return nil
}

func processSymbolName(name string) string {
	if name == "" {
		return ""
	}
	// fix process demangle symbol name, such as c++ language symbol
	skip := 0
	if name[0] == '.' || name[0] == '$' {
		skip++
	}
	return demangle.Filter(name[skip:])
}
