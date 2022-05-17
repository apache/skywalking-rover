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
	"debug/elf"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/tools/path"
)

// GoLibrary is using build-in elf reader to read
type GoLibrary struct {
}

func NewGoLibrary() *GoLibrary {
	return &GoLibrary{}
}

func (l *GoLibrary) IsSupport(filePath string) bool {
	f, err := elf.Open(filePath)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func (l *GoLibrary) AnalyzeSymbols(filePath string) ([]*Symbol, error) {
	// read els file
	file, err := elf.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// exist symbol data
	symbols, symError := file.Symbols()
	dySyms, dyError := file.DynamicSymbols()
	if len(symbols) == 0 && len(dySyms) == 0 {
		symError = multierror.Append(symError, dyError)
		return nil, symError
	}
	symbols = append(symbols, dySyms...)

	// adapt symbol struct
	data := make([]*Symbol, len(symbols))
	for i, sym := range symbols {
		data[i] = &Symbol{Name: sym.Name, Location: sym.Value}
	}

	sort.SliceStable(data, func(i, j int) bool {
		return data[i].Location < data[j].Location
	})

	return data, nil
}

func (l *GoLibrary) ToModule(pid int32, modName, modPath string, moduleRange []*ModuleRange) (*Module, error) {
	res := &Module{}
	res.Name = modName
	res.Path = modPath
	res.Ranges = moduleRange
	file, err := elf.Open(modPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	header := file.FileHeader
	mType := ModuleTypeUnknown
	switch header.Type {
	case elf.ET_EXEC:
		mType = ModuleTypeExec
	case elf.ET_DYN:
		mType = ModuleTypeSo
	}

	if mType == ModuleTypeUnknown {
		if strings.HasSuffix(modPath, ".map") && path.Exists(modPath) {
			mType = ModuleTypePerfMap
		} else if modName == "[vdso]" {
			mType = ModuleTypeVDSO
		}
	} else if mType == ModuleTypeSo {
		section := file.Section(".text")
		if section == nil {
			return nil, fmt.Errorf("could not found .text section in so file: %s", modName)
		}
		res.SoAddr = section.Addr
		res.SoOffset = section.Offset
	}
	res.Type = mType

	// load all symbols
	res.Symbols, err = l.AnalyzeSymbols(modPath)
	if err != nil {
		return nil, err
	}

	return res, nil
}
