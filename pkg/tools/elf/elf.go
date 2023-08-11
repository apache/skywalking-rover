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

package elf

import (
	"debug/elf"
	"fmt"
	"os"
)

type File struct {
	Path     string
	realFile *elf.File
}

type Symbol struct {
	Name     string
	Location uint64
	Size     uint64
}

func NewFile(path string) (*File, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	return &File{
		Path:     path,
		realFile: f,
	}, nil
}

func (f *File) Close() error {
	return f.realFile.Close()
}

func (f *File) FindSymbol(name string) *Symbol {
	symbols, _ := f.realFile.Symbols()
	dynamicSymbols, _ := f.realFile.DynamicSymbols()
	if len(symbols) == 0 && len(dynamicSymbols) == 0 {
		return nil
	}
	symbols = append(symbols, dynamicSymbols...)
	for _, s := range symbols {
		if s.Name == name {
			return &Symbol{
				Name:     name,
				Location: s.Value,
				Size:     s.Size,
			}
		}
	}
	return nil
}

func (f *File) ReadSymbolData(section string, offset, size uint64) ([]byte, error) {
	elfSection := f.realFile.Section(section)
	if elfSection == nil {
		return nil, fmt.Errorf("could not found the \"%s\" section in elf file", section)
	}

	dataOffset := offset - elfSection.Addr + elfSection.Offset
	realFile, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer realFile.Close()
	_, err = realFile.Seek(int64(dataOffset), 0)
	if err != nil {
		return nil, fmt.Errorf("seek file error: %v", err)
	}

	buffer := make([]byte, size)
	_, err = realFile.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("reading symbol data error: %v", err)
	}
	return buffer, nil
}

func (f *File) FindBaseAddressForAttach(symbolLocation uint64) uint64 {
	for _, prog := range f.realFile.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= symbolLocation && symbolLocation < (prog.Vaddr+prog.Memsz) {
			return symbolLocation - prog.Vaddr + prog.Off
		}
	}
	return 0
}
