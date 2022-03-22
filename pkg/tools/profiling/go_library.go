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
)

// GoLibrary is using build-in elf reader to read
type GoLibrary struct {
}

func NewGoLibrary() *GoLibrary {
	return &GoLibrary{}
}

func (l *GoLibrary) IsSupport(filePath string) bool {
	return true
}

func (l *GoLibrary) Analyze(filePath string) (*Info, error) {
	// read els file
	file, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("read ELF file error: %v", err)
	}
	defer file.Close()

	// exist symbol data
	symbols, err := file.Symbols()
	if err != nil || len(symbols) == 0 {
		return nil, fmt.Errorf("read symbol data failure or no symbole data: %v", err)
	}

	// adapt symbol struct
	data := make([]*Symbol, len(symbols))
	for i, sym := range symbols {
		data[i] = &Symbol{Name: sym.Name, Location: sym.Value}
	}

	return newInfo(data), nil
}
