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
	"debug/dwarf"
	"encoding/binary"
	"fmt"
)

var ReaderLanguageGolang = 22

type DwarfReader struct {
	elfByteOrder binary.ByteOrder

	producer  string
	language  int
	functions map[string]*FunctionInfo
	// structures holds EVERY definition seen under a name, in the order they were read. A DWARF
	// name does not identify a type on its own - Rust records types under their short name, so
	// one binary can carry several distinct structs called `Spiffe` - so callers that care which
	// one they get select by member set(see FindStructure), and GetStructure keeps returning the
	// first definition for those that do not.
	structures map[string][]*StructureInfo
	classes    map[string]*ClassInfo
}

func (f *File) NewDwarfReader(attrNames ...string) (*DwarfReader, error) {
	data, err := f.realFile.DWARF()
	if err != nil {
		return nil, err
	}
	reader := &DwarfReader{}
	if err := reader.init(data, attrNames); err != nil {
		return nil, err
	}
	return reader, nil
}

func (r *DwarfReader) GetFunction(name string) *FunctionInfo {
	return r.functions[name]
}

// GetStructure returns the first definition read under a name. Prefer FindStructure whenever
// the name could be ambiguous.
func (r *DwarfReader) GetStructure(name string) *StructureInfo {
	if defined := r.structures[name]; len(defined) > 0 {
		return defined[0]
	}
	return nil
}

// GetStructures returns every definition read under a name.
func (r *DwarfReader) GetStructures(name string) []*StructureInfo {
	return r.structures[name]
}

// FindStructure returns the definition of name that declares every member in requiredMembers.
//
// This is the lookup to use for any type whose name is ambiguous, which for Rust binaries is
// most of them: rustc records types under their short name, so a single binary holds several
// unrelated structs called `Spiffe` or `Inner`. Selecting on the member set picks the intended
// one, and makes a type whose members were RENAMED fail the lookup rather than quietly match a
// different type's offsets.
func (r *DwarfReader) FindStructure(name string, requiredMembers ...string) *StructureInfo {
	for _, structure := range r.structures[name] {
		if structure.HasFields(requiredMembers...) {
			return structure
		}
	}
	return nil
}

func (r *DwarfReader) GetStructMemberOffset(structName, memberName string) (uint64, error) {
	structure := r.GetStructure(structName)
	if structure == nil {
		return 0, fmt.Errorf("the struct not found: %s", structName)
	}
	field := structure.GetField(memberName)
	if field == nil {
		return 0, fmt.Errorf("the field not found, struct name: %s, member name: %s", structName, memberName)
	}
	return uint64(field.Offset), nil
}

func (r *DwarfReader) GetClassParentOffset(className, parentClassName string) (uint64, error) {
	class := r.GetClass(className)
	if class == nil {
		return 0, fmt.Errorf("the class not found: %s", className)
	}
	offset := class.GetInheritanceOffset(parentClassName)
	if offset >= 0 {
		return uint64(offset), nil
	}
	return 0, fmt.Errorf("the parent class not found, class: %s, parent: %s", className, parentClassName)
}

func (r *DwarfReader) GetClassMemberOffset(className, memberName string) (uint64, error) {
	class := r.GetClass(className)
	if class == nil {
		return 0, fmt.Errorf("the class not found: %s", className)
	}
	offset := class.GetMemberOffset(memberName)
	if offset >= 0 {
		return uint64(offset), nil
	}
	return 0, fmt.Errorf("the member not found, class: %s, member: %s", className, memberName)
}

func (r *DwarfReader) GetClass(name string) *ClassInfo {
	return r.classes[name]
}

func (r *DwarfReader) init(data *dwarf.Data, readAttrNames []string) error {
	r.functions = make(map[string]*FunctionInfo)
	r.structures = make(map[string][]*StructureInfo)
	r.classes = make(map[string]*ClassInfo)

	reader := data.Reader()
	r.elfByteOrder = reader.ByteOrder()
	for {
		entry, err := reader.Next()
		if err != nil {
			return fmt.Errorf("read dwarf error: %v", err)
		}
		if entry == nil {
			break
		}

		if err := r.processProducer(data, entry); err != nil {
			return err
		}
		if err := r.processFunctions(readAttrNames, data, entry); err != nil {
			return err
		}
		if err := r.processStructure(readAttrNames, data, entry); err != nil {
			return err
		}
		if err := r.processClass(readAttrNames, data, entry); err != nil {
			return err
		}
	}
	return nil
}
