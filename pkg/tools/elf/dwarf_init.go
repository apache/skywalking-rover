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
	"fmt"
)

func (r *DwarfReader) processProducer(_ *dwarf.Data, entry *dwarf.Entry) error {
	if entry.Tag != dwarf.TagCompileUnit {
		return nil
	}

	producer, ok := entry.Val(dwarf.AttrProducer).(string)
	if !ok {
		return fmt.Errorf("the producer field not exists")
	}
	language, ok := entry.Val(dwarf.AttrLanguage).(int64)
	if !ok {
		return fmt.Errorf("the language field not exists")
	}
	r.producer = producer
	r.language = int(language)
	return nil
}

func (r *DwarfReader) processFunctions(funcNames []string, data *dwarf.Data, entry *dwarf.Entry) error {
	if entry.Tag != dwarf.TagSubprogram {
		return nil
	}

	name, ok := entry.Val(dwarf.AttrName).(string)
	if !ok {
		return nil
	}

	// the function is need to read
	found := false
	for _, n := range funcNames {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	args, err := r.getFunctionArgs(data, entry)
	if err != nil {
		return err
	}

	r.functions[name] = &FunctionInfo{
		name: name,
		args: args,
	}
	return nil
}

func (r *DwarfReader) processStructure(names []string, data *dwarf.Data, entry *dwarf.Entry) error {
	if entry.Tag != dwarf.TagStructType {
		return nil
	}

	name, ok := entry.Val(dwarf.AttrName).(string)
	if !ok {
		return nil
	}

	found := false
	for _, n := range names {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	fields, err := r.getStructureFields(data, entry)
	if err != nil {
		return err
	}

	r.structures[name] = &StructureInfo{
		name:   name,
		fields: fields,
	}
	return nil
}

func (r *DwarfReader) processClass(names []string, data *dwarf.Data, entry *dwarf.Entry) error {
	if entry.Tag != dwarf.TagClassType {
		return nil
	}

	name, ok := entry.Val(dwarf.AttrName).(string)
	if !ok {
		return nil
	}
	_, ok = entry.Val(dwarf.AttrDeclaration).(bool)
	if ok {
		return nil
	}

	found := false
	for _, n := range names {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	info, err := r.getClassInfo(data, name, entry)
	if err != nil {
		return err
	}
	r.classes[name] = info

	return nil
}

func (r *DwarfReader) entryType(data *dwarf.Data, entry *dwarf.Entry) (dwarf.Type, error) {
	off, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return nil, nil
	}
	return data.Type(off)
}

func (r *DwarfReader) IsRetArgs(entry *dwarf.Entry) (bool, error) {
	isRet, ok := entry.Val(dwarf.AttrVarParam).(bool)
	if !ok {
		return false, nil
	}
	return isRet, nil
}

func (r *DwarfReader) getClassInfo(data *dwarf.Data, name string, entry *dwarf.Entry) (*ClassInfo, error) {
	reader := data.Reader()

	reader.Seek(entry.Offset)
	_, err := reader.Next()
	if err != nil {
		return nil, err
	}

	c := &ClassInfo{
		name: name,
	}

	foundMembers := false
	for {
		child, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if child == nil || child.Tag == 0 {
			break
		}

		if child.Tag == dwarf.TagInheritance {
			offset, ok := child.Val(dwarf.AttrDataMemberLoc).(int64)
			if !ok {
				continue
			}
			entryType, err1 := r.entryType(data, child)
			if err1 != nil {
				continue
			}
			structType, ok := entryType.(*dwarf.StructType)
			if !ok {
				continue
			}

			c.inheritances = append(c.inheritances, &ClassInheritance{
				name:   structType.StructName,
				cType:  structType,
				offset: uint64(offset),
			})
		}

		entryType, err := r.entryType(data, child)
		if !foundMembers && err == nil && entryType != nil {
			prtType, ok := entryType.(*dwarf.PtrType)
			if !ok {
				continue
			}
			structType, ok := prtType.Type.(*dwarf.StructType)
			if !ok {
				continue
			}
			c.members = structType.Field
			foundMembers = true
		}
	}
	return c, nil
}

func (r *DwarfReader) getStructureFields(data *dwarf.Data, entry *dwarf.Entry) ([]*StructureFieldInfo, error) {
	reader := data.Reader()
	reader.Seek(entry.Offset)
	_, err := reader.Next()
	if err != nil {
		return nil, err
	}

	res := make([]*StructureFieldInfo, 0)
	for {
		child, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if child == nil || child.Tag == 0 {
			break
		}

		if child.Tag != dwarf.TagMember {
			continue
		}

		name, ok := child.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}
		offset, ok := child.Val(dwarf.AttrDataMemberLoc).(int64)
		if !ok {
			continue
		}

		field := &StructureFieldInfo{
			Name:   name,
			Offset: offset,
		}
		res = append(res, field)
	}
	return res, nil
}

func (r *DwarfReader) getFunctionArgs(data *dwarf.Data, entry *dwarf.Entry) (map[string]*FunctionArgsInfo, error) {
	reader := data.Reader()

	reader.Seek(entry.Offset)
	_, err := reader.Next()
	if err != nil {
		return nil, err
	}

	locator := NewArgumentLocator(r)
	args := make(map[string]*FunctionArgsInfo)
	for {
		child, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if child == nil || child.Tag == 0 {
			break
		}

		if child.Tag != dwarf.TagFormalParameter {
			continue
		}
		name, ok := child.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}
		if existsArgs := args[name]; existsArgs != nil {
			continue
		}

		curArgs := &FunctionArgsInfo{}
		// data type
		dtyp, err := r.entryType(data, child)
		if err != nil {
			return nil, err
		}
		curArgs.tp = dtyp

		// Is return value
		if r.language == ReaderLanguageGolang {
			isRet, err1 := r.IsRetArgs(child)
			if err1 != nil {
				return nil, err1
			}
			curArgs.IsRet = isRet
		}

		// get location
		typeClass := r.getArgTypeClass(child, dtyp)
		byteSize := r.getArgTypeByteSize(child, dtyp)
		alignmentByteSize := r.getArgAlignmentByteSize(child, dtyp)
		primitiveFieldCount := r.getPrimitiveFieldCount(child, dtyp)
		location, err := locator.GetLocation(typeClass, byteSize, alignmentByteSize, primitiveFieldCount, curArgs.IsRet)
		if err != nil {
			return nil, err
		}
		curArgs.Location = location

		args[name] = curArgs
	}

	return args, nil
}

func (r *DwarfReader) getArgTypeClass(_ *dwarf.Entry, tp dwarf.Type) TypeClass {
	switch val := tp.(type) {
	case *dwarf.FloatType:
		return TypeClassFloat
	case *dwarf.StructType:
		res := TypeClassNone
		for _, field := range val.Field {
			memberType := r.getArgTypeClass(nil, field.Type)
			res = res.Combine(memberType)
		}
		return res
	default:
		return TypeClassInteger
	}
}

func (r *DwarfReader) getArgTypeByteSize(_ *dwarf.Entry, tp dwarf.Type) uint64 {
	basicType, ok := tp.(*dwarf.BasicType)
	if ok {
		return uint64(basicType.ByteSize)
	}

	switch val := tp.(type) {
	case *dwarf.StructType:
		return uint64(val.ByteSize)
	default:
		return 8
	}
}

func (r *DwarfReader) getArgAlignmentByteSize(_ *dwarf.Entry, tp dwarf.Type) uint64 {
	basicType, ok := tp.(*dwarf.BasicType)
	if ok {
		return uint64(basicType.ByteSize)
	}

	switch val := tp.(type) {
	case *dwarf.StructType:
		var maxSize uint64 = 1
		for _, field := range val.Field {
			curSize := r.getArgAlignmentByteSize(nil, field.Type)
			if curSize > maxSize {
				maxSize = curSize
			}
		}
		return maxSize
	default:
		return 8
	}
}

func (r *DwarfReader) getPrimitiveFieldCount(_ *dwarf.Entry, tp dwarf.Type) int {
	structType, ok := tp.(*dwarf.StructType)
	if ok {
		totalCount := 0
		for _, field := range structType.Field {
			totalCount += r.getPrimitiveFieldCount(nil, field.Type)
		}
		return totalCount
	}

	return 1
}
