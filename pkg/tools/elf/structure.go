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

type StructureInfo struct {
	name string
	// size is DW_AT_byte_size: needed by callers that must copy or bounds check a whole
	// struct(a uprobe copying a fixed window out of a monitored process, say), not just read
	// one member out of it.
	size   int
	fields []*StructureFieldInfo
}

func (s *StructureInfo) Name() string {
	return s.name
}

// Size is the total byte size of the structure.
func (s *StructureInfo) Size() int {
	return s.size
}

// Fields returns every member of the structure, in the order the debug info declared them.
// Callers that transcribe a whole type - rather than reading one known member - need this.
func (s *StructureInfo) Fields() []*StructureFieldInfo {
	return s.fields
}

func (s *StructureInfo) GetField(name string) *StructureFieldInfo {
	for _, f := range s.fields {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// HasFields reports whether the structure declares every named member.
//
// A DWARF type name is not unique: Rust in particular emits types under their SHORT name, so one
// binary can hold several different structs called `Spiffe`. The member set is what actually
// identifies the type, so callers that care which one they got select on this rather than on the
// name alone - and a type that RENAMED a member fails the test instead of silently matching.
func (s *StructureInfo) HasFields(names ...string) bool {
	for _, n := range names {
		if s.GetField(n) == nil {
			return false
		}
	}
	return true
}

type StructureFieldInfo struct {
	Name   string
	Offset int64
}
