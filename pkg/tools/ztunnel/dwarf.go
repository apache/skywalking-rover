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

package ztunnel

import (
	"fmt"

	"github.com/apache/skywalking-rover/pkg/tools/elf"
)

// ExtractLayoutsFromDWARF mines a ztunnel binary's debug info for the layout of every type the
// identity probe reads. Which types and which identifying fields come from the Offsets tags via
// schema(), so this needs no list of its own.
//
// It records ALL fields of those types, not just the ones read today, so a later agent that needs
// another label can use a table entry that already shipped - the alternative, regenerating every
// entry whenever the probe grows a field, would mean rebuilding a debug ztunnel per release.
//
// A type's referenced fields double as the DWARF identifying members: rustc records only the bare
// name in DW_AT_name(so `Spiffe` matches both the Identity variant wanted here and an unrelated
// struct of the same name), and requiring the fields present disambiguates them - and makes a
// ztunnel that RENAMED one of them fail the lookup instead of silently matching the wrong type.
func ExtractLayoutsFromDWARF(path string) (Layouts, error) {
	file, err := elf.NewFile(path)
	if err != nil {
		return nil, fmt.Errorf("open elf %s error: %w", path, err)
	}
	defer file.Close()

	types := schema().typeOrder
	names := make([]string, 0, len(types))
	for _, typeName := range types {
		names = append(names, dwarfName(typeName))
	}
	// the reader only decodes the named types, so a large Rust binary's whole debug info does not
	// have to be materialized to read a few dozen offsets
	reader, err := file.NewDwarfReader(names...)
	if err != nil {
		return nil, fmt.Errorf("no usable debug info in %s: %w", path, err)
	}

	layouts := make(Layouts, len(types))
	for _, typeName := range types {
		identifying := schema().byType[typeName].fields
		structure := reader.FindStructure(dwarfName(typeName), identifying...)
		if structure == nil {
			return nil, fmt.Errorf("cannot find %s(identified by %v) in the debug info of %s",
				typeName, identifying, path)
		}
		layout := &TypeLayout{Size: structure.Size(), Fields: make(map[string]int)}
		for _, field := range structure.Fields() {
			layout.Fields[field.Name] = int(field.Offset)
		}
		layouts[typeName] = layout
	}

	if err := layouts.Validate(); err != nil {
		return nil, fmt.Errorf("the layouts extracted from %s are not usable: %w", path, err)
	}
	return layouts, nil
}

// ExtractOffsetsFromDWARF reads a binary's layouts and composes them into the flat offsets the
// probe decoder uses. It is the first rung of the fallback ladder - a self-built ztunnel that
// still has its .debug_* sections - and shares its implementation with the offline table
// generator, so a table can never disagree with what a live DWARF read would have produced.
func ExtractOffsetsFromDWARF(path string) (*Offsets, error) {
	layouts, err := ExtractLayoutsFromDWARF(path)
	if err != nil {
		return nil, err
	}
	offsets, err := layouts.Resolve()
	if err != nil {
		return nil, err
	}
	offsets.Source = OffsetSourceDWARF
	return offsets, nil
}
