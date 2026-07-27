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
	"reflect"
	"strings"
	"sync"
)

// trafficLabelsField is the ConnectionResult field that embeds CommonTrafficLabels. Every
// CommonTrafficLabels offset is rebased onto ConnectionResult by adding this field's offset, so a
// consumer never composes two numbers. It is structural(true for every ztunnel measured), not a
// per-field mapping, so it lives here rather than as a tag.
const trafficLabelsField = "tl"

// offsetField is one `zt`-tagged field of Offsets: which Offsets field(by struct index) is filled
// from which Rust type and field.
type offsetField struct {
	index    int
	typeName string
	field    string
}

// schemaType is one Rust type the offsets reference, with the fields referenced on it. The field
// set doubles as the DWARF identifying members(so a renamed field fails the lookup instead of
// silently matching another type) and as the set layout validation requires to be present.
type schemaType struct {
	name   string
	fields []string
}

// offsetSchema is the parsed `zt` tag layout of Offsets - the single source of truth extraction,
// validation and resolution all read.
type offsetSchema struct {
	fields    []offsetField
	typeOrder []string
	byType    map[string]*schemaType
}

var (
	schemaOnce   sync.Once
	parsedSchema *offsetSchema
)

// schema parses the Offsets struct tags once and caches the result.
func schema() *offsetSchema {
	schemaOnce.Do(func() { parsedSchema = parseSchema(reflect.TypeOf(Offsets{})) })
	return parsedSchema
}

// parseSchema reads the `zt` tags off a struct type. A malformed tag is a programming error in
// this package - the struct is a compile-time constant - so it panics rather than returning an
// error nobody could handle at runtime.
func parseSchema(t reflect.Type) *offsetSchema {
	s := &offsetSchema{byType: map[string]*schemaType{}}
	add := func(typeName string) *schemaType {
		st := s.byType[typeName]
		if st == nil {
			st = &schemaType{name: typeName}
			s.byType[typeName] = st
			s.typeOrder = append(s.typeOrder, typeName)
		}
		return st
	}
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("zt")
		if tag == "" || tag == "-" {
			continue
		}
		typeName, field, ok := strings.Cut(tag, ".")
		if !ok || typeName == "" || field == "" {
			panic("ztunnel: malformed zt tag " + tag + " on Offsets." + t.Field(i).Name)
		}
		s.fields = append(s.fields, offsetField{index: i, typeName: typeName, field: field})
		st := add(typeName)
		st.fields = append(st.fields, field)
	}
	// CommonTrafficLabels is embedded in ConnectionResult at trafficLabelsField; resolution needs
	// that offset as the rebase, so it must be extracted and validated even though no Offsets field
	// maps to it directly.
	if st := s.byType[TypeConnectionResult]; st != nil && !contains(st.fields, trafficLabelsField) {
		st.fields = append(st.fields, trafficLabelsField)
	}
	return s
}

// dwarfName is what rustc records for a recorded type name: the last "::"-separated segment, since
// DWARF carries only the bare variant name(Identity::Spiffe is "Spiffe") while the table records
// the qualified name for readability.
func dwarfName(recorded string) string {
	if i := strings.LastIndex(recorded, "::"); i >= 0 {
		return recorded[i+2:]
	}
	return recorded
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
