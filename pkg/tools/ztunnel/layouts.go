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
	"reflect"
	"sort"
	"strings"
)

// The Rust types the identity probe reads, and the fields it currently needs from them. Names are
// exactly what rustc records in DWARF, so a table entry can be read against ztunnel's own source.
// The Rust types the identity probe reads. The FIELDS of each type, and how each maps to a
// resolved offset, are declared once as `zt` tags on the Offsets struct(see offsets.go) and read
// back through schema(); this file no longer keeps a parallel list of field-name constants.
const (
	TypeConnectionResult    = "ConnectionResult"
	TypeCommonTrafficLabels = "CommonTrafficLabels"
	TypeIdentitySpiffe      = "Identity::Spiffe"
)

// TypeLayout is one Rust type as rustc laid it out: its total size and the byte offset of every
// field, relative to the start of that type.
//
// Offsets are stored PER TYPE rather than pre-composed into absolute positions so the record
// stays a faithful transcription of the debug info. Composing `ConnectionResult.tl` with a field
// of `CommonTrafficLabels` is the reader's job(see Layouts.Resolve), which keeps a stored entry
// meaningful on its own and lets a reader compose paths the generator never anticipated.
type TypeLayout struct {
	Size   int            `json:"size"`
	Fields map[string]int `json:"fields"`
}

// Offset returns a field's offset within its type.
func (t *TypeLayout) Offset(field string) (int, bool) {
	if t == nil {
		return 0, false
	}
	offset, ok := t.Fields[field]
	return offset, ok
}

// Layouts records every type the extractor captured, keyed by the Rust type name.
//
// The extractor deliberately stores ALL fields of each type, not only the ones read today: a
// later agent that needs `destination_service` or `source_app` can use it against tables that
// already shipped, instead of every new field requiring the whole table to be regenerated.
type Layouts map[string]*TypeLayout

// Validate checks that the layouts describe the types the identity probe needs, with every field
// it reads present and plausibly placed. It runs before any layout is used, so a truncated or
// hand-edited entry is refused up front rather than producing wrong reads later.
func (l Layouts) Validate() error {
	for _, typeName := range schema().typeOrder {
		layout := l[typeName]
		if layout == nil {
			return fmt.Errorf("no layout recorded for %s", typeName)
		}
		if layout.Size <= 0 || layout.Size > maxWindow {
			return fmt.Errorf("%s has an implausible size %d", typeName, layout.Size)
		}
		for _, field := range schema().byType[typeName].fields {
			offset, ok := layout.Offset(field)
			if !ok {
				return fmt.Errorf("%s has no field %q", typeName, field)
			}
			if offset < 0 || offset >= layout.Size {
				return fmt.Errorf("%s.%s offset %d is outside the %d byte type",
					typeName, field, offset, layout.Size)
			}
		}
	}
	return nil
}

// Resolve composes the stored per-type layouts into the flat, absolute offsets the probe decoder
// works with. This is where `tl` is folded in, so nothing downstream has to know that the traffic
// labels are embedded inside ConnectionResult.
func (l Layouts) Resolve() (*Offsets, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	// every CommonTrafficLabels field is reported relative to ConnectionResult, because that is the
	// pointer the probe copies; rebase them by the tl offset so nothing downstream adds two numbers
	labelBase, _ := l[TypeConnectionResult].Offset(trafficLabelsField)
	base := func(typeName string) int {
		if typeName == TypeCommonTrafficLabels {
			return labelBase
		}
		return 0
	}

	offsets := &Offsets{
		Source:             OffsetSourceTable,
		Window:             l[TypeConnectionResult].Size,
		HasDirection:       true,
		IdentitySpiffeSize: l[TypeIdentitySpiffe].Size,
	}
	dst := reflect.ValueOf(offsets).Elem()
	for _, f := range schema().fields {
		offset, ok := l[f.typeName].Offset(f.field)
		if !ok {
			// Validate already guarantees presence, so a gap here is a resolution bug, not a miss.
			return nil, fmt.Errorf("%s.%s went missing during resolution", f.typeName, f.field)
		}
		dst.Field(f.index).SetInt(int64(offset + base(f.typeName)))
	}

	if err := offsets.Validate(); err != nil {
		return nil, fmt.Errorf("the resolved offsets are not usable: %w", err)
	}
	return offsets, nil
}

// Fingerprint is a stable string identifying one set of layouts, used to coalesce table entries
// whose binaries share a layout. It is derived from the layouts themselves rather than from their
// JSON encoding, so map ordering cannot make two identical layouts look different.
func (l Layouts) Fingerprint() string {
	typeNames := make([]string, 0, len(l))
	for typeName := range l {
		typeNames = append(typeNames, typeName)
	}
	sort.Strings(typeNames)

	var sb strings.Builder
	for _, typeName := range typeNames {
		layout := l[typeName]
		fmt.Fprintf(&sb, "%s(%d){", typeName, layout.Size)
		fields := make([]string, 0, len(layout.Fields))
		for field := range layout.Fields {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			fmt.Fprintf(&sb, "%s=%d,", field, layout.Fields[field])
		}
		sb.WriteString("}")
	}
	return sb.String()
}
