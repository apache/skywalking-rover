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
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	// buildIDSectionName is where the linker records the GNU build ID.
	buildIDSectionName = ".note.gnu.build-id"
	// noteTypeGNUBuildID is NT_GNU_BUILD_ID, the note type carrying the build ID.
	noteTypeGNUBuildID = 3
	// noteHeaderSize is namesz(4) + descsz(4) + type(4).
	noteHeaderSize = 12
)

// BuildID returns the hex-encoded GNU build ID of the file.
//
// It is the only identifier that pins an executable exactly. A version string does not: a
// redistributed build can carry a version label whose code differs substantially from the
// upstream release of that number, so anything that must be tied to one specific binary - a
// table of struct field offsets, a symbol map, a cached analysis - has to key on this.
func (f *File) BuildID() (string, error) {
	section := f.realFile.Section(buildIDSectionName)
	if section == nil {
		return "", fmt.Errorf("no %s section in %s", buildIDSectionName, f.Path)
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("read %s section of %s error: %w", buildIDSectionName, f.Path, err)
	}
	id, err := parseBuildIDNote(data, f.realFile.ByteOrder)
	if err != nil {
		return "", fmt.Errorf("parse %s of %s error: %w", buildIDSectionName, f.Path, err)
	}
	return id, nil
}

// parseBuildIDNote decodes an ELF note section and returns the hex NT_GNU_BUILD_ID descriptor.
// The note layout is: namesz(4) descsz(4) type(4) name[namesz, 4-byte aligned]
// desc[descsz, 4-byte aligned].
func parseBuildIDNote(data []byte, order binary.ByteOrder) (string, error) {
	for len(data) >= noteHeaderSize {
		nameSize := order.Uint32(data[0:4])
		descSize := order.Uint32(data[4:8])
		noteType := order.Uint32(data[8:12])

		nameEnd := noteHeaderSize + alignNote(nameSize)
		descEnd := nameEnd + alignNote(descSize)
		if descEnd > len(data) {
			break
		}
		if noteType == noteTypeGNUBuildID && descSize > 0 {
			return hex.EncodeToString(data[nameEnd : nameEnd+int(descSize)]), nil
		}
		data = data[descEnd:]
	}
	return "", fmt.Errorf("no NT_GNU_BUILD_ID note found")
}

// alignNote rounds a note field size up to the 4-byte alignment the ELF note format uses.
func alignNote(v uint32) int {
	return int((v + 3) &^ 3)
}
