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
	"testing"
)

// the note bytes here were captured from a real istio/ztunnel:1.29.0 image, so this pins the
// parser against an actual binary rather than a synthetic note
func TestParseBuildIDNote(t *testing.T) {
	raw, err := hex.DecodeString("040000001400000003000000474e550090b4ef913a502003bf70f6f1265305a2131b03aa")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseBuildIDNote(raw, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	const want = "90b4ef913a502003bf70f6f1265305a2131b03aa"
	if got != want {
		t.Fatalf("build id = %s; want %s", got, want)
	}
}

// A note section can hold several notes; the build id must be found past an unrelated one rather
// than only when it happens to come first.
func TestParseBuildIDNoteSkipsOtherNotes(t *testing.T) {
	abiTag := make([]byte, noteHeaderSize+4+16)
	binary.LittleEndian.PutUint32(abiTag[0:4], 4)
	binary.LittleEndian.PutUint32(abiTag[4:8], 16)
	binary.LittleEndian.PutUint32(abiTag[8:12], 1)
	copy(abiTag[12:16], "GNU\x00")

	buildID, err := hex.DecodeString("040000001400000003000000474e550090b4ef913a502003bf70f6f1265305a2131b03aa")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseBuildIDNote(append(abiTag, buildID...), binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if got != "90b4ef913a502003bf70f6f1265305a2131b03aa" {
		t.Fatalf("build id = %s; want the note that follows the ABI tag", got)
	}
}

func TestParseBuildIDNoteMissing(t *testing.T) {
	// a note section carrying only an NT_GNU_ABI_TAG(type 1) has no build id
	raw := make([]byte, noteHeaderSize+4+16)
	binary.LittleEndian.PutUint32(raw[0:4], 4)
	binary.LittleEndian.PutUint32(raw[4:8], 16)
	binary.LittleEndian.PutUint32(raw[8:12], 1)
	copy(raw[12:16], "GNU\x00")
	if _, err := parseBuildIDNote(raw, binary.LittleEndian); err == nil {
		t.Fatal("expected an error when no NT_GNU_BUILD_ID note is present")
	}
}

// A truncated descriptor must not be read past the end of the section.
func TestParseBuildIDNoteTruncated(t *testing.T) {
	raw := make([]byte, noteHeaderSize+4)
	binary.LittleEndian.PutUint32(raw[0:4], 4)
	binary.LittleEndian.PutUint32(raw[4:8], 20)
	binary.LittleEndian.PutUint32(raw[8:12], noteTypeGNUBuildID)
	copy(raw[12:16], "GNU\x00")
	if _, err := parseBuildIDNote(raw, binary.LittleEndian); err == nil {
		t.Fatal("expected an error when the descriptor is truncated")
	}
}
