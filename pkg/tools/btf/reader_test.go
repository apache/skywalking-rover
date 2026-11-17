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

package btf

import (
	"encoding/binary"
	"testing"
)

// TestBytesReaderReset: a reused reader reads every sample from its start, and an error of one sample
// is not carried to the next one
func TestBytesReaderReset(t *testing.T) {
	sample := func(values ...uint32) []byte {
		buf := make([]byte, 0, len(values)*4)
		for _, v := range values {
			buf = binary.LittleEndian.AppendUint32(buf, v)
		}
		return buf
	}
	reader := &BytesReader{}

	reader.Reset(sample(1, 2))
	if a, b := reader.ReadUint32(), reader.ReadUint32(); a != 1 || b != 2 || reader.HasError() != nil {
		t.Fatalf("read %d, %d, error: %v", a, b, reader.HasError())
	}
	reader.ReadUint32()
	if reader.HasError() == nil {
		t.Fatal("reading past the sample must fail")
	}

	reader.Reset(sample(3))
	if v := reader.ReadUint32(); v != 3 || reader.HasError() != nil {
		t.Fatalf("a reset reader must read the new sample from its start, read %d, error: %v", v, reader.HasError())
	}
	expected := NewReader(sample(3)).(*BytesReader)
	expected.ReadUint32()
	if reader.CurrentOffset != expected.CurrentOffset || reader.sampleLen != expected.sampleLen || reader.err != expected.err {
		t.Fatalf("a reset reader must be the same as a new one, got %+v, expected %+v", *reader, *expected)
	}
}
