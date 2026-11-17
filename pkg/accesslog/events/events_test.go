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

package events

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/btf"

	"github.com/stretchr/testify/assert"
)

// nolint
func TestBufferRead(t *testing.T) {
	tests := []struct {
		hex    string
		create func() btf.EventReader
		// binaryTarget and narrow are set for an event whose Go fields are deliberately wider than the
		// kernel struct: binary.Read fills a twin with the kernel widths, and narrow turns the parsed
		// event back into that twin, so the guard still covers both the order and the width of every field
		binaryTarget func() any
		narrow       func(btf.EventReader) any
	}{
		{
			hex: `
04 00 00 00 7a a1 00 00 4e 56 83 76 00 00 00 00
47 3b e1 7a 5a 30 02 00 a6 bd e1 7a 5a 30 02 00
7a a1 00 00 04 00 00 00 02 02 0a 01 00 00 00 00
00 00 00 00 a0 b4 00 00 00 00 00 00 00 00 00 00
00 00 ff ff 7f 00 00 01 00 00 00 00 fb 20 00 00
00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00`,
			create: func() btf.EventReader {
				return &SocketConnectEvent{}
			},
		},
		{
			hex: `
04 00 00 00 7a a1 00 00 4e 56 83 76 00 00 00 00
b2 2d 26 7c 5a 30 02 00 5e 34 26 7c 5a 30 02 00
7a a1 00 00 04 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00`,
			create: func() btf.EventReader {
				return &SocketCloseEvent{}
			},
		},
	}

	for _, test := range tests {
		t.Run(reflect.TypeOf(test.create()).String(), func(t *testing.T) {
			test.hex = strings.ReplaceAll(test.hex, "\n", "")
			test.hex = strings.ReplaceAll(test.hex, " ", "")
			rawData, err := hex.DecodeString(test.hex)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
				return
			}
			binaryRead := any(test.create())
			if test.binaryTarget != nil {
				binaryRead = test.binaryTarget()
			}
			selfRead := test.create()
			bufReader := btf.NewReader(rawData)
			selfRead.ReadFrom(bufReader)
			if err := bufReader.HasError(); err != nil {
				t.Fatalf("reading by self parsing error: %v", err)
			}
			if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, binaryRead); err != nil {
				t.Fatalf("reading buffer error: %v", err)
			}
			// self parsing should same with binary.Read
			parsed := any(selfRead)
			if test.narrow != nil {
				parsed = test.narrow(selfRead)
			}
			assert.Equal(t, parsed, binaryRead)
		})
	}
}
