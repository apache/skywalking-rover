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

	"github.com/stretchr/testify/assert"

	"github.com/apache/skywalking-rover/pkg/tools/btf/reader"
)

func TestBufferRead(t *testing.T) {
	tests := []struct {
		hex    string
		create func() reader.EventReader
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
			create: func() reader.EventReader {
				return &SocketConnectEvent{}
			},
		},
		{
			hex: `
04 00 00 00 7a a1 00 00 4e 56 83 76 00 00 00 00
01 00 00 00 00 00 00 00 b2 2d 26 7c 5a 30 02 00
5e 34 26 7c 5a 30 02 00 82 51 08 00 bd 64 07 00
27 15 00 00 1d 02 00 00 37 3c 00 00 00 00 00 00
23 4a 01 00 bb 49 01 00 00 00 00 00 e4 01 00 00
24 21 00 00 01 00 00 00 39 d6 00 00 00 00 00 00
03 00 00 00 00 00 00 00 02 02 00 02 02 09 01 00`,
			create: func() reader.EventReader {
				return &SocketDetailEvent{}
			},
		},
		{
			hex: `
04 00 00 00 7a a1 00 00 4e 56 83 76 00 00 00 00
b2 2d 26 7c 5a 30 02 00 5e 34 26 7c 5a 30 02 00
7a a1 00 00 04 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00`,
			create: func() reader.EventReader {
				return &SocketCloseEvent{}
			},
		},
		{
			hex: `
03 00 02 01 00 00 2a 06 9c 5c fc 7b 5a 30 02 00
20 c5 fd 7b 5a 30 02 00 04 00 00 00 7a a1 00 00
4e 56 83 76 00 00 00 00 02 00 00 00 00 00 00 00
2a 06 00 00 00 00 00 00 16 03 03 00 7a 02 00 00
76 03 03 b1 01 85 b9 ce d4 95 9d 1e 90 f5 90 c3
f5 99 70 64 ab 0f 48 a0 fa 0d 8d 69 a3 e6 6d a5
29 98 d7 20 6f a3 13 ea 3c e1 d7 20 28 1f df 94
90 27 e4 35 33 55 de 90 64 1c 3e 04 6f 8a ce c3
71 45 c0 5e 13 01 00 00 2e 00 2b 00 02 03 04 00
33 00 24 00 1d 00 20 00 f1 14 c3 d8 1c 40 01 8e
9a d7 06 93 be 1d c0 a8 dd 42 53 96 19 51 ce aa
a6 80 4c d1 cc f1 15 14 03 03 00 01 01 17 03 03
00 26 96 c9 a2 ec 5b d9 1b 81 38 a9 a1 b3 4e e3
a7 ee c2 e3 00 21 44 6a cb 05 d1 cc 3f 59 c7 67
29 f9 eb a9 b3 88 8b 43 17 03 03 03 8d cc f4 f1
0c 23 44 96 ea 11 a3 f0 1d 2f 71 e2 29 ec 1f c2
88 8a 04 a8 59 13 fe fd 45 24 aa 0b 64 b0 67 08
41 17 39 f6 c7 ad 5d 0a 94 70 d9 89 74 6a 24 5a
91 7a 8d 92 a7 66 1c f9 10 17 52 0e df 9e 4c 24
b4 23 1c bb 0c 78 a6 bb 8a 97 46 27 45 ae 3e 01
83 12 ac 8a 75 12 68 f3 91 37 7e ae a8 41 61 82
e6 48 a8 65 08 1b ae f5 28 92 b9 3c f8 47 93 77
a9 f1 f9 a6 ec 67 6f 3d f9 00 df c7 da 43 27 c1
8a 61 ac 28 6a aa 0d ce 99 25 c3 9e ab ee a7 ff
d8 0a e8 65 bd a0 4d a9 e8 0f 39 e6 b3 2f 95 ef
83 dd 31 31 d8 49 df 1a 5d 5c 51 76 7f bd 4b a3
5d 08 da 25 c8 06 38 ba b4 d2 21 24 33 e1 b2 48
8b af 2d bd 7b 32 9b 7c e6 b2 72 ba f2 fe 60 62
db d9 b0 0a aa 34 3d f7 46 3a b2 d0 0a 84 fc 02
a7 a9 d8 ca db 89 3b f4 a1 f1 de e5 5d 29 73 02
2b 1b 8d 8d b7 06 1f a2 8e dd d4 6c 1d b8 1a 57
8b 09 17 96 6f 00 62 75 c3 be 42 68 2a 29 1a 70
f8 03 5b ae 69 cb 89 8a c1 00 34 d0 90 cf 69 5b
00 62 26 4a 74 d3 6d 0e 84 38 1a 29 da 7e d9 57
44 22 75 f1 23 e8 8e e4 cb 80 ec 06 f7 c4 63 cb
0b ec a5 02 32 50 d9 92 40 f5 89 a7 18 10 79 c1
fc d3 52 aa 15 8d 28 14 53 32 5c 46 db 4f 00 19
5e 50 8c 17 e8 0e 36 71 1a 94 53 3c 03 42 0a 05
8c 7d 7f 4e d3 a1 0b 90 aa a3 f7 9a a5 f9 a2 7f
36 4d 46 95 df 89 91 ef 01 ec 44 2c d1 79 b7 e8
3f 1e 56 8e bb b6 fc c1 19 81 78 85 87 88 c4 f1
64 69 df aa 33 f0 a9 1f aa 54 82 16 1f 4b 99 2b
18 38 9c bf 26 98 a7 12 f0 a2 04 de ef 98 63 da
49 ab f7 38 6d 0b 89 45 ee db c0 1e af bf d3 3a
27 6c 91 7a 9b d0 35 45 e7 65 c5 43 3d 70 68 03
02 8d 68 c7 3f fe 1d 2b a4 0e 74 28 e9 82 21 9a
cb b1 b4 9e 91 01 53 89 51 d2 3d 37 b3 16 1c 3e
d8 5f 84 04 95 3a fc f5 9a b7 00 4c ba 10 72 31
2f 6d 17 bd b8 9f 48 e5 3e 14 60 61 4c 33 86 a1
bd 99 34 15 aa 61 39 89 97 91 3f dc 11 f7 25 d0
5d 80 5e c5 dc 2c 03 d7 ab 2d 90 93 3c e5 f5 3e
2c 16 76 48 0b 94 b5 00 5e 8f 97 cf 10 2d 46 d3
50 18 c2 8f 58 ac bd cf 6e 4e 2f 6d cc 71 4f 00
1d 33 4f 3c 57 06 d6 48 8e 50 a9 e3 19 1d b6 13
1c 6a 1d 43 88 4d 57 5d e2 be 79 6b 2b 86 0b 52
01 31 67 1a 59 a0 7f 0c be c4 cb 5e 7e 5e bb 39
45 2c 68 10 7c 51 39 a0 ed 83 1e 35 1b c4 63 8b
b5 e2 7b 8a 9d a7 ac 02 a3 fc cc ec c2 db c0 59
7b db 4b 27 b8 52 38 12 4d 05 38 bd 2b bd 73 c8
a1 33 c4 da 69 6a ce 32 f4 62 51 c6 87 c2 d8 f8
45 5b df 9c 18 5a 91 2e c7 f9 44 87 69 0d 44 70
04 23 f7 da b7 1e 8a 81 c5 28 15 bc b4 83 fb c2
ef b8 95 b7 37 aa 2d 85 22 8c b8 26 28 7d c7 83
d5 fe 30 bf 9c a9 44 d1 d4 37 34 5b a4 ff 63 fc
e6 31 d0 11 6c 4a bd 1d 7a 70 80 25 54 70 d1 44
45 74 ed b6 50 a5 4e 59 f8 c2 f5 99 3d f9 26 43
cd 21 7e 72 60 ef 53 03 f3 6e e7 8e 86 68 5f f0
cc b3 09 64 56 f6 f5 37 53 06 fe ec 3c e7 79 a5
82 7f e0 d0 5f e3 77 0b 18 4a 03 1e 63 a1 53 64
df 87 57 40 f5 c2 56 bb 73 cb ce 68 d2 da 6c 0f
4e 57 06 8d 95 5f a9 6d f0 70 d8 bb 83 85 80 56
52 a5 3f bc 4a 21 45 89 d4 0a 17 03 03 01 19 4f
b6 ea 71 c8 69 7d fa 10 21 08 8b 93 b2 d2 06 5b
2b b5 60 e7 cf 0d 85 ad 3d c4 53 e5 b6 7c d2 35
e6 97 23 95 fb 61 15 57 3c 4a 67 ec 61 26 4d 58
ee 08 af 47 f7 90 b3 11 ba 41 6a be 79 db cf 88
1f d5 04 89 c9 b0 f0 bc 85 30 87 82 88 ee 77 8d
f9 ff 9d 77 f6 50 03 93 88 ea 62 14 cf 47 d4 ad
f7 c4 e1 be 46 7b c0 fa ab b1 76 39 50 76 55 e9
8c c6 c8 a8 13 fa a3 2e 9c 4f 32 7f 9c a4 dc f3
1d e8 fe 3c be af 6d 21 e4 e0 e4 53 b1 cb 3f 63
ac d9 d2 17 81 fa 33 88 8d 61 82 40 5f 56 0f 91
a0 d7 a6 33 fd 59 09 f4 95 99 f6 57 dd d5 32 44
6f a0 64 2e 74 0a 54 90 65 c2 93 61 18 b4 b0 5e
15 27 fa 4d 53 e6 1d aa 1b 13 a6 00 d0 b6 98 07
9a b5 91 03 2f 55 40 69 c0 69 4e 48 33 f1 03 15
cc f8 d2 0a ad 74 6a 37 5a 1b a8 bb fa 3f 04 8c
a8 b5 23 a0 50 2b 8f a5 fb 1d e4 1b 2f 11 bf e1
4c 5a 7b 72 4f f4 d5 65 23 e8 26 22 47 ad 8a e0
eb 0e b3 ee db 54 7c 23 17 03 03 00 35 8e 6c 95
11 a0 76 73 22 67 3a 72 b6 02 30 fe 55 94 60 bb
33 4a c4 fd 7f 6b 00 2c 10 37 4e 29 e8 f7 39 f9
04 9d 92 97 93 12 ec d7 fe 9c fb 78 95 a2 c1 2d
74 d2 17 03 03 00 8b df 38 dc a2 d9 44 06 ce 79
5a 6a e8 9f 97 83 e1 80 c2 84 3b 18 7f 16 d3 9e
fb 53 c9 03 b1 2b 66 fe 81 06 a8 89 4d a0 e3 64
f7 39 53 b6 9c d4 4a 38 bc e4 db c8 d7 68 5e f1
d7 6a 0c 49 4c 5c 28 f6 09 76 8e 15 0b 42 f6 1c
17 07 05 81 8a 05 23 50 cd b0 a6 a3 89 c9 ac 5d
35 35 33 15 4a 6f 31 80 a0 ea de 8e 56 e5 16 e5
d7 f0 e3 f9 09 35 c2 be 9d 74 48 19 39 b8 c9 04
70 9a 58 22 05 fc 68 78 52 b4 92 ab d2 14 66 97
45 e6 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00
`,
			create: func() reader.EventReader {
				return &SocketDataUploadEvent{}
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
			binaryRead := test.create()
			selfRead := test.create()
			bufReader := reader.NewReader(rawData)
			selfRead.ReadFrom(bufReader)
			if err := bufReader.HasError(); err != nil {
				t.Fatalf("reading by self parsing error: %v", err)
			}
			if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, binaryRead); err != nil {
				t.Fatalf("reading buffer error: %v", err)
			}
			// self parsing should same with binary.Read
			assert.Equal(t, selfRead, binaryRead)
		})
	}
}
