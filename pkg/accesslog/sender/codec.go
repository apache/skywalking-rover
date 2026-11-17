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

package sender

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"

	// registers the proto codec the access log codec delegates to
	_ "google.golang.org/grpc/encoding/proto"
)

// preEncoded is an EBPFAccessLogMessage already encoded, its parts sent as they are by accessLogCodec. The
// transport reads them after SendMsg returns, so every message has its own; the parts are immutable (a fresh
// header, sealed arena slices).
type preEncoded struct {
	data mem.BufferSlice
	// backing of data for a header and a log, one allocation for the message: data holds pointers into parts,
	// so the slices are not boxed one by one
	parts   [2]mem.SliceBuffer
	buffers [2]mem.Buffer
}

func newPreEncoded(header []byte, logs [][]byte) *preEncoded {
	p := &preEncoded{}
	n := len(logs)
	if len(header) > 0 {
		n++
	}
	parts, data := p.parts[:0], mem.BufferSlice(p.buffers[:0])
	if n > len(p.parts) {
		parts, data = make([]mem.SliceBuffer, 0, n), make(mem.BufferSlice, 0, n)
	}
	if len(header) > 0 {
		parts = append(parts, header)
	}
	for _, l := range logs {
		parts = append(parts, l)
	}
	for i := range parts {
		data = append(data, &parts[i])
	}
	p.data = data
	return p
}

// accessLogCodec sends the pre-encoded messages as they are and leaves every other message, such as
// the reply of the stream, to the proto codec of gRPC
type accessLogCodec struct {
	proto encoding.CodecV2
}

func (c accessLogCodec) Marshal(v any) (mem.BufferSlice, error) {
	if p, ok := v.(*preEncoded); ok {
		return p.data, nil
	}
	return c.proto.Marshal(v)
}

func (c accessLogCodec) Unmarshal(data mem.BufferSlice, v any) error {
	return c.proto.Unmarshal(data, v)
}

// Name is the content-subtype of the stream: empty keeps the content-type "application/grpc" the
// stream has with the default codec, instead of "application/grpc+proto"
func (c accessLogCodec) Name() string {
	return ""
}

// collectCallOption makes a Collect stream take the pre-encoded messages
var collectCallOption = grpc.ForceCodecV2(accessLogCodec{proto: encoding.GetCodecV2("proto")})
