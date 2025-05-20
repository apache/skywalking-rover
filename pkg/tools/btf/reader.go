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
	"fmt"
)

// EventReader read the sample data by self, instant of binary.Read
type EventReader interface {
	// ReadFrom read buffer data
	ReadFrom(reader Reader)
}

type Reader interface {
	HasError() error
	ReadUint64() uint64
	ReadUint32() uint32
	ReadUint16() uint16
	ReadUint8() uint8
	ReadUint8Array(a []uint8, size int)
}

// BytesReader buffer sample reader
type BytesReader struct {
	Sample        []byte
	CurrentOffset int
	sampleLen     int
	err           error
}

// NewReader create a reader from BPF buffer
func NewReader(sample []byte) Reader {
	return &BytesReader{
		Sample:        sample,
		CurrentOffset: 0,
		sampleLen:     len(sample),
	}
}

// HasError is there have error when reading buffer
func (r *BytesReader) HasError() error {
	return r.err
}

func (r *BytesReader) ReadUint64() uint64 {
	bytes, err := r.read(8)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(bytes)
}

func (r *BytesReader) ReadUint32() uint32 {
	bytes, err := r.read(4)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(bytes)
}

func (r *BytesReader) ReadUint16() uint16 {
	bytes, err := r.read(2)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint16(bytes)
}

func (r *BytesReader) ReadUint8() uint8 {
	bytes, err := r.read(1)
	if err != nil {
		return 0
	}
	return bytes[0]
}

func (r *BytesReader) ReadUint8Array(a []uint8, size int) {
	read, err := r.read(size)
	if err != nil {
		return
	}
	copy(a, read)
}

func (r *BytesReader) read(size int) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.sampleLen < r.CurrentOffset+size {
		r.err = fmt.Errorf("out of the buffer reader bound, current offset: %d, read size: %d, sample size: %d",
			r.CurrentOffset, size, r.sampleLen)
		return nil, r.err
	}
	bytes := r.Sample[r.CurrentOffset : r.CurrentOffset+size]
	r.CurrentOffset += size
	return bytes, nil
}

type sizeCalcReader struct {
	size int
}

func newSizeCalcReader() *sizeCalcReader {
	return &sizeCalcReader{}
}

func (r *sizeCalcReader) HasError() error {
	return nil
}

func (r *sizeCalcReader) ReadUint64() uint64 {
	r.size += 8
	return 0
}

func (r *sizeCalcReader) ReadUint32() uint32 {
	r.size += 4
	return 0
}

func (r *sizeCalcReader) ReadUint16() uint16 {
	r.size += 2
	return 0
}

func (r *sizeCalcReader) ReadUint8() uint8 {
	r.size++
	return 0
}

func (r *sizeCalcReader) ReadUint8Array(_ []uint8, size int) {
	r.size += size
}

func (r *sizeCalcReader) Size() int {
	return r.size
}
