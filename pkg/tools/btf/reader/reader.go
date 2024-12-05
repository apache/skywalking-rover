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

package reader

import (
	"encoding/binary"
	"fmt"
)

// EventReader read the sample data by self, instant of binary.Read
type EventReader interface {
	// ReadFrom read buffer data
	ReadFrom(reader *Reader)
}

// Reader buffer sample reader
type Reader struct {
	Sample        []byte
	CurrentOffset int
	sampleLen     int
	err           error
}

// NewReader create a reader from BPF buffer
func NewReader(sample []byte) *Reader {
	return &Reader{
		Sample:        sample,
		CurrentOffset: 0,
		sampleLen:     len(sample),
	}
}

// HasError is there have error when reading buffer
func (r *Reader) HasError() error {
	return r.err
}

func (r *Reader) ReadUint64() uint64 {
	bytes, err := r.read(8)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(bytes)
}

func (r *Reader) ReadUint32() uint32 {
	bytes, err := r.read(4)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(bytes)
}

func (r *Reader) ReadUint16() uint16 {
	bytes, err := r.read(2)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint16(bytes)
}

func (r *Reader) ReadUint8() uint8 {
	bytes, err := r.read(1)
	if err != nil {
		return 0
	}
	return bytes[0]
}

func (r *Reader) ReadUint8Array(a []uint8, size int) {
	read, err := r.read(size)
	if err != nil {
		return
	}
	copy(a, read)
}

func (r *Reader) read(size int) ([]byte, error) {
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
