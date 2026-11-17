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

package unwind

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errOutOfRange = errors.New("read out of range")
	errBadCIE     = errors.New("bad CIE")
)

// pointer encodings used by the .eh_frame section (DW_EH_PE_*)
const (
	pePtrAbs     = 0x00
	pePtrULEB128 = 0x01
	pePtrUData2  = 0x02
	pePtrUData4  = 0x03
	pePtrUData8  = 0x04
	pePtrSLEB128 = 0x09
	pePtrSData2  = 0x0a
	pePtrSData4  = 0x0b
	pePtrSData8  = 0x0c

	pePcRel = 0x10
	peOmit  = 0xff

	peFormatMask = 0x0f
	peApplyMask  = 0x70
)

// byteReader is a little-endian cursor over a byte slice, it records the first error
// and returns zero values after that, so callers could check the error only once.
type byteReader struct {
	data []byte
	pos  int
	err  error
}

func newByteReader(data []byte, pos int) *byteReader {
	return &byteReader{data: data, pos: pos}
}

func (r *byteReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *byteReader) remaining() int {
	return len(r.data) - r.pos
}

func (r *byteReader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.remaining() < n {
		r.fail(errOutOfRange)
		return nil
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}

func (r *byteReader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *byteReader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

func (r *byteReader) u32() uint32 {
	b := r.bytes(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (r *byteReader) u64() uint64 {
	b := r.bytes(8)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

func (r *byteReader) uleb() uint64 {
	var result uint64
	var shift uint
	for {
		b := r.u8()
		if r.err != nil {
			return 0
		}
		if shift < 64 {
			result |= uint64(b&0x7f) << shift
		}
		shift += 7
		if b&0x80 == 0 {
			return result
		}
	}
}

func (r *byteReader) sleb() int64 {
	var result int64
	var shift uint
	var b uint8
	for {
		b = r.u8()
		if r.err != nil {
			return 0
		}
		if shift < 64 {
			result |= int64(b&0x7f) << shift
		}
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	if shift < 64 && b&0x40 != 0 {
		result |= -1 << shift
	}
	return result
}

func (r *byteReader) cstring() string {
	if r.err != nil {
		return ""
	}
	for i := r.pos; i < len(r.data); i++ {
		if r.data[i] == 0 {
			s := string(r.data[r.pos:i])
			r.pos = i + 1
			return s
		}
	}
	r.fail(errOutOfRange)
	return ""
}

// encodedPointer reads a pointer with the DW_EH_PE_* encoding.
// sectionAddr is the virtual address of the first byte of data, used to resolve pc-relative values.
func (r *byteReader) encodedPointer(enc uint8, sectionAddr uint64) uint64 {
	if enc == peOmit {
		return 0
	}
	position := sectionAddr + uint64(r.pos)
	var value uint64
	switch enc & peFormatMask {
	case pePtrAbs, pePtrUData8, pePtrSData8:
		value = r.u64()
	case pePtrULEB128:
		value = r.uleb()
	case pePtrUData2:
		value = uint64(r.u16())
	case pePtrUData4:
		value = uint64(r.u32())
	case pePtrSLEB128:
		value = uint64(r.sleb())
	case pePtrSData2:
		value = uint64(int64(int16(r.u16())))
	case pePtrSData4:
		value = uint64(int64(int32(r.u32())))
	default:
		r.fail(fmt.Errorf("unsupported pointer encoding: 0x%x", enc))
		return 0
	}
	switch enc & peApplyMask {
	case 0:
	case pePcRel:
		value += position
	default:
		// data/text/func relative and aligned are not used by the toolchains on linux x86_64/arm64
		r.fail(fmt.Errorf("unsupported pointer application: 0x%x", enc))
		return 0
	}
	// indirect pointers only appear in the personality routine, which is never needed for unwinding
	return value
}

// encodedValue reads a value with the format of the encoding but without the application, used for the FDE address range.
func (r *byteReader) encodedValue(enc uint8) uint64 {
	if enc == peOmit {
		return 0
	}
	return r.encodedPointer(enc&peFormatMask, 0)
}
