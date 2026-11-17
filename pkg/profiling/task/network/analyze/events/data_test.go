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
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

// header is the packed header of the event of the network profiling (bpf/include/socket_data_event.h)
type header struct {
	Protocol, HaveReduce, Direction, Finished uint8
	Sequence, DataLen                         uint16
	StartTime, EndTime, ConID, RandomID       uint64
	DataID, PrevDataID, TotalSize             uint64
	PayloadSkipped                            uint8
}

func sample(t *testing.T, h header, data []byte) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, h); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 65 {
		t.Fatalf("the header is %d bytes, the buffer of the BPF event is at 65", buf.Len())
	}
	buf.Write(data)
	return buf.Bytes()
}

// TestSocketDataUploadEventReadFrom: an event submitted with only its used bytes (offsetof(buffer) + data_len)
// decodes, as a full one does with binary.Read
func TestSocketDataUploadEventReadFrom(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\n\r\n")
	h := header{Protocol: 1, HaveReduce: 1, Direction: 2, Finished: 1, Sequence: 3, DataLen: uint16(len(data)),
		StartTime: 10, EndTime: 20, ConID: 30, RandomID: 40, DataID: 50, PrevDataID: 49, TotalSize: 1000, PayloadSkipped: 0}
	short := sample(t, h, data)

	var e SocketDataUploadEvent
	r := btf.NewReader(short)
	e.ReadFrom(r)
	if err := r.HasError(); err != nil {
		t.Fatalf("a short event: %v", err)
	}
	if !bytes.Equal(e.BufferData(), data) || e.DataID() != 50 || e.PrevDataID() != 49 || e.TotalSize() != 1000 ||
		e.DataSequence() != 3 || !e.IsFinished() || !e.HaveReduceDataAfterChunk() || e.ConnectionID != 30 ||
		e.RandomID != 40 || e.StartTime() != 10 || e.EndTime() != 20 || e.Direction() != 2 || e.Protocol() != 1 {
		t.Errorf("decoded %+v", e.header())
	}

	// the whole struct as a sample (the event as it was submitted before the truncated submit) decodes the same
	full := sample(t, h, append(append([]byte{}, data...), make([]byte, 20480-len(data))...))
	var viaFull SocketDataUploadEvent
	r = btf.NewReader(full)
	viaFull.ReadFrom(r)
	if err := r.HasError(); err != nil || viaFull.header() != e.header() || !bytes.Equal(viaFull.BufferData(), data) {
		t.Errorf("full event: %v %+v != %+v", err, viaFull.header(), e.header())
	}

	// an event without data
	h.DataLen = 0
	var empty SocketDataUploadEvent
	r = btf.NewReader(sample(t, h, nil))
	empty.ReadFrom(r)
	if err := r.HasError(); err != nil || empty.BufferLen() != 0 {
		t.Errorf("an empty event: %v, %d bytes", err, empty.BufferLen())
	}

	// a sample shorter than its data_len is broken
	h.DataLen = 100
	r = btf.NewReader(sample(t, h, data))
	var broken SocketDataUploadEvent
	broken.ReadFrom(r)
	if r.HasError() == nil {
		t.Errorf("a sample shorter than data_len decoded")
	}
}

// header is the event without its buffer and its memory charge, comparable
func (s *SocketDataUploadEvent) header() SocketDataUploadEvent {
	c := *s
	c.Buffer = [20480]byte{}
	c.embeddedCharge = 0
	return c
}
