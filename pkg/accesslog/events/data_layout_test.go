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
	"os"
	"reflect"
	"testing"

	ciliumbtf "github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// socketDataUploadWire mirrors the header of struct socket_data_upload_event of
// bpf/accesslog/include/socket_data_event.h field by field, with the kernel widths: a record is this
// header and the data_len bytes of buffer behind it
type socketDataUploadWire struct {
	Protocol0          enums.ConnectionProtocol
	HaveReduce         uint8
	L4PackageCount     uint8
	Finished           uint8
	Sequence0          uint16
	DataLen            uint16
	FunctionName       uint32
	SSL                uint8
	H2CFrames0         uint8
	InFlight           uint16
	StartTime0         uint64
	EndTime0           uint64
	ConnectionID       uint64
	RandomID           uint64
	DataID0            uint64
	PrevDataID0        uint64
	TotalSize0         uint64
	L4TotalPackageSize uint64
	Direction0         enums.SocketDataDirection
	PayloadSkipped0    uint8
	LocalPort          uint16
	RemotePort         uint16
	DataIDSpan         uint16
	SumBefore          uint32
	SumStream          uint32
	SumFrames          uint16
	FirstFrameOff      uint16
}

// the C member of each field of the wire struct, in order
var socketDataUploadMembers = []string{"protocol", "have_reduce_after_chunk", "l4_package_count", "finished",
	"sequence", "data_len", "func_name", "ssl", "h2c_frames", "in_flight", "start_time", "end_time", "conid", "randomid", "data_id",
	"prev_data_id", "total_size", "l4_total_package_size", "direction", "payload_skipped", "local_port",
	"remote_port", "data_id_span", "sum_before", "sum_stream", "sum_frames", "first_frame_off"}

func narrowSocketData(e *SocketDataUploadEvent) *socketDataUploadWire {
	return &socketDataUploadWire{
		Protocol0: e.Protocol0, HaveReduce: e.HaveReduce, L4PackageCount: uint8(e.L4PackageCount), Finished: e.Finished,
		Sequence0: e.Sequence0, DataLen: e.DataLen, FunctionName: e.FunctionName, SSL: uint8(e.SSL), H2CFrames0: e.H2CFrames0, InFlight: e.InFlight,
		StartTime0: e.StartTime0,
		EndTime0:   e.EndTime0, ConnectionID: e.ConnectionID, RandomID: e.RandomID, DataID0: e.DataID0,
		PrevDataID0: e.PrevDataID0, TotalSize0: e.TotalSize0, L4TotalPackageSize: e.L4TotalPackageSize,
		Direction0: e.Direction0, PayloadSkipped0: e.PayloadSkipped0, LocalPort: e.LocalPort, RemotePort: e.RemotePort,
		DataIDSpan: e.DataIDSpan, SumBefore: e.SumBefore, SumStream: e.SumStream, SumFrames: e.SumFrames,
		FirstFrameOff: e.FirstFrameOff,
	}
}

// TestSocketDataUploadEventLayout checks the wire struct against the kernel struct as the access log
// object was compiled (its BTF), member by member, and ReadFrom against the wire struct, for an event with
// content and for the event without content of a skipped h2c DATA payload. The object is the one `make
// generate` puts into the rover module; the BTF part is skipped without it.
func TestSocketDataUploadEventLayout(t *testing.T) {
	object := "../../../skywalking-rover/pkg/accesslog/bpf/bpf_x86_bpfel.o"
	if _, err := os.Stat(object); err == nil {
		spec, err := ciliumbtf.LoadSpec(object)
		if err != nil {
			t.Fatalf("read the BTF of %s: %v", object, err)
		}
		var event *ciliumbtf.Struct
		if err := spec.TypeByName("socket_data_upload_event", &event); err != nil {
			t.Fatalf("struct socket_data_upload_event: %v", err)
		}
		wire := reflect.TypeOf(socketDataUploadWire{})
		offset := 0
		for i, name := range socketDataUploadMembers {
			member := event.Members[i]
			size := int(wire.Field(i).Type.Size())
			memberSize, err := ciliumbtf.Sizeof(member.Type)
			if err != nil {
				t.Fatal(err)
			}
			if member.Name != name || int(member.Offset.Bytes()) != offset || memberSize != size {
				t.Fatalf("member %d is %s at %d (%d bytes), the reader expects %s at %d (%d bytes)", i, member.Name,
					member.Offset.Bytes(), memberSize, name, offset, size)
			}
			offset += size
		}
		if buf := event.Members[len(socketDataUploadMembers)]; buf.Name != "buffer" || int(buf.Offset.Bytes()) != offset {
			t.Fatalf("the buffer is %s at %d, expected at %d", buf.Name, buf.Offset.Bytes(), offset)
		}
	} else {
		t.Logf("no access log object at %s, only the reader is checked", object)
	}

	for _, wire := range []*socketDataUploadWire{
		{Protocol0: enums.ConnectionProtocolHTTP2, L4PackageCount: 3, Finished: 1, DataLen: 5, FunctionName: 11,
			StartTime0: 1, EndTime0: 2, ConnectionID: 3, RandomID: 4, DataID0: 7, PrevDataID0: 6, TotalSize0: 5,
			L4TotalPackageSize: 300, Direction0: enums.SocketDataDirectionIngress, LocalPort: 8080, RemotePort: 34567},
		{Protocol0: enums.ConnectionProtocolHTTP2, L4PackageCount: 12, Finished: 1, FunctionName: 11, StartTime0: 1,
			EndTime0: 2, ConnectionID: 3, RandomID: 4, DataID0: 8, PrevDataID0: 7, TotalSize0: 16384,
			L4TotalPackageSize: 17000, Direction0: enums.SocketDataDirectionIngress, PayloadSkipped0: 1, LocalPort: 8080,
			RemotePort: 34567, InFlight: 1},
		// the coalesced skipped calls of an HTTP/1 body: data ids 20 to 31, on a TLS-less connection with
		// another call in flight
		{Protocol0: enums.ConnectionProtocolHTTP, L4PackageCount: 40, Finished: 1, FunctionName: 2, SSL: 1, InFlight: 3,
			StartTime0: 1, EndTime0: 2, ConnectionID: 3, RandomID: 4, DataID0: 31, PrevDataID0: 19, TotalSize0: 60000,
			L4TotalPackageSize: 62000, Direction0: enums.SocketDataDirectionEgress, PayloadSkipped0: 1, LocalPort: 8080,
			RemotePort: 34567, DataIDSpan: 11},
		// a positional h2c call with a run of 15 whole DATA frames of stream 0x7fffffff in front of it
		{Protocol0: enums.ConnectionProtocolHTTP2, HaveReduce: 1, L4PackageCount: 2, Finished: 1, DataLen: 9,
			FunctionName: 11, StartTime0: 1, EndTime0: 2, ConnectionID: 3, RandomID: 4, DataID0: 9, PrevDataID0: 8,
			TotalSize0: 16393, L4TotalPackageSize: 16500, Direction0: enums.SocketDataDirectionEgress, LocalPort: 8080,
			RemotePort: 34567, SumBefore: 15 * 16393, SumStream: 0x7fffffff, SumFrames: 15, H2CFrames0: 3, FirstFrameOff: 0},
		// a call whose frames the follower knew, a header block among them, the first frame header at 13
		{Protocol0: enums.ConnectionProtocolHTTP2, Finished: 1, DataLen: 40, FunctionName: 11, StartTime0: 1, EndTime0: 2,
			ConnectionID: 3, RandomID: 4, DataID0: 10, PrevDataID0: 9, TotalSize0: 40, Direction0: enums.SocketDataDirectionEgress,
			H2CFrames0: 1, FirstFrameOff: 13},
	} {
		var record bytes.Buffer
		if err := binary.Write(&record, binary.LittleEndian, wire); err != nil {
			t.Fatal(err)
		}
		record.Write(bytes.Repeat([]byte{'x'}, int(wire.DataLen)))
		e := &SocketDataUploadEvent{}
		reader := btf.NewReader(record.Bytes())
		e.ReadFrom(reader)
		if err := reader.HasError(); err != nil {
			t.Fatalf("read: %v", err)
		}
		assert.Equal(t, wire, narrowSocketData(e))
		if e.PayloadSkipped() != (wire.PayloadSkipped0 == 1) || buffer.IsPayloadSkipped(e) != e.PayloadSkipped() ||
			e.BufferLen() != int(wire.DataLen) || e.TotalSize() != wire.TotalSize0 {
			t.Fatalf("the event is read wrong: %+v", *e.Detach())
		}
		if e.FirstDataID() != wire.DataID0-uint64(wire.DataIDSpan) {
			t.Fatalf("the first data id is %d, the event stands for %d to %d", e.FirstDataID(),
				wire.DataID0-uint64(wire.DataIDSpan), wire.DataID0)
		}
		if detached := e.Detach(); detached.PayloadSkipped() != e.PayloadSkipped() {
			t.Fatalf("the detached copy loses the mark")
		}
	}
}
