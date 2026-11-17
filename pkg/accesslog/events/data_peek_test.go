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
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// peekRecord is the record of a receive made with MSG_PEEK that carries bytes (BPF sends none, the decode must not
// depend on it)
func peekRecord(t *testing.T, data []byte) []byte {
	var record bytes.Buffer
	wire := &socketDataUploadWire{Protocol0: enums.ConnectionProtocolHTTP2, Finished: 1, DataLen: uint16(len(data)),
		ConnectionID: 7, RandomID: 9, DataID0: 12, PrevDataID0: 11, TotalSize0: uint64(len(data)), L4PackageCount: 1,
		L4TotalPackageSize: 77, FunctionName: uint32(enums.SocketFunctionNameRecvfrom), StartTime0: 10, EndTime0: 20,
		Direction0: enums.SocketDataDirectionIngress, PayloadSkipped0: PayloadPeek, LocalPort: 8080, RemotePort: 5000}
	if err := binary.Write(&record, binary.LittleEndian, wire); err != nil {
		t.Fatal(err)
	}
	record.Write(data)
	return record.Bytes()
}

// TestPeekEventIsTheKernelLogOnly: the event of a peek is decoded without a protocol and without bytes, naming no
// previous upload, so no protocol analyzer reads what it peeked (it is read again by the receive that consumes it);
// the details of its call are kept for its kernel log
func TestPeekEventIsTheKernelLogOnly(t *testing.T) {
	// a HEADERS frame of stream 3 (an indexed :method GET), as a peek at a header block would see it
	headers := []byte{0, 0, 1, 1, 4, 0, 0, 0, 3, 0x82}
	for _, data := range [][]byte{nil, headers} {
		var e SocketDataUploadEvent
		reader := btf.NewReader(peekRecord(t, data))
		e.ReadFrom(reader)
		if err := reader.HasError(); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !e.Peek() || e.Protocol() != enums.ConnectionProtocolUnknown || e.BufferData() != nil || e.BufferLen() != 0 ||
			e.PayloadSkipped() || e.PrevDataID0 != 0 {
			t.Fatalf("%d bytes: decoded as %+v", len(data), e)
		}
		if e.GetFunctionName() != enums.SocketFunctionNameRecvfrom || e.DataID0 != 12 || e.L4PackageCount != 1 ||
			e.L4TotalPackageSize != 77 || e.StartTime0 != 10 || e.EndTime0 != 20 || e.LocalPort != 8080 {
			t.Fatalf("%d bytes: the details of the call are lost: %+v", len(data), e)
		}
	}
}
