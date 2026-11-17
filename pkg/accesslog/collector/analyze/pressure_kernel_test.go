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

package analyze

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// TestSocketDataPressure runs the h2c traffic of Go's client and server with the memory pressure flag
// set (socket_data_pressure_map, skywalking-rover/bpf/accesslog/syscalls/transfer.h): every socket call
// sends exactly one event, marked shed (aclevents.PayloadShed), which decodes into an event without a
// protocol and without data that carries the size, the times, the function, the L4 counters and the ports
// of its own call, so its kernel log is that of the call; per connection and direction the shed calls
// and their sizes are the calls and the bytes really made, and the previous data ids still name sent
// calls. With the flag clear the calls are uploaded with their data, byte for byte.
func TestSocketDataPressure(t *testing.T) { //nolint:funlen // one scenario whose steps share the loaded BPF and the state of the run
	requireBPF(t)
	loader, err := h2cLoadBPF()
	if err != nil {
		t.Fatal(err)
	}
	setPressure := func(on bool) {
		value := uint32(0)
		if on {
			value = 1
		}
		if err := loader.SocketDataPressureMap.Update(uint32(0), value, ebpf.UpdateAny); err != nil {
			t.Fatalf("set the pressure flag: %v", err)
		}
	}
	t.Cleanup(func() { setPressure(false) })
	for _, on := range []bool{true, false} {
		run := withAccessLogBPFModes(t, false, false, func(run *h2cKernelRun) {
			// kept until the events are read: the endpoints still read and write once the requests are done
			setPressure(on)
			goH2CTraffic(t, run, 4)
		})
		setPressure(false)
		shed, calls, recordBytes := 0, 0, 0
		for _, conn := range run.conns {
			checkPrevDataIDs(t, conn)
			checkLayoutFields(t, conn)
			for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
				events := conn.events[d]
				calls += len(conn.calls[d])
				for _, e := range events {
					recordBytes += uploadRecordHeader + int(e.DataLen)
				}
				if !on {
					if got := uploadedStream(t, events); !bytes.Equal(got, conn.real[d]) {
						t.Fatalf("pressure off, %s %s: the uploaded stream (%d bytes) is not the real one (%d bytes)",
							conn.name, directionName(d), len(got), len(conn.real[d]))
					}
					for _, e := range events {
						if e.PayloadSkipped0 != 0 {
							t.Fatalf("pressure off, %s %s: call %d is marked %d", conn.name, directionName(d), e.DataID0, e.PayloadSkipped0)
						}
					}
					continue
				}
				if len(events) != len(conn.calls[d]) {
					t.Fatalf("%s %s: %d events for %d calls", conn.name, directionName(d), len(events), len(conn.calls[d]))
				}
				shedBytes := 0
				for i, e := range events {
					size := conn.calls[d][i]
					if !e.Shed() || e.Protocol0 != enums.ConnectionProtocolUnknown || e.PayloadSkipped0 != 0 ||
						e.Sequence0 != 0 || e.Finished != 1 || e.HaveReduce != 0 || e.DataLen != 0 || e.BufferLen() != 0 ||
						e.TotalSize0 != uint64(size) || e.StartTime0 == 0 || e.EndTime0 < e.StartTime0 {
						t.Fatalf("%s %s: call %d (%d bytes) is not sent as a shed event of its call: %+v",
							conn.name, directionName(d), i, size, *e.Detach())
					}
					// the kernel log of the call, as the agent sends it for a call without a protocol
					log, _, ok := forwarder.BuildTransferLog(e)
					l4 := log.Metrics[0][3]
					if d == enums.SocketDataDirectionEgress {
						l4 = log.Metrics[0][5]
					}
					if !ok || log.Write != (d == enums.SocketDataDirectionEgress) || log.StartTime != e.StartTime0 ||
						log.EndTime != e.EndTime0 || l4 != e.L4TotalPackageSize || log.Metrics[0][2] != uint64(e.L4PackageCount) {
						t.Fatalf("%s %s: the kernel log of call %d is %+v, the event %+v", conn.name, directionName(d), i,
							log, *e.Detach())
					}
					shedBytes += size
					if i > 0 && events[i-1].DataID0 >= e.DataID0 {
						t.Fatalf("%s %s: call %d does not have an event of its own", conn.name, directionName(d), i)
					}
					shed++
				}
				if shedBytes != len(conn.real[d]) {
					t.Fatalf("%s %s: the shed calls carry %d bytes, %d were transferred", conn.name, directionName(d),
						shedBytes, len(conn.real[d]))
				}
			}
		}
		if on && shed == 0 {
			t.Fatal("no call was shed")
		}
		t.Logf("pressure=%t: %d calls, %d shed, %d record bytes", on, calls, shed, recordBytes)
	}
}
