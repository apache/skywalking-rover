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

package protocols

import (
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// TestProtocolSlots: the slot of a protocol gives what the maps give, and a connection whose slots are not set
// (built with the maps alone) reads the maps
func TestProtocolSlots(t *testing.T) {
	h2 := NewHTTP2Analyzer(nil, nil)
	buf, metrics := buffer.NewBuffer(), h2.GenerateConnection(1, 1)
	byMaps := &PartitionConnection{
		dataBuffers:      map[enums.ConnectionProtocol]*buffer.Buffer{enums.ConnectionProtocolHTTP2: buf},
		protocol:         map[enums.ConnectionProtocol]uint64{enums.ConnectionProtocolHTTP2: 0},
		protocolAnalyzer: map[enums.ConnectionProtocol]Protocol{enums.ConnectionProtocolHTTP2: h2},
		protocolMetrics:  map[enums.ConnectionProtocol]ProtocolMetrics{enums.ConnectionProtocolHTTP2: metrics},
	}
	bySlots := &PartitionConnection{
		dataBuffers:      map[enums.ConnectionProtocol]*buffer.Buffer{},
		protocol:         map[enums.ConnectionProtocol]uint64{},
		protocolAnalyzer: map[enums.ConnectionProtocol]Protocol{},
		protocolMetrics:  map[enums.ConnectionProtocol]ProtocolMetrics{},
	}
	bySlots.setProtocolSlot(enums.ConnectionProtocolHTTP2, buf, h2, metrics)
	bySlots.setProtocolSlot(enums.ConnectionProtocol(200), buf, h2, metrics) // beyond the slots: ignored
	for _, c := range []*PartitionConnection{byMaps, bySlots} {
		if c.Buffer(enums.ConnectionProtocolHTTP2) != buf || c.Metrics(enums.ConnectionProtocolHTTP2) != metrics ||
			c.analyzer(enums.ConnectionProtocolHTTP2) != h2 {
			t.Fatalf("HTTP/2 of the connection differs")
		}
		if c.Buffer(enums.ConnectionProtocolHTTP) != nil || c.Metrics(enums.ConnectionProtocolHTTP) != nil ||
			c.analyzer(enums.ConnectionProtocolHTTP) != nil || c.Buffer(enums.ConnectionProtocol(200)) != nil {
			t.Fatalf("a protocol the connection does not have is there")
		}
	}
}
