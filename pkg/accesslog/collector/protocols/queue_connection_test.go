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
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/shardmap"
)

// fixedProtocol is a protocol of any number that counts the connections it generated
type fixedProtocol struct {
	protocol  enums.ConnectionProtocol
	generated atomic.Int32
}

func (f *fixedProtocol) ForProtocol() enums.ConnectionProtocol { return f.protocol }

func (f *fixedProtocol) GenerateConnection(_, _ uint64) ProtocolMetrics {
	f.generated.Add(1)
	return nil
}

func (f *fixedProtocol) Analyze(*PartitionConnection, *AnalyzeHelper) error { return nil }

// protocolNumbers are the protocols the tests record, including a number beyond the known protocols
var protocolNumbers = []enums.ConnectionProtocol{enums.ConnectionProtocolHTTP, enums.ConnectionProtocolHTTP2, 9}

func newFixedProtocols() ([]Protocol, map[enums.ConnectionProtocol]*fixedProtocol) {
	list := make([]Protocol, 0, len(protocolNumbers))
	byNumber := make(map[enums.ConnectionProtocol]*fixedProtocol)
	for _, number := range protocolNumbers {
		p := &fixedProtocol{protocol: number}
		list = append(list, p)
		byNumber[number] = p
	}
	return list, byNumber
}

func newTestPartition(protocols []Protocol) *PartitionContext {
	return &PartitionContext{
		protocolMgr: NewProtocolManager(protocols),
		connections: shardmap.New[common.ConnectionKey, *PartitionConnection](),
	}
}

func TestGetConnectionContextByKey(t *testing.T) {
	protocols, _ := newFixedProtocols()
	p := newTestPartition(protocols)
	first := p.GetConnectionContext(1, 2, enums.ConnectionProtocolHTTP, 1)
	if again := p.GetConnectionContext(1, 2, enums.ConnectionProtocolHTTP, 2); again != first {
		t.Fatal("the same IDs must give the same connection")
	}
	if other := p.GetConnectionContext(2, 1, enums.ConnectionProtocolHTTP, 1); other == first {
		t.Fatal("swapped IDs are another connection")
	}
	if p.connections.Count() != 2 {
		t.Fatalf("connections: %d", p.connections.Count())
	}
}

// TestAppendProtocolIfNeedKeepsMinimalDataID: whether the read locked check returns early or not, the
// connection records every protocol once, with the smallest data id it has seen
func TestAppendProtocolIfNeedKeepsMinimalDataID(t *testing.T) {
	protocols, byNumber := newFixedProtocols()
	p := newTestPartition(protocols)
	random := rand.New(rand.NewSource(1))
	expected := make(map[enums.ConnectionProtocol]uint64)
	var connection *PartitionConnection
	for i := 0; i < 5000; i++ {
		protocol := protocolNumbers[random.Intn(len(protocolNumbers))]
		dataID := uint64(random.Intn(1000))
		connection = p.GetConnectionContext(1, 1, protocol, dataID)
		if current, exist := expected[protocol]; !exist || dataID < current {
			expected[protocol] = dataID
		}
		if len(connection.protocol) != len(expected) {
			t.Fatalf("recorded protocols: %v, expected: %v", connection.protocol, expected)
		}
		for number, minDataID := range expected {
			if connection.protocol[number] != minDataID {
				t.Fatalf("protocol %d: recorded data id %d, expected %d", number, connection.protocol[number], minDataID)
			}
		}
	}
	for number, protocol := range byNumber {
		if protocol.generated.Load() != 1 {
			t.Fatalf("protocol %d generated %d connections, expected one", number, protocol.generated.Load())
		}
		if connection.Buffer(number) == nil {
			t.Fatalf("protocol %d has no buffer", number)
		}
	}
}

// TestAppendProtocolIfNeedConcurrentReaders: the partition goroutine appends while the analyzer
// reads the protocols, the race detector checks the read locked path
func TestAppendProtocolIfNeedConcurrentReaders(t *testing.T) {
	protocols, _ := newFixedProtocols()
	p := newTestPartition(protocols)
	connection := p.GetConnectionContext(1, 1, enums.ConnectionProtocolHTTP, 500)
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				connection.sortedProtocols()
				connection.IsExistProtocol(enums.ConnectionProtocolHTTP2)
			}
		}
	}()
	for i := 1000; i > 0; i-- {
		p.GetConnectionContext(1, 1, protocolNumbers[i%len(protocolNumbers)], uint64(i))
	}
	close(done)
	wg.Wait()
	if sorted := connection.sortedProtocols(); len(sorted) != len(protocolNumbers) {
		t.Fatalf("sorted protocols: %v", sorted)
	}
}
