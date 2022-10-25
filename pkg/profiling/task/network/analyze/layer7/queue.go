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

package layer7

import (
	"context"
	"hash/fnv"
	"sync"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"

	"github.com/cilium/ebpf"
)

type PartitionContext interface {
	Consume(data interface{})
}

type EventQueue struct {
	count      int
	partitions []*partition

	startOnce sync.Once
}

func NewEventQueue(partitionCount, sizePerPartition int, contextGenerator func() PartitionContext) *EventQueue {
	partitions := make([]*partition, 0)
	for i := 0; i < partitionCount; i++ {
		partitions = append(partitions, newPartition(i, sizePerPartition, contextGenerator()))
	}
	return &EventQueue{count: partitionCount, partitions: partitions}
}

func (e *EventQueue) Start(ctx context.Context, bpfLoader *bpf.Loader, emap *ebpf.Map, receiverCount int,
	perCPUBufferSize int, dataSupplier func() interface{}, routeGenerator func(data interface{}) string) {
	e.startOnce.Do(func() {
		e.start0(ctx, bpfLoader, emap, receiverCount, perCPUBufferSize, dataSupplier, routeGenerator)
	})
}

func (e *EventQueue) Push(key string, data interface{}) {
	// calculate hash of key
	h := fnv.New32a()
	h.Write([]byte(key))
	sum32 := int(h.Sum32())

	// append data
	e.partitions[sum32%e.count].channel <- data
}

func (e *EventQueue) start0(ctx context.Context, bpfLoader *bpf.Loader, emap *ebpf.Map, receiverCount int,
	perCPUBufferSize int, dataSupplier func() interface{}, routeGenerator func(data interface{}) string) {
	for i := 0; i < receiverCount; i++ {
		bpfLoader.ReadEventAsyncWithBufferSize(emap, func(data interface{}) {
			e.routerTransformer(data, routeGenerator)
		}, perCPUBufferSize, dataSupplier)
	}

	for i := 0; i < len(e.partitions); i++ {
		go func(inx int) {
			p := e.partitions[inx]
			for {
				select {
				// consume the data
				case data := <-p.channel:
					p.ctx.Consume(data)
				// shutdown the consumer
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}
}

func (e *EventQueue) routerTransformer(data interface{}, routeGenerator func(data interface{}) string) {
	key := routeGenerator(data)
	e.Push(key, data)
}

type partition struct {
	index   int
	channel chan interface{}
	ctx     PartitionContext
}

func newPartition(index, size int, ctx PartitionContext) *partition {
	return &partition{
		index:   index,
		channel: make(chan interface{}, size),
		ctx:     ctx,
	}
}
