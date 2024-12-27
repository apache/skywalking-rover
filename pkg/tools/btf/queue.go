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
	"context"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// queueChannelReducingCountCheckInterval is the interval to check the queue channel reducing count
// if the reducing count is almost full, then added a warning log
const queueChannelReducingCountCheckInterval = time.Second * 5

type PartitionContext interface {
	Start(ctx context.Context)
	Consume(data interface{})
}

type EventQueue struct {
	name       string
	count      int
	receivers  []*mapReceiver
	partitions []*partition

	startOnce sync.Once
}

type mapReceiver struct {
	emap         *ebpf.Map
	perCPUBuffer int
	dataSupplier func() interface{}
	router       func(data interface{}) int
	parallels    int
}

func NewEventQueue(name string, partitionCount, sizePerPartition int, contextGenerator func(partitionNum int) PartitionContext) *EventQueue {
	partitions := make([]*partition, 0)
	for i := 0; i < partitionCount; i++ {
		partitions = append(partitions, newPartition(i, sizePerPartition, contextGenerator(i)))
	}
	return &EventQueue{name: name, count: partitionCount, partitions: partitions}
}

func (e *EventQueue) RegisterReceiver(emap *ebpf.Map, perCPUBufferSize, parallels int, dataSupplier func() interface{},
	routeGenerator func(data interface{}) int) {
	e.receivers = append(e.receivers, &mapReceiver{
		emap:         emap,
		perCPUBuffer: perCPUBufferSize,
		dataSupplier: dataSupplier,
		router:       routeGenerator,
		parallels:    parallels,
	})
}

func (e *EventQueue) Start(ctx context.Context, linker *Linker) {
	e.startOnce.Do(func() {
		e.start0(ctx, linker)
	})
}

func (e *EventQueue) Push(key int, data interface{}) {
	// append data
	e.partitions[key%e.count].channel <- data
}

func (e *EventQueue) PartitionContexts() []PartitionContext {
	result := make([]PartitionContext, 0)
	for _, p := range e.partitions {
		result = append(result, p.ctx)
	}
	return result
}

func (e *EventQueue) start0(ctx context.Context, linker *Linker) {
	for _, r := range e.receivers {
		func(receiver *mapReceiver) {
			linker.ReadEventAsyncWithBufferSize(receiver.emap, func(data interface{}) {
				e.routerTransformer(data, receiver.router)
			}, receiver.perCPUBuffer, r.parallels, receiver.dataSupplier)
		}(r)
	}

	for i := 0; i < len(e.partitions); i++ {
		go func(ctx context.Context, inx int) {
			p := e.partitions[inx]
			p.ctx.Start(ctx)
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
		}(ctx, i)
	}

	// channel reducing count check
	go func() {
		ticker := time.NewTicker(queueChannelReducingCountCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for _, p := range e.partitions {
					reducingCount := len(p.channel)
					if reducingCount > cap(p.channel)*9/10 {
						log.Warnf("queue %s partition %d reducing count is almost full, "+
							"please trying to increase the parallels count or queue size, status: %d/%d",
							e.name, p.index, reducingCount, cap(p.channel))
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (e *EventQueue) routerTransformer(data interface{}, routeGenerator func(data interface{}) int) {
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
