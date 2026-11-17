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
	// batches recycles the batches the partition goroutines have consumed, see takeBatch and recycleBatch
	batches sync.Pool

	startOnce sync.Once
	// trackDelivery: the queue is part of the delivery clock (delivery.go)
	trackDelivery bool
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

// Push hands an event to the partition of the key from a goroutine that is not a reader of the queue (such as
// the flush of the h2c summaries): false when it is dropped, because the queue has not started or has stopped.
// It may block while the partition is full, which is not counted as time a reader did not read.
func (e *EventQueue) Push(key int, data interface{}) bool {
	return e.push(key, data, false)
}

// push hands an event to its partition; reader: from a reader of the queue, whose time blocked on a full
// partition does not run on the delivery clock
func (e *EventQueue) push(key int, data interface{}, reader bool) bool {
	p := e.partitions[e.partitionIndex(key)]
	if p.channel == nil {
		// not started: nothing would ever take it
		discardEvent(data)
		return false
	}
	p.delivery.trackSingle(DeliveryNow())
	if !sendTracked(p, data, reader) {
		p.delivery.consumedSingle()
		discardEvent(data)
		return false
	}
	return true
}

// partitionIndex is the partition of a routing key
func (e *EventQueue) partitionIndex(key int) int {
	return key % e.count
}

func (e *EventQueue) PartitionContexts() []PartitionContext {
	result := make([]PartitionContext, 0)
	for _, p := range e.partitions {
		result = append(result, p.ctx)
	}
	return result
}

func (e *EventQueue) start0(ctx context.Context, linker *Linker) {
	options := linker.queueReader
	for _, p := range e.partitions {
		p.done = ctx.Done()
		p.open(options.BatchSize)
	}
	for _, r := range e.receivers {
		func(receiver *mapReceiver) {
			opts := readerOptions{wakeupEvents: options.WakeupEvents, flushPeriod: options.FlushPeriod}
			var bufReader RingBufferReader
			if options.BatchSize > 1 {
				batcher := newEventBatcher(e, receiver.router, options.BatchSize)
				bufReader, opts.drained = batcher.add, batcher.flush
			} else {
				bufReader = func(data interface{}) {
					e.routerTransformer(data, receiver.router)
				}
			}
			linker.readEventAsync(receiver.emap, bufReader, receiver.perCPUBuffer, r.parallels, receiver.dataSupplier, opts)
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
					if batch, ok := data.(*eventBatch); ok {
						for _, d := range *batch {
							p.ctx.Consume(d)
						}
						// its events are with their consumers now (delivery.go)
						p.delivery.consumedBatch(batch)
						// the batch is only known to this goroutine (consumers get its events, never
						// the batch), so it is free again once its events are consumed
						e.recycleBatch(batch)
					} else {
						p.ctx.Consume(data)
						p.delivery.consumedSingle()
					}
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
	e.push(key, data, true)
}

type partition struct {
	index int
	// size is the count of events the channel holds
	size    int
	channel chan interface{}
	ctx     PartitionContext
	// done ends the sends to the partition (the context of the queue): nothing consumes the channel anymore
	done <-chan struct{}
	// delivery is what the partition was handed over and has not consumed yet (delivery.go)
	delivery partitionDelivery
}

func newPartition(index, size int, ctx PartitionContext) *partition {
	return &partition{
		index: index,
		size:  size,
		ctx:   ctx,
	}
}

// open creates the channel of the partition. With batches a slot holds a batch: the capacity keeps the
// queue size an event count, so it still bounds the memory of the queue and pushes back on the reader.
func (p *partition) open(batchSize int) {
	slots := p.size
	if batchSize > 1 {
		slots = max(1, (p.size+batchSize-1)/batchSize)
	}
	p.channel = make(chan interface{}, slots)
}

// eventBatch is a run of events of one partition, in the order they were read. It travels as a pointer, so
// the channel send does not box a slice header.
type eventBatch []interface{}

// takeBatch returns an empty batch, a recycled one when there is one
func (e *EventQueue) takeBatch(size int) *eventBatch {
	if batch, ok := e.batches.Get().(*eventBatch); ok {
		return batch
	}
	batch := make(eventBatch, 0, size)
	return &batch
}

// recycleBatch makes a consumed batch available to the batchers again. Its slots are cleared first: a
// recycled batch must not keep the events it carried alive.
func (e *EventQueue) recycleBatch(batch *eventBatch) {
	clear(*batch)
	*batch = (*batch)[:0]
	e.batches.Put(batch)
}

// eventBatcher collects the events one reader reads, per partition, and hands every partition its run
// when it reaches the batch size or when the ring is drained: one channel send and one wakeup of the
// partition goroutine per run instead of per event. It belongs to the goroutine of its reader, and the
// events of a partition keep their order.
type eventBatcher struct {
	queue  *EventQueue
	router func(data interface{}) int
	size   int
	// pending is the open batch of every partition, nil until an event of the partition arrives: never empty
	pending []*eventBatch
}

func newEventBatcher(queue *EventQueue, router func(data interface{}) int, size int) *eventBatcher {
	return &eventBatcher{queue: queue, router: router, size: size, pending: make([]*eventBatch, queue.count)}
}

func (b *eventBatcher) add(data interface{}) {
	index := b.queue.partitionIndex(b.router(data))
	batch := b.pending[index]
	if batch == nil {
		batch = b.queue.takeBatch(b.size)
		b.pending[index] = batch
		// read now: on its way from here on, until the partition consumed it (delivery.go)
		b.queue.partitions[index].delivery.trackBatch(batch, DeliveryNow())
	}
	*batch = append(*batch, data)
	if len(*batch) >= b.size {
		b.send(index)
	}
}

func (b *eventBatcher) flush() {
	for index, batch := range b.pending {
		if batch != nil {
			b.send(index)
		}
	}
}

// send hands the open batch of the partition over: from here on it belongs to the partition goroutine,
// which recycles it, so the batcher keeps no reference to it
func (b *eventBatcher) send(index int) {
	p, batch := b.queue.partitions[index], b.pending[index]
	b.pending[index] = nil
	if !sendTracked(p, batch, true) {
		// the queue stopped: the events of the batch are given back
		p.delivery.consumedBatch(batch)
		for _, d := range *batch {
			discardEvent(d)
		}
	}
}
