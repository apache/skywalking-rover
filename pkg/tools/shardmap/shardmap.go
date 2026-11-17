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

package shardmap

import "sync"

const shardCount = 32

// Key is a map key that hashes itself, so a lookup needs neither a string key nor a generic hasher
type Key interface {
	comparable
	Hash() uint32
}

// Map is a concurrent map split into shards, each guarded by its own lock. It has the semantics of
// the string keyed concurrent-map it replaces on the hot paths (the same shard locking, IterCb holds
// the read lock of a shard while calling back), without building a string key per lookup.
// orcaman/concurrent-map/v2 was not used to avoid a new dependency and an indirect sharding call.
type Map[K Key, V any] struct {
	shards [shardCount]shard[K, V]
}

type shard[K Key, V any] struct {
	sync.RWMutex
	items map[K]V
}

func New[K Key, V any]() *Map[K, V] {
	m := &Map[K, V]{}
	for i := range m.shards {
		m.shards[i].items = make(map[K]V)
	}
	return m
}

func (m *Map[K, V]) shard(key K) *shard[K, V] {
	return &m.shards[key.Hash()%shardCount]
}

func (m *Map[K, V]) Get(key K) (V, bool) {
	s := m.shard(key)
	s.RLock()
	val, ok := s.items[key]
	s.RUnlock()
	return val, ok
}

func (m *Map[K, V]) Set(key K, value V) {
	s := m.shard(key)
	s.Lock()
	s.items[key] = value
	s.Unlock()
}

func (m *Map[K, V]) Remove(key K) {
	s := m.shard(key)
	s.Lock()
	delete(s.items, key)
	s.Unlock()
}

func (m *Map[K, V]) Count() int {
	count := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.RLock()
		count += len(s.items)
		s.RUnlock()
	}
	return count
}

// IterCb calls fn for every item, holding the read lock of the shard of the item, so fn must not
// write to the map
func (m *Map[K, V]) IterCb(fn func(key K, value V)) {
	for i := range m.shards {
		s := &m.shards[i]
		s.RLock()
		for key, value := range s.items {
			fn(key, value)
		}
		s.RUnlock()
	}
}

// AppendValues appends every value to dst and returns it: the lock of a shard is held only while its values are
// copied, so what is done with them does not hold off the writers of the map
func (m *Map[K, V]) AppendValues(dst []V) []V {
	for i := range m.shards {
		s := &m.shards[i]
		s.RLock()
		for _, value := range s.items {
			dst = append(dst, value)
		}
		s.RUnlock()
	}
	return dst
}
