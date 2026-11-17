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

import (
	"sync"
	"testing"
)

type testKey struct {
	a, b uint64
}

func (k testKey) Hash() uint32 {
	return uint32(k.a*31 + k.b)
}

func TestMap(t *testing.T) {
	m := New[testKey, int]()
	for i := uint64(0); i < 100; i++ {
		m.Set(testKey{a: i, b: i + 1}, int(i))
	}
	if m.Count() != 100 {
		t.Fatalf("count: %d", m.Count())
	}
	if v, ok := m.Get(testKey{a: 7, b: 8}); !ok || v != 7 {
		t.Fatalf("get: %d, %t", v, ok)
	}
	if _, ok := m.Get(testKey{a: 8, b: 7}); ok {
		t.Fatal("a missing key must not be found")
	}
	m.Set(testKey{a: 7, b: 8}, 70)
	if v, _ := m.Get(testKey{a: 7, b: 8}); v != 70 {
		t.Fatalf("set must replace the value, got %d", v)
	}
	m.Remove(testKey{a: 7, b: 8})
	if _, ok := m.Get(testKey{a: 7, b: 8}); ok || m.Count() != 99 {
		t.Fatal("remove must delete the key")
	}
	sum := 0
	m.IterCb(func(k testKey, v int) {
		if int(k.a) != v {
			t.Fatalf("key %v holds %d", k, v)
		}
		sum += v
	})
	if sum != 99*100/2-7 {
		t.Fatalf("every item must be visited once, sum: %d", sum)
	}
}

func TestMapConcurrent(t *testing.T) {
	m := New[testKey, int]()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				key := testKey{a: uint64(w), b: uint64(i)}
				m.Set(key, i)
				m.Get(key)
				m.IterCb(func(testKey, int) {})
				if i%2 == 0 {
					m.Remove(key)
				}
			}
		}(w)
	}
	wg.Wait()
	if m.Count() != 4*500 {
		t.Fatalf("count: %d", m.Count())
	}
}

// TestAppendValuesWithoutTheLock: the values are copied out, and a write to the map while the copy is used does not
// wait (IterCb would hold the shard lock in the callback)
func TestAppendValuesWithoutTheLock(t *testing.T) {
	m := New[testKey, int]()
	for i := 0; i < 100; i++ {
		m.Set(testKey{uint64(i), 1}, i)
	}
	values := m.AppendValues(nil)
	if len(values) != 100 {
		t.Fatalf("%d values", len(values))
	}
	sum := 0
	for _, v := range values {
		m.Set(testKey{uint64(v), 1}, v+1) // would deadlock under a held read lock of its shard
		m.Remove(testKey{uint64(v), 2})
		sum += v
	}
	if sum != 99*100/2 {
		t.Fatalf("sum %d", sum)
	}
}
