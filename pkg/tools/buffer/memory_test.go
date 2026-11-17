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

package buffer

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// withInflight runs f with the in-flight counters cleared and the budget set
func withInflight(t *testing.T, budget, overhead int64, f func()) {
	t.Helper()
	events, bytes, saved := eventsInUse.Load(), bytesInUse.Load(), eventOverhead.Load()
	defer func() {
		eventsInUse.Store(events)
		bytesInUse.Store(bytes)
		eventOverhead.Store(saved)
		memoryBudget.Store(0)
	}()
	eventsInUse.Store(0)
	bytesInUse.Store(0)
	eventOverhead.Store(overhead)
	memoryBudget.Store(budget)
	f()
}

// TestMemoryBudget: an event is admitted while the events in use hold less than the budget, refused
// (and counted) once they hold it, and admitted again as soon as some are released
func TestMemoryBudget(t *testing.T) {
	withInflight(t, 100_000, 100, func() {
		_, dropped0, _, _ := MemoryStats()
		bytesInUse.Store(99_800)
		if !AcquireEvent() {
			t.Fatal("below the budget the event must be admitted")
		}
		if InflightBytes() != 99_900 {
			t.Fatalf("in-flight %d", InflightBytes())
		}
		bytesInUse.Store(99_900) // 99_900 + one event of 100 = the budget
		if AcquireEvent() || AcquireEventBuffer(10) != nil {
			t.Fatal("at the budget the events must be refused")
		}
		bytesInUse.Store(99_899)
		if !AcquireEvent() {
			t.Fatal("below the budget again the event must be admitted")
		}
		if _, dropped, inflight, budget := MemoryStats(); dropped-dropped0 != 2 || budget != 100_000 || inflight != 99_899+200 {
			t.Fatalf("dropped %d, in-flight %d, budget %d", dropped-dropped0, inflight, budget)
		}
		memoryBudget.Store(0)
		bytesInUse.Store(1 << 40)
		if !AcquireEvent() {
			t.Fatal("without a budget every event is admitted")
		}
	})
}

func TestMemoryBudgetFromLimit(t *testing.T) {
	var soft int64
	stubSoftLimit(t, func(v int64) int64 { soft = v; return 0 }, false)
	defer func() { memoryBudget.Store(0); eventOverhead.Store(embeddedEventSize + eventBookkeepingBytes) }()
	desc, err := enableMemoryProtection(MemoryConfig{MaxPercent: 80, EventSize: 160}, memoryLimit{limit: 2 << 30, source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := memoryBudget.Load(); got != (2<<30)*80/100 || memoryLimitBytes.Load() != 2<<30 {
		t.Fatalf("budget %d: %s", got, desc)
	}
	if got := eventOverhead.Load(); got != 160+eventBookkeepingBytes {
		t.Fatalf("event overhead %d", got)
	}
	if soft != (2<<30)*90/100 || !strings.Contains(desc, "Go memory limit set to 1843 MB (90%)") {
		t.Fatalf("soft limit %d: %s", soft, desc)
	}
	if _, err := enableMemoryProtection(MemoryConfig{MaxPercent: 80}, memoryLimit{}); err == nil || memoryBudget.Load() != 0 {
		t.Fatal("without a limit the protection must stay off")
	}
}

func TestMemoryBudgetRaceStaysConsistent(t *testing.T) {
	withInflight(t, 50*MaxEventBufferSize, 0, func() {
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 2000; i++ {
					if b := AcquireEventBuffer(MaxEventBufferSize); b != nil {
						ReleaseEvent(b)
					}
				}
			}()
		}
		wg.Wait()
		if InflightBytes() != 0 || eventsInUse.Load() != 0 {
			t.Fatalf("in-flight %d events %d after every release", InflightBytes(), eventsInUse.Load())
		}
	})
}

// pooledEvent is a socket data event holding a pooled buffer, as the access log events do
type pooledEvent struct {
	uploadEvent
	buf []byte
}

func (e *pooledEvent) ReleaseBuffer() []byte {
	b := e.buf
	e.buf = nil
	return b
}

func newPooledEvent(t testing.TB, dataID uint64, size int, start uint64) *pooledEvent {
	if !AcquireEvent() {
		t.Fatal("the protection must be off")
	}
	return &pooledEvent{
		uploadEvent: uploadEvent{dataID: dataID, size: size, total: uint64(size), finished: true, start: start},
		buf:         TakeBuffer(size),
	}
}

// TestInflightAccountingBalance: every path that drops events from a buffer gives back what the
// admission charged
func TestInflightAccountingBalance(t *testing.T) {
	withInflight(t, 0, 200, func() {
		fill := func(n int, start uint64) *Buffer {
			b := NewBuffer()
			for i := 0; i < n; i++ {
				b.AppendDataEvent(newPooledEvent(t, uint64(i+1), 100+i*997%MaxEventBufferSize, start))
			}
			return b
		}
		check := func(name string) {
			if InflightBytes() != 0 || eventsInUse.Load() != 0 || bytesInUse.Load() != 0 {
				t.Fatalf("%s: in-flight %d events %d bytes %d", name, InflightBytes(), eventsInUse.Load(), bytesInUse.Load())
			}
		}
		fill(20, 0).Clean()
		check("Clean")
		fill(20, 0).ReleaseAll()
		check("ReleaseAll")

		b := fill(20, 0)
		for b.PrepareForReading() {
			b.RemoveCurrentElement()
		}
		check("RemoveCurrentElement")

		// the analyzer path: read a few events, then drop what was read
		b = fill(20, 0)
		b.PrepareForReading()
		if _, err := b.Read(make([]byte, 3000)); err != nil {
			t.Fatal(err)
		}
		b.RemoveReadElements(false)
		b.Clean()
		check("RemoveReadElements")

		// the expiry: events started long ago
		b = fill(20, 1)
		if n := b.DeleteExpireEvents(time.Second); n != 20 {
			t.Fatalf("expired %d", n)
		}
		check("DeleteExpireEvents")

		// an event dropped before it reaches a buffer, and a buffer only taken after the admission
		e := newPooledEvent(t, 1, 5000, 0)
		ReleaseEvent(e.ReleaseBuffer())
		ReleaseEvent(e.ReleaseBuffer()) // nothing left to give back, only the slot
		eventsInUse.Add(1)
		extra := TakeBuffer(3000)
		ReleaseBufferOnly(extra)
		check("direct release")
	})
}

// TestCleanOfSliceReleasesNothing: a body assembled from slices of a buffer (the HTTP/2 request body
// split after maxHTTP2StreamingTime) only borrows the events; cleaning it must not release them again,
// or the in-flight counters drift negative and the budget never trips
func TestCleanOfSliceReleasesNothing(t *testing.T) {
	withInflight(t, 0, 200, func() {
		db := NewBuffer()
		var evs []*pooledEvent
		for i := 1; i <= 3; i++ {
			e := newPooledEvent(t, uint64(i), 4000, 0)
			evs = append(evs, e)
			db.AppendDataEvent(e)
		}
		// 10 frames of 900 bytes: the frames share events, the last event is read only in part
		var body *Buffer
		for f := 0; f < 10; f++ {
			db.PrepareForReading()
			start := db.Position()
			if err := db.ReadUntilBufferFull(make([]byte, 900)); err != nil {
				t.Fatal(f, err)
			}
			body = AppendSlices(true, db, body, db.Slice(true, start, db.Position()))
			db.RemoveReadElements(false)
		}
		if eventsInUse.Load() != 1 {
			t.Fatalf("events in use after parsing %d, want 1 (the head event)", eventsInUse.Load())
		}
		body.Clean()
		if eventsInUse.Load() != 1 || evs[2].buf == nil {
			t.Fatalf("the clean of the body released borrowed events: events %d, head buffer released %v",
				eventsInUse.Load(), evs[2].buf == nil)
		}
		// a single slice and a combination borrow as well
		db.PrepareForReading()
		start := db.Position()
		if err := db.ReadUntilBufferFull(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		slice := db.Slice(true, start, db.Position())
		CombineSlices(true, db, slice, slice).Clean()
		slice.Clean()
		db.ReleaseAll()
		if InflightBytes() != 0 || eventsInUse.Load() != 0 || bytesInUse.Load() != 0 {
			t.Fatalf("in-flight %d events %d bytes %d after the owner is released",
				InflightBytes(), eventsInUse.Load(), bytesInUse.Load())
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLimitDiscovery(t *testing.T) { //nolint:funlen // one subtest per cgroup layout over a shared fixture
	const pid = 4242
	pod := "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice"
	v2Tree := func(t *testing.T, ctrLimit string) string {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "cgroup.controllers"), "cpuset cpu io memory pids\n")
		writeFile(t, filepath.Join(root, pod, "memory.max"), "3221225472\n")
		writeFile(t, filepath.Join(root, pod, "other", "cgroup.procs"), "1\n42\n")
		writeFile(t, filepath.Join(root, pod, "other", "memory.max"), "1000\n")
		ctr := filepath.Join(root, pod, "cri-containerd-abc.scope")
		writeFile(t, filepath.Join(ctr, "cgroup.procs"), "17\n4242\n")
		writeFile(t, filepath.Join(ctr, "memory.max"), ctrLimit)
		writeFile(t, filepath.Join(ctr, "memory.current"), "1000000\n")
		writeFile(t, filepath.Join(ctr, "memory.stat"), "anon 600000\ninactive_file 300000\n")
		writeFile(t, filepath.Join(root, "system.slice", "cgroup.procs"), "4242\n") // not under kubepods
		return root
	}
	meminfo := func(t *testing.T) string {
		p := filepath.Join(t.TempDir(), "meminfo")
		writeFile(t, p, "MemTotal:        8388608 kB\nMemFree:         1000 kB\n")
		return p
	}
	selfCgroup := func(t *testing.T, content string) string {
		p := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, p, content)
		return p
	}

	t.Run("v2 own cgroup from /proc/self/cgroup", func(t *testing.T) {
		root := v2Tree(t, "2147483648\n")
		d := limitDiscovery{cgroupRoot: root, pid: 1, selfCgroup: selfCgroup(t, "0::/"+pod+"/cri-containerd-abc.scope\n")}
		if got := d.discover(); got.limit != 2<<30 {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("v2 host PID scan, limit from the pod", func(t *testing.T) {
		root := v2Tree(t, "max\n")
		d := limitDiscovery{cgroupRoot: root, pid: pid, selfCgroup: selfCgroup(t, "0::/\n"), meminfo: meminfo(t)}
		got := d.discover()
		if got.limit != 3<<30 || !strings.HasPrefix(got.source, "cgroup "+filepath.Join(root, pod, "memory.max")) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("v2 host PID scan, container limit is the smallest", func(t *testing.T) {
		root := v2Tree(t, "2147483648\n")
		got := limitDiscovery{cgroupRoot: root, pid: pid, selfCgroup: selfCgroup(t, "0::/\n")}.discover()
		if got.limit != 2<<30 {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("v1 host PID scan", func(t *testing.T) {
		root := t.TempDir()
		mem := filepath.Join(root, "memory")
		writeFile(t, filepath.Join(mem, "memory.limit_in_bytes"), "9223372036854771712\n")
		writeFile(t, filepath.Join(mem, "memory.usage_in_bytes"), "99999999\n")
		ctr := filepath.Join(mem, "kubepods", "burstable", "podx", "abc")
		writeFile(t, filepath.Join(ctr, "cgroup.procs"), "4242\n")
		writeFile(t, filepath.Join(ctr, "memory.limit_in_bytes"), "1073741824\n")
		writeFile(t, filepath.Join(ctr, "memory.usage_in_bytes"), "5000\n")
		writeFile(t, filepath.Join(ctr, "memory.stat"), "total_inactive_file 1000\n")
		d := limitDiscovery{cgroupRoot: root, pid: pid, selfCgroup: selfCgroup(t, "12:memory:/\n11:cpu,cpuacct:/\n")}
		if got := d.discover(); got.limit != 1<<30 {
			t.Fatalf("%+v", got)
		}
	})
	// kubelet limits kubepods.slice (kubepods on v1) to the node allocatable: that limit and the usage of
	// every pod on the node must never become the agent's
	nodeTree := func(t *testing.T, v2 bool) (root, ctr string) {
		root = t.TempDir()
		limitFile, usageFile, mem := "memory.max", "memory.current", root
		qos := filepath.Join("kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-podA.slice")
		if v2 {
			writeFile(t, filepath.Join(root, "cgroup.controllers"), "cpu memory\n")
		} else {
			limitFile, usageFile, mem = "memory.limit_in_bytes", "memory.usage_in_bytes", filepath.Join(root, "memory")
			qos = filepath.Join("kubepods", "besteffort", "podA")
		}
		node := filepath.Join(mem, strings.SplitN(qos, string(filepath.Separator), 2)[0])
		writeFile(t, filepath.Join(node, limitFile), "16000000000\n")
		writeFile(t, filepath.Join(node, usageFile), "14000000000\n")
		writeFile(t, filepath.Join(filepath.Dir(filepath.Join(mem, qos)), limitFile), "15000000000\n") // the QoS class
		ctr = filepath.Join(mem, qos, "cri-containerd-x.scope")
		writeFile(t, filepath.Join(ctr, limitFile), "max\n")
		writeFile(t, filepath.Join(ctr, usageFile), "200000000\n")
		writeFile(t, filepath.Join(ctr, "cgroup.procs"), "4242\n")
		return root, ctr
	}
	t.Run("v2 host PID scan, no limit below the node level", func(t *testing.T) {
		root, _ := nodeTree(t, true)
		d := limitDiscovery{cgroupRoot: root, pid: pid, selfCgroup: selfCgroup(t, "0::/\n")}
		if got := d.discover(); got.limit != 0 {
			t.Fatalf("the node allocatable must not be the limit: %+v", got)
		}
		d.meminfo = meminfo(t)
		if got := d.discover(); got.limit != 8<<30 || !strings.HasPrefix(got.source, "host memory") {
			t.Fatalf("without a cgroup limit the memory of the host is the limit: %+v", got)
		}
	})
	t.Run("v2 host cgroup namespace, no limit below the node level", func(t *testing.T) {
		root, ctr := nodeTree(t, true)
		rel, _ := filepath.Rel(root, ctr)
		d := limitDiscovery{cgroupRoot: root, selfCgroup: selfCgroup(t, "0::/"+rel+"\n"), meminfo: meminfo(t)}
		if got := d.discover(); got.limit != 8<<30 {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("v1 host PID scan, no limit below the node level", func(t *testing.T) {
		root, _ := nodeTree(t, false)
		d := limitDiscovery{cgroupRoot: root, pid: pid, selfCgroup: selfCgroup(t, "12:memory:/\n")}
		if got := d.discover(); got.limit != 0 {
			t.Fatalf("the node allocatable must not be the limit: %+v", got)
		}
	})
	t.Run("node level cgroups", func(t *testing.T) {
		for dir, want := range map[string]bool{
			"/kubepods.slice": true, "/kubepods.slice/kubepods-burstable.slice": true,
			"/kubepods.slice/kubepods-besteffort.slice": true, "/kubepods": true, "/kubepods/burstable": true,
			"/kubepods/besteffort": true, "/kubepods.slice/kubepods-pod1.slice": false,
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice": false,
			"/kubepods/burstable/pod1": false, "/kubepods/pod1": false, "/system.slice/burstable": false,
			"/kubepods/pod1/cri-containerd-x.scope": false,
		} {
			if got := isNodeLevelCgroup(dir); got != want {
				t.Errorf("%s: %v, want %v", dir, got, want)
			}
		}
	})
	t.Run("host memory", func(t *testing.T) {
		d := limitDiscovery{cgroupRoot: t.TempDir(), pid: pid, meminfo: meminfo(t)}
		if got := d.discover(); got.limit != 8<<30 {
			t.Fatalf("%+v", got)
		}
		d.meminfo = filepath.Join(t.TempDir(), "none")
		if got := d.discover(); got.limit != 0 {
			t.Fatalf("no limit without /proc/meminfo: %+v", got)
		}
	})
}

// stubSoftLimit replaces the runtime and the environment the soft limit setup uses
func stubSoftLimit(t *testing.T, set func(int64) int64, gomemlimit bool) {
	savedSet, savedLookup := setMemoryLimit, lookupEnv
	t.Cleanup(func() { setMemoryLimit, lookupEnv = savedSet, savedLookup })
	setMemoryLimit = set
	lookupEnv = func(key string) (string, bool) {
		if key == "GOMEMLIMIT" && gomemlimit {
			return "1500MiB", true
		}
		return "", false
	}
}

// TestGoSoftLimit: 90% of the memory limit, once, unless GOMEMLIMIT is set
func TestGoSoftLimit(t *testing.T) {
	calls := 0
	var got int64
	stubSoftLimit(t, func(v int64) int64 { calls++; got = v; return 0 }, false)
	if desc := applyGoSoftLimit(2 << 30); calls != 1 || got != (2<<30)*90/100 || !strings.Contains(desc, "1843 MB") {
		t.Fatalf("calls %d, limit %d: %s", calls, got, desc)
	}
	calls = 0
	stubSoftLimit(t, func(int64) int64 { calls++; return 0 }, true)
	if desc := applyGoSoftLimit(2 << 30); calls != 0 || !strings.Contains(desc, "GOMEMLIMIT=1500MiB") {
		t.Fatalf("an explicit GOMEMLIMIT must be kept: calls %d, %s", calls, desc)
	}
}
