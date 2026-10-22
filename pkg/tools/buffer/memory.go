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
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/docker/go-units"

	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

// memory protection state (see the comment in buffer.go)
var (
	memoryThreshold        atomic.Int64 // bytes, 0: protection off
	memoryUsage            atomic.Int64 // last sampled usage, bytes
	memoryProtectionActive atomic.Bool
	memorySamplerOnce      sync.Once
	memorySampleInterval   = 500 * time.Millisecond
)

// cgroupMemory locates the memory usage and limit files of the cgroup this process runs in. The cgroup
// path comes from /proc/self/cgroup, so it also works when the host's /sys is mounted into the container.
type cgroupMemory struct {
	usageFile, limitFile string
	// statFile holds the memory breakdown; the reclaimable page cache is subtracted from the usage so
	// the protection reacts to the working set (what the OOM killer accounts) and not to file cache
	statFile    string
	inactiveKey string
}

func detectCgroupMemory() *cgroupMemory {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return nil
	}
	defer f.Close()
	var v2Path, v1Path string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			v2Path = parts[2]
		case strings.Contains(","+parts[1]+",", ",memory,"):
			v1Path = parts[2]
		}
	}
	candidates := make([]cgroupMemory, 0, 4)
	if v2Path != "" {
		candidates = append(candidates, newCgroupV2(filepath.Join("/sys/fs/cgroup", v2Path)))
	}
	if v1Path != "" {
		candidates = append(candidates, newCgroupV1(filepath.Join("/sys/fs/cgroup/memory", v1Path)))
	}
	// the container's own cgroup root (when /sys/fs/cgroup is namespaced)
	candidates = append(candidates, newCgroupV2("/sys/fs/cgroup"), newCgroupV1("/sys/fs/cgroup/memory"))
	for i := range candidates {
		if _, err := readCgroupValue(candidates[i].usageFile); err == nil {
			return &candidates[i]
		}
	}
	return nil
}

func newCgroupV2(dir string) cgroupMemory {
	return cgroupMemory{
		usageFile: filepath.Join(dir, "memory.current"), limitFile: filepath.Join(dir, "memory.max"),
		statFile: filepath.Join(dir, "memory.stat"), inactiveKey: "inactive_file",
	}
}

func newCgroupV1(dir string) cgroupMemory {
	return cgroupMemory{
		usageFile: filepath.Join(dir, "memory.usage_in_bytes"), limitFile: filepath.Join(dir, "memory.limit_in_bytes"),
		statFile: filepath.Join(dir, "memory.stat"), inactiveKey: "total_inactive_file",
	}
}

// workingSet is the cgroup usage without the reclaimable page cache, the same definition the kubelet
// uses: file cache the agent produced by reading binaries, BTF or /proc must not trigger the protection
func (c *cgroupMemory) workingSet() (int64, error) {
	usage, err := readCgroupValue(c.usageFile)
	if err != nil {
		return 0, err
	}
	if inactive := c.readStat(c.inactiveKey); inactive > 0 && inactive < usage {
		usage -= inactive
	}
	return usage, nil
}

func (c *cgroupMemory) readStat(key string) int64 {
	data, err := os.ReadFile(c.statFile)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || name != key {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return 0
}

// readCgroupValue returns the value of a cgroup memory file; "max" (no limit) is reported as 0
func readCgroupValue(file string) (int64, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(data))
	if text == "max" {
		return 0, nil
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, err
	}
	// cgroup v1 reports "no limit" as a huge number
	if v >= math.MaxInt64/2 {
		return 0, nil
	}
	return v, nil
}

// goHeapUsage is the usage source when the limit comes from GOMEMLIMIT (or no cgroup accounting is
// available): the live heap plus everything outside the heap (stacks, metadata, ...). The total runtime
// memory is not usable here, because under GOMEMLIMIT the GC deliberately lets the heap grow up to the
// limit before collecting, so the protection would trip on garbage instead of on live data.
func goHeapUsage() int64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/gc/heap/live:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
	}
	metrics.Read(samples)
	value := func(i int) (int64, bool) {
		if samples[i].Value.Kind() != metrics.KindUint64 {
			return 0, false
		}
		return int64(samples[i].Value.Uint64()), true
	}
	total, ok := value(0)
	if !ok {
		return 0
	}
	released, _ := value(1)
	live, liveOK := value(2)
	objects, objectsOK := value(3)
	unused, unusedOK := value(4)
	free, freeOK := value(5)
	if liveOK && objectsOK && unusedOK && freeOK {
		// replace the heap classes by the live heap, keep stacks / metadata / other
		if usage := total - objects - unused - free - released + live; usage > 0 {
			return usage
		}
	}
	return total - released
}

// EnableMemoryProtection drops new socket data events while the process memory usage is at or above
// `percent` of its memory limit (the cgroup limit, or GOMEMLIMIT when the cgroup has none). An absolute
// threshold in bytes overrides the percentage when it is positive. It returns a description of what was
// configured, or an error when no limit could be determined (the protection then stays off).
func EnableMemoryProtection(percent int, absolute int64) (string, error) {
	cg := detectCgroupMemory()
	var limit int64
	source := ""
	if cg != nil {
		if v, err := readCgroupValue(cg.limitFile); err == nil && v > 0 {
			limit, source = v, "cgroup limit "+cg.limitFile
		}
	}
	if limit == 0 {
		if v := debug.SetMemoryLimit(-1); v > 0 && v < math.MaxInt64 {
			limit, source = v, "GOMEMLIMIT"
			// the threshold is a share of the Go runtime limit, so the usage must be the Go runtime's
			// own usage: comparing it against the cgroup usage (page cache, BPF maps, other processes
			// of the cgroup) would keep the protection permanently active
			cg = nil
		}
	}
	threshold := absolute
	if threshold <= 0 {
		if limit == 0 {
			memoryThreshold.Store(0)
			hint := ""
			if cg == nil {
				// a container that mounts the host's /sys over /sys sees the host cgroup tree, where the
				// path of /proc/self/cgroup ("/" under a private cgroup namespace) is the root cgroup and
				// has no memory accounting at all
				hint = ", the cgroup of the process could not be read (the host /sys may be mounted over" +
					" /sys): set GOMEMLIMIT or the absolute max_memory instead"
			}
			return "", fmt.Errorf("no memory limit found (no cgroup limit, no GOMEMLIMIT)%s: memory protection disabled", hint)
		}
		if percent <= 0 || percent > 100 {
			percent = 90
		}
		threshold = limit * int64(percent) / 100
	}
	memoryThreshold.Store(threshold)
	memorySamplerOnce.Do(func() { go sampleMemory(cg) })
	usageSource := "go runtime live heap"
	if cg != nil {
		usageSource = "cgroup working set " + cg.usageFile
	}
	return fmt.Sprintf("threshold %d MB (%d%% of %d MB, %s), usage from %s", threshold>>20, percent, limit>>20, source, usageSource), nil
}

// EnableMemoryProtectionFromConfig applies the configuration values (percent of the limit, optional
// absolute size such as "1GB") and logs the outcome
func EnableMemoryProtectionFromConfig(percent int, absolute string) {
	var abs int64
	if strings.TrimSpace(absolute) != "" {
		if v, err := units.RAMInBytes(absolute); err == nil {
			abs = v
		} else {
			log.Warnf("invalid max_memory %q: %v", absolute, err)
		}
	}
	if percent <= 0 && abs <= 0 {
		log.Infof("memory protection disabled (max_memory_percent %d, max_memory %q)", percent, absolute)
		return
	}
	desc, err := EnableMemoryProtection(percent, abs)
	if err != nil {
		log.Warnf("%v", err)
		return
	}
	log.Infof("memory protection enabled: %s", desc)
}

// minForcedGCInterval bounds how often the sampler may force a full collection: it is a stop-the-world
// GC plus a scavenge, and the usage hovering around the threshold would otherwise trigger one every
// sample exactly while the agent is already saturated
const minForcedGCInterval = 10 * time.Second

func sampleMemory(cg *cgroupMemory) {
	var lastForcedGC time.Time
	for {
		var usage int64
		if cg != nil {
			if v, err := cg.workingSet(); err == nil {
				usage = v
			}
		}
		if usage == 0 {
			usage = goHeapUsage()
		}
		if applyMemorySample(usage) && time.Since(lastForcedGC) >= minForcedGCInterval {
			// give the released buffers back to the OS so the sampled usage follows the real one and
			// the protection is released again instead of staying on until the next GC cycle
			debug.FreeOSMemory()
			lastForcedGC = time.Now()
		}
		time.Sleep(memorySampleInterval)
	}
}

// applyMemorySample records the sampled usage and switches the protection on or off; it reports
// whether the protection has just been activated
func applyMemorySample(usage int64) bool {
	memoryUsage.Store(usage)
	threshold := memoryThreshold.Load()
	active := threshold > 0 && usage >= threshold
	if memoryProtectionActive.Swap(active) == active {
		return false
	}
	if active {
		log.Warnf("memory protection active: usage %d MB reached the threshold %d MB, new socket data events "+
			"are dropped; %d events are still held by the analysis (%d MB)",
			usage>>20, threshold>>20, eventsInUse.Load(), eventsInUse.Load()*20480>>20)
		return true
	}
	log.Infof("memory protection released: usage %d MB is below the threshold %d MB, %d events held by the analysis",
		usage>>20, threshold>>20, eventsInUse.Load())
	return false
}

// the agent cannot be operated on a heap profile: these are the numbers that say whether the
// analysis is keeping up with the kernel, and they are the first thing to look at when it is not
func init() {
	telemetry.Register("rover_socket_data_events_in_use",
		"Socket data events held by the analysis, each holding a buffer of the upload chunk size",
		telemetry.Gauge, func() float64 { return float64(eventsInUse.Load()) })
	telemetry.Register("rover_socket_data_events_dropped_total",
		"Socket data events refused because the memory protection was active",
		telemetry.Counter, func() float64 { return float64(droppedByLimit.Load()) })
	telemetry.Register("rover_memory_usage_bytes",
		"Memory usage of the process as the memory protection measures it",
		telemetry.Gauge, func() float64 { return float64(memoryUsage.Load()) })
	telemetry.Register("rover_memory_threshold_bytes",
		"Usage at which new socket data events are dropped, 0 when the protection is off",
		telemetry.Gauge, func() float64 { return float64(memoryThreshold.Load()) })
	telemetry.Register("rover_memory_protection_active",
		"1 while the memory protection is dropping new socket data events",
		telemetry.Gauge, func() float64 {
			if memoryProtectionActive.Load() {
				return 1
			}
			return 0
		})
}
