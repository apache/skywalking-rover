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
	"bytes"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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

func cgroupLimitFile(dir string, v2 bool) string {
	if v2 {
		return filepath.Join(dir, "memory.max")
	}
	return filepath.Join(dir, "memory.limit_in_bytes")
}

// memoryLimit is the memory the agent can be allocated and where that number came from
type memoryLimit struct {
	limit  int64
	source string
}

// limitDiscovery finds the memory the agent can be allocated. The fields are the inputs, so tests can
// point it at a fake cgroup tree.
type limitDiscovery struct {
	cgroupRoot string // /sys/fs/cgroup
	selfCgroup string // /proc/self/cgroup
	meminfo    string // /proc/meminfo
	pid        int
}

func defaultLimitDiscovery() limitDiscovery {
	return limitDiscovery{cgroupRoot: "/sys/fs/cgroup", selfCgroup: "/proc/self/cgroup", meminfo: "/proc/meminfo", pid: os.Getpid()}
}

// discover tries, in order: the cgroup named by /proc/self/cgroup, the cgroup of our PID found in the
// host cgroup tree, and without a cgroup limit the memory of the host. A zero limit means none was found.
func (d limitDiscovery) discover() memoryLimit {
	if limit, limitFile := d.selfCgroupLimit(); limit > 0 {
		return memoryLimit{limit: limit, source: "cgroup " + limitFile}
	}
	// the DaemonSet runs with hostPID and the host /sys: /proc/self/cgroup reads "/" under a private
	// cgroup namespace, but our PID is a host PID and its cgroup is in the tree
	if scanned := d.scanHostCgroup(); scanned != nil {
		if limit, limitFile := effectiveLimit(scanned.dir, scanned.root, scanned.v2); limit > 0 {
			return memoryLimit{limit: limit, source: "cgroup " + limitFile + " (host cgroup tree)"}
		}
	}
	if total := d.hostMemory(); total > 0 {
		return memoryLimit{limit: total, source: "host memory " + d.meminfo + " (no cgroup limit)"}
	}
	return memoryLimit{}
}

// hostMemory is MemTotal of /proc/meminfo in bytes, 0 when it cannot be read
func (d limitDiscovery) hostMemory() int64 {
	data, err := os.ReadFile(d.meminfo)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || kb <= 0 {
			return 0
		}
		return kb << 10
	}
	return 0
}

// selfCgroupLimit reads the cgroup named by /proc/self/cgroup (and the namespaced cgroup root): the
// limit and the file that holds it
func (d limitDiscovery) selfCgroupLimit() (limit int64, limitFile string) {
	f, err := os.Open(d.selfCgroup)
	if err != nil {
		return 0, ""
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
	v1Root := filepath.Join(d.cgroupRoot, "memory")
	if v2Path != "" {
		if limit, file := effectiveLimit(filepath.Join(d.cgroupRoot, v2Path), d.cgroupRoot, true); limit > 0 {
			return limit, file
		}
	}
	if v1Path != "" {
		if limit, file := effectiveLimit(filepath.Join(v1Root, v1Path), v1Root, false); limit > 0 {
			return limit, file
		}
	}
	// the container's own cgroup root (when /sys/fs/cgroup is namespaced)
	for _, file := range []string{cgroupLimitFile(d.cgroupRoot, true), cgroupLimitFile(v1Root, false)} {
		if limit, err := readCgroupValue(file); err == nil && limit > 0 {
			return limit, file
		}
	}
	return 0, ""
}

// effectiveLimit walks from dir up to (not including) root and returns the smallest limit of the
// container and pod cgroups, with the file that holds it: a container cgroup without a limit is still
// bounded by its pod. The walk stops at the node level (kubepods) and QoS (burstable, besteffort)
// cgroups: their limit is the node allocatable shared by every pod, not the agent's.
func effectiveLimit(dir, root string, v2 bool) (limit int64, limitFile string) {
	dir, root = filepath.Clean(dir), filepath.Clean(root)
	for d := dir; d != root && strings.HasPrefix(d, root+string(filepath.Separator)); d = filepath.Dir(d) {
		if isNodeLevelCgroup(d) {
			break
		}
		file := cgroupLimitFile(d, v2)
		if l, err := readCgroupValue(file); err == nil && l > 0 && (limit == 0 || l < limit) {
			limit, limitFile = l, file
		}
	}
	return limit, limitFile
}

// isNodeLevelCgroup tells the cgroups kubelet keeps above the pods: kubepods (cgroupfs) or kubepods.slice
// (systemd) and the QoS classes under it, kubepods-burstable.slice / kubepods-besteffort.slice or
// burstable / besteffort
func isNodeLevelCgroup(dir string) bool {
	name := filepath.Base(dir)
	if strings.HasPrefix(name, "kubepods") && !strings.Contains(name, "-pod") {
		return true
	}
	return (name == "burstable" || name == "besteffort") && strings.HasPrefix(filepath.Base(filepath.Dir(dir)), "kubepods")
}

type scannedCgroup struct {
	dir, root string
	v2        bool
}

// scanHostCgroup looks for the cgroup whose cgroup.procs lists our PID under the kubepods hierarchies
// of the host cgroup tree (v2 unified, else the v1 memory controller). It runs once at startup.
func (d limitDiscovery) scanHostCgroup() *scannedCgroup {
	if d.pid <= 0 {
		return nil
	}
	pid := []byte(strconv.Itoa(d.pid))
	v1Root := filepath.Join(d.cgroupRoot, "memory")
	roots := []scannedCgroup{{root: v1Root}}
	if controllers, err := os.ReadFile(filepath.Join(d.cgroupRoot, "cgroup.controllers")); err == nil &&
		bytes.Contains(controllers, []byte("memory")) {
		roots = []scannedCgroup{{root: d.cgroupRoot, v2: true}}
	}
	for _, r := range roots {
		entries, err := os.ReadDir(r.root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "kubepods") {
				continue
			}
			if dir := findPIDCgroup(filepath.Join(r.root, e.Name()), pid); dir != "" {
				return &scannedCgroup{dir: dir, root: r.root, v2: r.v2}
			}
		}
	}
	return nil
}

func findPIDCgroup(top string, pid []byte) string {
	found := ""
	_ = filepath.WalkDir(top, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		if procsContain(filepath.Join(path, "cgroup.procs"), pid) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func procsContain(file string, pid []byte) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	for len(data) > 0 {
		line, rest, _ := bytes.Cut(data, []byte{'\n'})
		if bytes.Equal(bytes.TrimSpace(line), pid) {
			return true
		}
		data = rest
	}
	return false
}
