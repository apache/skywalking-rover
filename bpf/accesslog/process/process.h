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

#pragma once

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, __u32);
} process_monitor_control SEC(".maps");

// cgroup_monitor_allowlist holds the cgroup id of every cgroup a monitored process was found in.
// User space fills it from the periodic process discovery (which reads /proc and is therefore
// never gated by this map), and the fork tracepoint reads it to decide, entirely in kernel space,
// whether a forking process is worth reporting. A node runs far more unmonitored host processes
// (kubelet, containerd, systemd, ...) than monitored pod ones, so rejecting them here - before any
// perf event is emitted and before user space touches /proc - is what makes the tracepoint cheap.
//
// Only consulted when cgroup_filter_enabled is set; see process_not_monitor for the fallback.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, __u32);
} cgroup_monitor_allowlist SEC(".maps");

// process_not_monitor is the fallback filter for hosts where the cgroup allowlist cannot be built
// (cgroup v1, or a cgroup tree user space failed to walk). There the tracepoint cannot tell a pod
// process from a host one up front, so it reports every process once and user space records the
// ones it rejected here, which keeps them from being reported again.
//
// It is weaker than the allowlist - every process costs one event and one /proc read instead of
// zero - but still collapses the machine-wide *fork* rate down to one event per process lifetime,
// which is the cost that made this tracepoint unaffordable before.
//
// LRU rather than HASH: entries accumulate for every unmonitored process on the node and nothing
// enumerates them for removal, so eviction has to be the kernel's job. Evicting one only costs a
// re-check, whereas a full map would silently stop recording rejections.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u32);
} process_not_monitor SEC(".maps");

// cgroup_filter_enabled selects between the two filters above. User space sets it at startup after
// probing the host, and it never changes afterwards.
volatile __u32 cgroup_filter_enabled;

volatile __u32 ztunnel_process_pid;

static __inline bool tgid_should_trace(__u32 tgid) {
    __u32 *val = bpf_map_lookup_elem(&process_monitor_control, &tgid);
    if (!val) {
        return false;
    }
    return (*val) == 1 ? true : false;
}

static __inline bool tgid_is_ztunnel(__u32 tgid) {
    return ztunnel_process_pid > 0 && tgid == ztunnel_process_pid ? true : false;
}