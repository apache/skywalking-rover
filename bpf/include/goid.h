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

#include "api.h"
#include "symbol_offsets.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} go_tgid_goid_map SEC(".maps");
static __inline __u64 get_goid(__u64 id) {
    __u32 tgid = id >> 32;
    struct go_tls_args_symaddr_t* symaddrs = get_go_tls_args_symaddr(tgid);
    if (symaddrs == NULL) {
       return 0;
    }

    // Get fsbase from `struct task_struct`.
    const struct task_struct* task_ptr = (struct task_struct*)bpf_get_current_task();
    if (!task_ptr) {
        return 0;
    }

    __u64 g_addr;
#if defined(bpf_target_x86)
    // thread local storage
    const void* fs_base;
    bpf_probe_read_kernel(&fs_base, sizeof(fs_base), &(task_ptr->thread.fsbase));

    // struct g location
    int32_t g_addr_offset = -8;
    bpf_probe_read_user(&g_addr, sizeof(void*), (void*)(fs_base + g_addr_offset));
#else
    const void* tp;
    bpf_probe_read_kernel(&tp, sizeof(tp), &(task_ptr->thread.uw.tp_value));

    int32_t g_addr_offset = 16;
    bpf_probe_read_user(&g_addr, sizeof(void*), (void*)(tp + g_addr_offset));
#endif

    // goid in struct g
    __u64 goid;
    bpf_probe_read_user(&goid, sizeof(void*), (void*)(g_addr + symaddrs->gid_offset));
    return goid;
}