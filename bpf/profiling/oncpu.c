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

#include "api.h"
#include "oncpu.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("perf_event")
int do_perf_event(struct pt_regs *ctx) {
    int monitor_pid;
    asm("%0 = MONITOR_PID ll" : "=r"(monitor_pid));

    // only match the same pid
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid != monitor_pid) {
        return 0;
    }

    // create map key
    struct key_t key = {};

    // get stacks
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);

    __u32 *val;
    val = bpf_map_lookup_elem(&counts, &key);
    if (!val) {
        __u32 count = 0;
        bpf_map_update_elem(&counts, &key, &count, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&counts, &key);
        if (!val)
            return 0;
    }
    (*val) += 1;
    return 0;
}