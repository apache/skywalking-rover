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
#include "offcpu.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    int monitor_pid;
    asm("%0 = MONITOR_PID ll" : "=r"(monitor_pid));

    __u32 pid, tgid;
    __u64 ts, *tsp;

    struct task_struct *prev = (void *) PT_REGS_PARM1(ctx);
    pid = _KERNEL(prev->pid);
    tgid = _KERNEL(prev->tgid);

    // in kernel, tgid means the process id
    // monitor_pid is the same concept with process id
    // only the monitor pid is same with previous process id could record the start time
    if (tgid == monitor_pid) {
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);
    }

    // if current process have record start time in the map
    // means the monitored process switch to the on-cpu
    struct task_struct *current = (void *)bpf_get_current_task();
    pid = _(current->pid);
    tgid = _(current->tgid);
    if (tgid != monitor_pid) {
        return 0;
    }
    tsp = bpf_map_lookup_elem(&starts, &pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate the duration(on->off to off->on)
    __u64 t_start = *tsp;
    __u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&starts, &pid);
    if (t_start > t_end) {
        return 0;
    }

    // create map key
    struct key_t key = {};
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));

    // add counters
    struct value_t *val;
    val = bpf_map_lookup_elem(&counts, &key);
    if (!val) {
        struct value_t value = {};
         bpf_map_update_elem(&counts, &key, &value, BPF_NOEXIST);
         val = bpf_map_lookup_elem(&counts, &key);
         if (!val)
             return 0;
    }
    (*val).counts += 1;
    (*val).deltas += t_end - t_start;
    return 0;
}