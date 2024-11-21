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
#include "process.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} process_execute_queue SEC(".maps");

struct process_execute_event {
    __u32 pid;
};

struct trace_event_raw_sched_process_fork {
        struct trace_entry ent;
        char parent_comm[16];
        __u32 parent_pid;
        char child_comm[16];
        __u32 child_pid;
        char __data[0];
}  __attribute__((preserve_access_index)) ;

SEC("tracepoint/sched/sched_process_fork")
int tracepoint_sched_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    __u32 tgid = ctx->parent_pid;
    // adding to the monitor
    __u32 v = 1;
    bpf_map_update_elem(&process_monitor_control, &tgid, &v, 0);

    // send to the user-space to check the pid should monitor or not
    struct process_execute_event event = {};
    event.pid = tgid;
    bpf_perf_event_output(ctx, &process_execute_queue, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}