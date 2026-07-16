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
    __u32 pad0;
    __u64 cgroup_id;
    // comm is the kernel's task name. User space prefers /proc/<pid>/cmdline for the process
    // name and only falls back to this when the process is already gone - which is the whole
    // point of reporting a short-lived process, so its identity must not depend on /proc still
    // being readable by the time the event is consumed.
    char comm[16];
};

struct trace_event_raw_sched_process_fork {
        struct trace_entry ent;
        char parent_comm[16];
        __u32 parent_pid;
        char child_comm[16];
        __u32 child_pid;
        char __data[0];
}  __attribute__((preserve_access_index)) ;

struct trace_event_raw_sched_process_exec {
        struct trace_entry ent;
        __u32 __data_loc_filename;
        __u32 pid;
        __u32 old_pid;
        char __data[0];
}  __attribute__((preserve_access_index)) ;

// report_running_process starts tracing the current process and tells user space about it, unless
// it is filtered out or already known. Shared by the fork and the exec tracepoint, which differ
// only in *when* they notice a process, never in how it is judged.
static __always_inline void report_running_process(void *ctx) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // Reject what we are not interested in before emitting anything. This is the check that keeps
    // the machine-wide fork rate off the perf queue and out of user space, so it runs first, ahead
    // of the process_monitor_control lookup below: the host processes it rejects fork far more than
    // the monitored pods do, and this way they cost a single lookup rather than two.
    __u64 cgroup_id = 0;
    if (cgroup_filter_enabled) {
        // Preferred: the cgroup is known up front, so a host process never reaches user space.
        cgroup_id = bpf_get_current_cgroup_id();
        if (!bpf_map_lookup_elem(&cgroup_monitor_allowlist, &cgroup_id)) {
            return;
        }
    } else {
        // Fallback: nothing is known up front, so every process gets reported once and only the
        // ones user space rejected are filtered out from then on.
        if (bpf_map_lookup_elem(&process_not_monitor, &tgid)) {
            return;
        }
    }

    // Already decided for this process - nothing new to tell user space. Without this a
    // thread-happy process (a JVM spawning workers) would emit an event and force a user-space
    // re-check on every single clone; with it, each process costs one event per lifetime.
    if (bpf_map_lookup_elem(&process_monitor_control, &tgid)) {
        return;
    }

    // Start tracing immediately, optimistically: the process may be gone long before the
    // periodic discovery would have found it. User space still gets the final say and removes
    // the entry if the process turns out not to be monitorable.
    __u32 v = 1;
    bpf_map_update_elem(&process_monitor_control, &tgid, &v, 0);

    struct process_execute_event event = {};
    event.pid = tgid;
    event.cgroup_id = cgroup_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_perf_event_output(ctx, &process_execute_queue, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

// A process that execs is reported here rather than at fork, because only here is it the thing it
// is going to be: the runtime forks a helper from its *own* cgroup (containerd-shim sits in a host
// cgroup, e.g. /podruntime/docker), and that child only joins the container's cgroup and namespaces
// afterwards, right before execve. Judging at fork would therefore test the shim's cgroup and
// reject every process started through `kubectl exec` - exactly the short-lived kind this exists
// for. At exec the process already carries its final cgroup, pid and name.
SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct trace_event_raw_sched_process_exec* ctx) {
    report_running_process(ctx);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int tracepoint_sched_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    // Reclaim any entry left behind by a dead task that used to own the child's pid.
    //
    // The kernel allocates every task's pid - thread (TID) and process (TGID) alike - from one
    // global allocator, so a pid identifies at most one task at a time. ctx->child_pid was just
    // handed out by copy_process(), which proves the pid was free a moment ago, which in turn
    // proves any entry still keyed by it belongs to a task that has already exited: a live task
    // never releases its pid, so the child could not have been given the number. Deleting here
    // is therefore safe (it can never evict a live process) and sufficient (a pid can only be
    // reused by going through a fork, so this runs before the new owner executes a single
    // instruction). That removes the need for an exit tracepoint or a periodic sweep.
    //
    // This has to happen for every fork, before any of the filtering below can return early.
    __u32 child = ctx->child_pid;
    bpf_map_delete_elem(&process_monitor_control, &child);
    bpf_map_delete_elem(&process_not_monitor, &child);

    // Report the forking process itself. The exec tracepoint covers anything that starts a new
    // program; this additionally catches a process that only ever forks - and, because
    // bpf_get_current_pid_tgid() is read inside, it reports the real TGID rather than
    // ctx->parent_pid, which for a multi-threaded app (e.g. a JVM worker thread forking) is the
    // thread's TID that the periodic /proc scan never lists, making the process flip between
    // detected and dead.
    report_running_process(ctx);
    return 0;
}