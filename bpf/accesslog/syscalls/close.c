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
#include "socket.h"
#include "socket_opts.h"
#include "../process/process.h"
#include "../common/connection.h"

static __inline void process_close_sock(void* ctx, __u64 id, struct sock_close_args_t *args, int ret) {
    __u32 tgid = (__u32)(id >> 32);
    if (args->fd < 0) {
        return;
    }

    submit_close_connection(ctx, tgid, args->fd, args->start_nacs, ret);
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_enter_close(struct syscall_trace_enter *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct sock_close_args_t close_args = {};
    close_args.fd = (__u32)ctx->args[0];
    close_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&closing_args, &id, &close_args, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint_exit_close(struct syscall_trace_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_close_args_t *close_args = bpf_map_lookup_elem(&closing_args, &id);
    if (close_args) {
        process_close_sock(ctx, id, close_args, (int)ctx->ret);
    }

    bpf_map_delete_elem(&closing_args, &id);
	return 0;
}