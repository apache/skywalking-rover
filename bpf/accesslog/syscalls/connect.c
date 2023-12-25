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

struct trace_point_enter_connect {
    __u64 pad_0;
    int __syscall_nr;
    __u32 pad_1;
    int fd;
    struct sockaddr * uservaddr;
};
struct trace_point_exit_connect {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    __u64 ret;
};

struct trace_point_enter_accept {
    __u64 pad_0;
    int __syscall_nr;
    __u32 pad_1;
    int fd;
    struct sockaddr * upeer_sockaddr;
};
struct trace_point_exit_accept {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    long ret;
};

static __inline void process_connect(void *ctx, __u64 id, struct connect_args_t *connect_args, long ret) {
    bool success = true;
    if (ret < 0 && ret != -EINPROGRESS) {
        success = false;
    }
    if (connect_args->fd < 0) {
        return;
    }
    __u32 tgid = id >> 32;
    struct sock *sock = connect_args->sock;
    struct socket *s = _(sock->sk_socket);
    submit_new_connection(ctx, success, SOCKET_OPTS_TYPE_CONNECT, tgid, connect_args->fd, connect_args->start_nacs, connect_args->addr, s, &connect_args->remote, 0);
}

static __inline void process_accept(void *ctx, __u64 id, struct accept_args_t *accept_args, long ret) {
    int fd = (int) ret;
    __u32 tgid = id >> 32;
    struct socket *s = accept_args->socket;
    submit_new_connection(ctx, true, SOCKET_OPTS_TYPE_ACCEPT, tgid, fd, accept_args->start_nacs, accept_args->addr, s, NULL, 0);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_enter_connect(struct trace_point_enter_connect *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct connect_args_t connect_args = {};
    connect_args.fd = ctx->fd;
    connect_args.addr = ctx->uservaddr;
    connect_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint_exit_connect(struct trace_point_exit_connect *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args) {
        process_connect(ctx, id, connect_args, ctx->ret);
    }

    bpf_map_delete_elem(&conecting_args, &id);
	return 0;
}

SEC("kprobe/tcp_connect")
int tcp_connect(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);;
    if (connect_args) {
        connect_args->sock = (void *)PT_REGS_PARM1(ctx);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint_enter_accept(struct trace_point_enter_accept *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct accept_args_t accept_args = {};
    accept_args.addr = ctx->upeer_sockaddr;
    accept_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&accepting_args, &id, &accept_args, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint_exit_accept(struct trace_point_exit_accept *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_args = bpf_map_lookup_elem(&accepting_args, &id);
    if (accept_args) {
        process_accept(ctx, id, accept_args, ctx->ret);
    }

    bpf_map_delete_elem(&accepting_args, &id);
	return 0;
}

SEC("kretprobe/sock_alloc")
int sock_alloc_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_sock = bpf_map_lookup_elem(&accepting_args, &id);
    if (accept_sock) {
        struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
        accept_sock->socket = sock;
    }
    return 0;
}

#include "connect_conntrack.c"