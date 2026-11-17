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
#include "../common/sys_attach.h"

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

static __always_inline int sys_enter_connect(void *ctx, __u64 fd, __u64 addr) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false && tgid_is_ztunnel(id >> 32) == false) {
        return 0;
    }

    struct connect_args_t connect_args = {};
    connect_args.fd = (__u32)fd;
    connect_args.addr = (struct sockaddr *)addr;
    connect_args.start_nacs = bpf_ktime_get_ns();
    conecting_args_put(&id, &connect_args);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_enter_connect(struct syscall_trace_enter *ctx) {
    return sys_enter_connect(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1));
}

SYS_FENTRY(connect)
int fentry_enter_connect(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_connect(ctx, SYS_ARG0(regs), SYS_ARG1(regs));
}

static __always_inline int sys_exit_connect(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = conecting_args_get(&id);
    if (connect_args) {
        process_connect(ctx, id, connect_args, ret);
        // (only the thread's own enter puts its entry: one the lookup did not find is not there to delete)
        conecting_args_del(&id);
    }
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint_exit_connect(struct syscall_trace_exit *ctx) {
    return sys_exit_connect(ctx, TP_RET(ctx));
}

SYS_FEXIT(connect)
int fexit_exit_connect(__u64 *ctx) {
    return sys_exit_connect(ctx, SYS_RET(ctx));
}

SEC("kprobe/tcp_connect")
int tcp_connect(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args = conecting_args_get(&id);;
    if (connect_args) {
        connect_args->sock = (void *)PT_REGS_PARM1(ctx);
    }
    return 0;
}

static __always_inline int sys_enter_accept(void *ctx, __u64 addr) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr *)addr;
    accept_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&accepting_args, &id, &accept_args, 0);
	return 0;
}

// (accept and accept4 share the tracepoint programs; a trampoline program is bound to its one function)
SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint_enter_accept(struct syscall_trace_enter *ctx) {
    return sys_enter_accept(ctx, TP_ARG(ctx, 1));
}

SYS_FENTRY(accept)
int fentry_enter_accept(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_accept(ctx, SYS_ARG1(regs));
}

SYS_FENTRY(accept4)
int fentry_enter_accept4(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_accept(ctx, SYS_ARG1(regs));
}

static __always_inline int sys_exit_accept(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_args = bpf_map_lookup_elem(&accepting_args, &id);
    if (accept_args) {
        process_accept(ctx, id, accept_args, ret);
        // (only the thread's own enter puts its entry: one the lookup did not find is not there to delete)
        bpf_map_delete_elem(&accepting_args, &id);
    }
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint_exit_accept(struct syscall_trace_exit *ctx) {
    return sys_exit_accept(ctx, TP_RET(ctx));
}

SYS_FEXIT(accept)
int fexit_exit_accept(__u64 *ctx) {
    return sys_exit_accept(ctx, SYS_RET(ctx));
}

SYS_FEXIT(accept4)
int fexit_exit_accept4(__u64 *ctx) {
    return sys_exit_accept(ctx, SYS_RET(ctx));
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

SEC("kprobe/ip4_datagram_connect")
int ip4_udp_datagram_connect(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (connect_args) {
        struct sock *sock = (struct sock*)PT_REGS_PARM1(ctx);
        connect_args->sock = sock;
    }
    return 0;
}

#include "connect_conntrack.c"