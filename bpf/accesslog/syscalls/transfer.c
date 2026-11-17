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
#include "socket_opts.h"
#include "../process/process.h"
#include "../common/data_args.h"
#include "../common/sock.h"
#include "transfer.h"
#include "../common/sys_attach.h"


struct trace_event_raw_skb_copy_datagram_iovec {
        struct trace_entry ent;
        const void *skbaddr;
        int len;
        char __data[0];
} __attribute__((preserve_access_index));

#define BPF_PROBE_READ_VAR(value, ptr) bpf_probe_read(&value, sizeof(value), ptr)

static __always_inline int sys_enter_write(void *ctx, __u64 a0, __u64 a1) {
    uint64_t id = bpf_get_current_pid_tgid();
    // the agent's own idle-flush kick: flush this CPU's batch and do not record it as traffic
    if (h2c_batch_kick(id, (__u32)a0)) {
        h2c_batch_set_kickable();
        h2c_batch_flush(ctx);
        return 0;
    }
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_EGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->buf = (char *)a1;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_EGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_EGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_enter_write(struct syscall_trace_enter *ctx) {
    return sys_enter_write(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1));
}

SYS_FENTRY(write)
int fentry_enter_write(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_write(ctx, SYS_ARG0(regs), SYS_ARG1(regs));
}

static __always_inline int sys_exit_write(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        if (data_args->is_sock_event) {
            ssize_t bytes_count = ret;
            process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_WRITE, false);
        }
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_exit_write(struct syscall_trace_exit *ctx) {
    return sys_exit_write(ctx, TP_RET(ctx));
}

SYS_FEXIT(write)
int fexit_exit_write(__u64 *ctx) {
    return sys_exit_write(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_sendto(void *ctx, __u64 a0, __u64 a1, __u64 a2, __u64 a3, __u64 a4) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    if ((struct sockaddr *)a4 != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = (struct sockaddr *)a4;
        connect_args.fd = (__u32)a0;
        conecting_args_put(&id, &connect_args);
    }

    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_EGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->buf = (char *)a1;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_EGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_EGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sendto")
int tracepoint_enter_sendto(struct syscall_trace_enter *ctx) {
    return sys_enter_sendto(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1), TP_ARG(ctx, 2), TP_ARG(ctx, 3), TP_ARG(ctx, 4));
}

SYS_FENTRY(sendto)
int fentry_enter_sendto(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_sendto(ctx, SYS_ARG0(regs), SYS_ARG1(regs), SYS_ARG2(regs), SYS_ARG3(regs), SYS_ARG4(regs));
}

static __always_inline int sys_exit_sendto(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ret;

    // connection
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (connect_args) {
        if (bytes_count > 0) {
            submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDTO, CONNECTION_ROLE_TYPE_CLIENT);
        }
        // (only the thread's own enter puts its entry, so one the lookup did not find is not there to delete)
        conecting_args_del(&id);
    }

    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_SENDTO, false);
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tracepoint_exit_sendto(struct syscall_trace_exit *ctx) {
    return sys_exit_sendto(ctx, TP_RET(ctx));
}

SYS_FEXIT(sendto)
int fexit_exit_sendto(__u64 *ctx) {
    return sys_exit_sendto(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_writev(void *ctx, __u64 a0, __u64 a1, __u64 a2) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_EGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->iovec = (struct iovec *)a1;
    data_args->iovlen = (size_t)a2;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_EGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_EGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint_enter_writev(struct syscall_trace_enter *ctx) {
    return sys_enter_writev(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1), TP_ARG(ctx, 2));
}

SYS_FENTRY(writev)
int fentry_enter_writev(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_writev(ctx, SYS_ARG0(regs), SYS_ARG1(regs), SYS_ARG2(regs));
}

static __always_inline int sys_exit_writev(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        if (data_args->is_sock_event) {
            ssize_t bytes_count = ret;
            process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_WRITEV, false);
        }
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int tracepoint_exit_writev(struct syscall_trace_exit *ctx) {
    return sys_exit_writev(ctx, TP_RET(ctx));
}

SYS_FEXIT(writev)
int fexit_exit_writev(__u64 *ctx) {
    return sys_exit_writev(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_sendmsg(void *ctx, __u64 a0, __u64 a1) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct user_msghdr* msghdr = (struct user_msghdr*)a1;
    if (msghdr == NULL) {
        return 0;
    }

    struct sockaddr* addr = _(msghdr->msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = (__u32)a0;
        connect_args.start_nacs = bpf_ktime_get_ns();
        conecting_args_put(&id, &connect_args);
    }

    struct iovec *msg_iov = _(msghdr->msg_iov);
    size_t msg_iovlen = _(msghdr->msg_iovlen);
    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_EGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->iovec = msg_iov;
    data_args->iovlen = msg_iovlen;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_EGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_EGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint_enter_sendmsg(struct syscall_trace_enter *ctx) {
    return sys_enter_sendmsg(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1));
}

SYS_FENTRY(sendmsg)
int fentry_enter_sendmsg(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_sendmsg(ctx, SYS_ARG0(regs), SYS_ARG1(regs));
}

static __always_inline int sys_exit_sendmsg(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ret;

     // connection
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (connect_args) {
        if (bytes_count > 0) {
            submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDMSG, CONNECTION_ROLE_TYPE_CLIENT);
        }
        // (only the thread's own enter puts its entry, so one the lookup did not find is not there to delete)
        conecting_args_del(&id);
    }

    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_SENDMSG, false);
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int tracepoint_exit_sendmsg(struct syscall_trace_exit *ctx) {
    return sys_exit_sendmsg(ctx, TP_RET(ctx));
}

SYS_FEXIT(sendmsg)
int fexit_exit_sendmsg(__u64 *ctx) {
    return sys_exit_sendmsg(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_sendmmsg(void *ctx, __u64 a0, __u64 a1, __u64 a2) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct mmsghdr* mmsghdr = (struct mmsghdr*)a1;
    __u32 vlen = (__u32)a2;
    if (mmsghdr == NULL || vlen <= 0) {
        return 0;
    }

    struct sockaddr* addr = _(mmsghdr->msg_hdr.msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = (__u32)a0;
        connect_args.start_nacs = bpf_ktime_get_ns();
        conecting_args_put(&id, &connect_args);
    }

    struct iovec *msg_iov = _(mmsghdr->msg_hdr.msg_iov);
    size_t msg_iovlen = _(mmsghdr->msg_hdr.msg_iovlen);
    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_EGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->iovec = msg_iov;
    data_args->iovlen = msg_iovlen;
    data_args->msg_len = (unsigned int*)(&mmsghdr->msg_hdr.msg_iovlen);
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_EGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_EGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tracepoint_enter_sendmmsg(struct syscall_trace_enter *ctx) {
    return sys_enter_sendmmsg(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1), TP_ARG(ctx, 2));
}

SYS_FENTRY(sendmmsg)
int fentry_enter_sendmmsg(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_sendmmsg(ctx, SYS_ARG0(regs), SYS_ARG1(regs), SYS_ARG2(regs));
}

static __always_inline int sys_exit_sendmmsg(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ret;

     // connection
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (connect_args) {
        if (bytes_count > 0) {
            submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDMMSG, CONNECTION_ROLE_TYPE_CLIENT);
        }
        // (only the thread's own enter puts its entry, so one the lookup did not find is not there to delete)
        conecting_args_del(&id);
    }

    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        __u32 bytes_count;
        BPF_PROBE_READ_VAR(bytes_count, data_args->msg_len);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_SENDMMSG, false);
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int tracepoint_exit_sendmmsg(struct syscall_trace_exit *ctx) {
    return sys_exit_sendmmsg(ctx, TP_RET(ctx));
}

SYS_FEXIT(sendmmsg)
int fexit_exit_sendmmsg(__u64 *ctx) {
    return sys_exit_sendmmsg(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_read(void *ctx, __u64 a0, __u64 a1) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_INGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->buf = (char *)a1;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_INGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_INGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_enter_read(struct syscall_trace_enter *ctx) {
    return sys_enter_read(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1));
}

SYS_FENTRY(read)
int fentry_enter_read(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_read(ctx, SYS_ARG0(regs), SYS_ARG1(regs));
}

static __always_inline int sys_exit_read(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        if (data_args->is_sock_event) {
            ssize_t bytes_count = ret;
            process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_READ, false);
        }
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_exit_read(struct syscall_trace_exit *ctx) {
    return sys_exit_read(ctx, TP_RET(ctx));
}

SYS_FEXIT(read)
int fexit_exit_read(__u64 *ctx) {
    return sys_exit_read(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_readv(void *ctx, __u64 a0, __u64 a1, __u64 a2) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_INGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->iovec = (struct iovec *)a1;
    data_args->iovlen = (size_t)a2;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_INGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_INGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint_enter_readv(struct syscall_trace_enter *ctx) {
    return sys_enter_readv(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1), TP_ARG(ctx, 2));
}

SYS_FENTRY(readv)
int fentry_enter_readv(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_readv(ctx, SYS_ARG0(regs), SYS_ARG1(regs), SYS_ARG2(regs));
}

static __always_inline int sys_exit_readv(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        if (data_args->is_sock_event) {
            ssize_t bytes_count = ret;
            process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_READV, false);
        }
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int tracepoint_exit_readv(struct syscall_trace_exit *ctx) {
    return sys_exit_readv(ctx, TP_RET(ctx));
}

SYS_FEXIT(readv)
int fexit_exit_readv(__u64 *ctx) {
    return sys_exit_readv(ctx, SYS_RET(ctx));
}

SEC("kprobe/recv")
int sys_recv(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    char* buf = (void *)SYSCALL_PARM_2(ctx);
    __u32 fd = SYSCALL_PARM_1(ctx);
    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_INGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = fd;
    data_args->buf = buf;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_INGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_INGRESS);
    return 0;
}

SEC("kretprobe/recv")
int sys_recv_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_RECV, false);
    }

    socket_data_call_done(id, data_args);
    return 0;
}

static __always_inline int sys_enter_recvfrom(void *ctx, __u64 a0, __u64 a1, __u64 a2, __u64 a3, __u64 a4) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    if ((struct sockaddr *)a4 != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = (struct sockaddr *)a4;
        connect_args.fd = (__u32)a0;
        conecting_args_put(&id, &connect_args);
    }

    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_INGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->buf = (char *)a1;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_INGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_INGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_enter_recvfrom(struct syscall_trace_enter *ctx) {
    return sys_enter_recvfrom(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1), TP_ARG(ctx, 2), TP_ARG(ctx, 3), TP_ARG(ctx, 4));
}

SYS_FENTRY(recvfrom)
int fentry_enter_recvfrom(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_recvfrom(ctx, SYS_ARG0(regs), SYS_ARG1(regs), SYS_ARG2(regs), SYS_ARG3(regs), SYS_ARG4(regs));
}

static __always_inline int sys_exit_recvfrom(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ret;

    // connection
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (connect_args) {
        if (bytes_count > 0) {
            submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVFROM, CONNECTION_ROLE_TYPE_SERVER);
        }
        // (only the thread's own enter puts its entry, so one the lookup did not find is not there to delete)
        conecting_args_del(&id);
    }

    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_RECVFROM, false);
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint_exit_recvfrom(struct syscall_trace_exit *ctx) {
    return sys_exit_recvfrom(ctx, TP_RET(ctx));
}

SYS_FEXIT(recvfrom)
int fexit_exit_recvfrom(__u64 *ctx) {
    return sys_exit_recvfrom(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_recvmsg(void *ctx, __u64 a0, __u64 a1) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct user_msghdr* msghdr = (struct user_msghdr*)a1;
    if (msghdr == NULL) {
        return 0;
    }

    struct sockaddr* addr = _(msghdr->msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = (__u32)a0;
        connect_args.start_nacs = bpf_ktime_get_ns();
        conecting_args_put(&id, &connect_args);
    }

    struct iovec *msg_iov = _(msghdr->msg_iov);
    size_t msg_iovlen = _(msghdr->msg_iovlen);
    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_INGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->iovec = msg_iov;
    data_args->iovlen = msg_iovlen;
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_INGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_INGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint_enter_recvmsg(struct syscall_trace_enter *ctx) {
    return sys_enter_recvmsg(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1));
}

SYS_FENTRY(recvmsg)
int fentry_enter_recvmsg(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_recvmsg(ctx, SYS_ARG0(regs), SYS_ARG1(regs));
}

static __always_inline int sys_exit_recvmsg(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ret;

     // connection
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (connect_args) {
        if (bytes_count > 0) {
            submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVMSG, CONNECTION_ROLE_TYPE_SERVER);
        }
        // (only the thread's own enter puts its entry, so one the lookup did not find is not there to delete)
        conecting_args_del(&id);
    }

    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_RECVMSG, false);
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tracepoint_exit_recvmsg(struct syscall_trace_exit *ctx) {
    return sys_exit_recvmsg(ctx, TP_RET(ctx));
}

SYS_FEXIT(recvmsg)
int fexit_exit_recvmsg(__u64 *ctx) {
    return sys_exit_recvmsg(ctx, SYS_RET(ctx));
}

static __always_inline int sys_enter_recvmmsg(void *ctx, __u64 a0, __u64 a1, __u64 a2) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct mmsghdr* mmsghdr = (struct mmsghdr*)a1;
    __u32 vlen = (__u32)a2;
    if (mmsghdr == NULL || vlen <= 0) {
        return 0;
    }

    struct sockaddr* addr = _(mmsghdr->msg_hdr.msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = (__u32)a0;
        connect_args.start_nacs = bpf_ktime_get_ns();
        conecting_args_put(&id, &connect_args);
    }

    struct iovec *msg_iov = _(mmsghdr->msg_hdr.msg_iov);
    size_t msg_iovlen = _(mmsghdr->msg_hdr.msg_iovlen);
    __u64 start_nacs = bpf_ktime_get_ns();
    struct sock_data_stale_t stale;
    struct sock_data_args_t *data_args = socket_data_call_begin(&id, &stale, SOCK_DATA_DIRECTION_INGRESS);
    if (data_args == NULL) {
        return 0;
    }
    data_args->fd = (__u32)a0;
    data_args->iovec = msg_iov;
    data_args->iovlen = msg_iovlen;
    data_args->msg_len = (unsigned int*)(&mmsghdr->msg_hdr.msg_iovlen);
    data_args->start_nacs = start_nacs;
    socket_data_call_enter(id, data_args, SOCK_DATA_DIRECTION_INGRESS);
    socket_data_call_finish(id, data_args, &stale, SOCK_DATA_DIRECTION_INGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int tracepoint_enter_recvmmsg(struct syscall_trace_enter *ctx) {
    return sys_enter_recvmmsg(ctx, TP_ARG(ctx, 0), TP_ARG(ctx, 1), TP_ARG(ctx, 2));
}

SYS_FENTRY(recvmmsg)
int fentry_enter_recvmmsg(__u64 *ctx) {
    struct sys_attach_regs *regs = sys_attach_regs(ctx);
    if (regs == NULL) {
        return 0;
    }
    return sys_enter_recvmmsg(ctx, SYS_ARG0(regs), SYS_ARG1(regs), SYS_ARG2(regs));
}

static __always_inline int sys_exit_recvmmsg(void *ctx, long ret) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ret;

     // connection
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (connect_args) {
        if (bytes_count > 0) {
            submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVMMSG, CONNECTION_ROLE_TYPE_SERVER);
        }
        // (only the thread's own enter puts its entry, so one the lookup did not find is not there to delete)
        conecting_args_del(&id);
    }

    struct sock_data_args_t *data_args = socket_data_args_exit_get(&id);
    if (data_args) {
        __u32 bytes_count;
        BPF_PROBE_READ_VAR(bytes_count, data_args->msg_len);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_RECVMMSG, false);
    }

    socket_data_call_done(id, data_args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmmsg")
int tracepoint_exit_recvmmsg(struct syscall_trace_exit *ctx) {
    return sys_exit_recvmmsg(ctx, TP_RET(ctx));
}

SYS_FEXIT(recvmmsg)
int fexit_exit_recvmmsg(__u64 *ctx) {
    return sys_exit_recvmmsg(ctx, SYS_RET(ctx));
}

// the copy of an sk_buff to the reader (the tracepoint skb:skb_copy_datagram_iovec(skb, len) at the start of
// skb_copy_datagram_iter): the tracepoint program, or the raw tracepoint one of the trampoline attach, which
// gets the same two arguments without the perf buffer of the tracepoint
// btf: 1 (a constant) for the tp_btf program, whose buff is a typed kernel pointer the verifier reads fields of
// without a helper (no probe read per copy for the socket)
static __always_inline int skb_copy_datagram_iovec_body(struct sk_buff *buff, int copy_len, const int btf) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args == NULL) {
        return 0;
    }

    // the socket is only kept while the role of the call is not known
    if (data_args->sk_role == CONNECTION_ROLE_TYPE_UNKNOWN) {
        if (data_args->role_sk == NULL) {
            // (the role itself is read at the exit, only when the call makes the connection; the tp_btf program
            // loads the socket without a helper)
            if (btf) {
                data_args->role_sk = buff->sk;
            } else {
                data_args->role_sk = _(buff->sk);
            }
        }
    }

    // (one byte: a call that copies from more skbs stays at 255 instead of wrapping)
    if (data_args->package_count < 0xff) {
        data_args->package_count++;
    }
    // bytes copied to user space by this call; buff->len is the whole skb (up to 64K with GRO) and a
    // partial read copies from the same skb several times, so summing it counted the skb again on every copy
    if (copy_len > 0) {
        data_args->total_package_size += copy_len;
    }
    return 0;
}

SEC("tracepoint/skb/skb_copy_datagram_iovec")
int tracepoint_skb_copy_datagram_iovec(struct trace_event_raw_skb_copy_datagram_iovec* ctx) {
    return skb_copy_datagram_iovec_body((struct sk_buff *)ctx->skbaddr, ctx->len, 0);
}

SEC("raw_tracepoint/skb_copy_datagram_iovec")
int raw_tp_skb_copy_datagram_iovec(struct bpf_raw_tracepoint_args *ctx) {
    return skb_copy_datagram_iovec_body((struct sk_buff *)ctx->args[0], (int)ctx->args[1], 0);
}

// the BTF-typed raw tracepoint twin (tp_btf, 5.5 with kernel BTF): the same body, the socket of the sk_buff
// loaded without a helper. The loader prefers it to the raw tracepoint where it attaches (pkg/accesslog/bpf/attach.go).
SEC("tp_btf/skb_copy_datagram_iovec")
int tp_btf_skb_copy_datagram_iovec(__u64 *ctx) {
    return skb_copy_datagram_iovec_body((struct sk_buff *)ctx[0], (int)ctx[1], 1);
}

static __always_inline int security_socket_sendmsg_body() {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {
        data_args->is_sock_event = true;
    }
    return 0;
}

SEC("kprobe/security_socket_sendmsg")
int security_socket_sendmsg(struct pt_regs* ctx) {
    return security_socket_sendmsg_body();
}

// the kprobes of the socket calls have a fentry twin for the trampoline attach (common/sys_attach.h)
SEC("fentry/security_socket_sendmsg")
int fentry_security_socket_sendmsg(__u64 *ctx) {
    return security_socket_sendmsg_body();
}

static __always_inline int security_socket_recvmsg_body(__u64 flags) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {
        data_args->is_sock_event = true;
        // security_socket_recvmsg(sock, msg, size, flags): every receive of a socket passes here with its
        // flags, whatever the syscall (the access log always attaches it). Only syscalls/h2c.h reads them.
        data_args->recv_flags |= (__u16)(flags & SOCK_RECV_FLAGS_NOT_CONSUMED);
    }
    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int security_socket_recvmsg(struct pt_regs* ctx) {
    return security_socket_recvmsg_body(PT_REGS_PARM4(ctx));
}

SEC("fentry/security_socket_recvmsg")
int fentry_security_socket_recvmsg(__u64 *ctx) {
    return security_socket_recvmsg_body(ctx[3]);
}

// The entry the thread keeps in socket_data_args between its socket calls (common/data_args.h) goes when the thread
// exits. An active one stays: the thread died in a call whose exit never came, and the entry stays as it stayed
// before, for the next enter of the same pid_tgid to take out of the calls in flight.
SEC("tracepoint/sched/sched_process_exit")
int tracepoint_sched_process_exit(void *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    // (the thread's slot, or its entry in socket_data_args, common/data_args.h)
    socket_data_args_release(id);
    return 0;
}
