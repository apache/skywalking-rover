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
#include "../l24/l24.h"
#include "transfer.h"

struct trace_point_common_exit {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    __u64 ret;
};
struct trace_point_common_write {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    char * buf;
    size_t count;
};
struct trace_point_common_writev {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    struct iovec * vec;
    size_t count;
};
struct trace_point_common_readv {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    struct iovec * vec;
    size_t count;
};
struct trace_point_common_sendmsg {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    struct user_msghdr * msg;
};
struct trace_point_common_sendmmsg {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    struct mmsghdr * mmsg;
    unsigned int vlen;
};
struct trace_point_enter_sendto {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    char * buf;
    size_t count;
    unsigned int flags;
    struct sockaddr * addr;
};
struct trace_point_enter_recvfrom {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    char * buf;
    size_t count;
    unsigned int flags;
    struct sockaddr * addr;
};
struct trace_point_common_recvmsg {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    struct user_msghdr * msg;
};
struct trace_point_common_recvmmsg {
    __u64 pad_0;
    __u32 __syscall_nr;
    __u32 pad_1;
    int fd;
    struct mmsghdr * mmsg;
    unsigned int vlen;
};
struct trace_point_skb_copy_datagram_iovec {
    __u64 pad_0;
    void *skb;
};

#define BPF_PROBE_READ_VAR(value, ptr) bpf_probe_read(&value, sizeof(value), ptr)

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_enter_write(struct trace_point_common_write *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    data_args.buf = ctx->buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_WRITE, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_exit_write(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = ctx->ret;
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_WRITE, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sendto")
int tracepoint_enter_sendto(struct trace_point_enter_sendto *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    if (ctx->addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = ctx->addr;
        connect_args.fd = ctx->fd;
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    data_args.buf = ctx->buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_SENDTO, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tracepoint_exit_sendto(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ctx->ret;

    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDTO, CONNECTION_ROLE_TYPE_CLIENT);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_SENDTO, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint_enter_writev(struct trace_point_common_writev *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    data_args.iovec = ctx->vec;
    data_args.iovlen = ctx->count;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_WRITE, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int tracepoint_exit_writev(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = ctx->ret;
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_WRITEV, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint_enter_sendmsg(struct trace_point_common_sendmsg *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct user_msghdr* msghdr = ctx->msg;
    if (msghdr == NULL) {
        return 0;
    }

    struct connect_args_t connect_args = {};
    struct sockaddr* addr=NULL;
    if (bpf_core_field_exists(msghdr->msg_name)) {
        BPF_CORE_READ_INTO(&addr, msghdr, msg_name);
        if (addr != NULL) {
            connect_args.addr = addr;
        }
    } else {
        const char fmt_str[] = "enter_sendmsgnot not found msg_name %d\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), id);
    }
    connect_args.fd = ctx->fd;
    connect_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    if (bpf_core_field_exists(msghdr->msg_iov)) {
        BPF_CORE_READ_INTO(&data_args.iovec, msghdr, msg_iov);
    }
    if (bpf_core_field_exists(msghdr->msg_iovlen)) {
        BPF_CORE_READ_INTO(&data_args.iovlen, msghdr, msg_iovlen);
    }
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_SENDMSG, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int tracepoint_exit_sendmsg(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ctx->ret;

     // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDMSG, CONNECTION_ROLE_TYPE_CLIENT);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_SENDMSG, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tracepoint_enter_sendmmsg(struct trace_point_common_sendmmsg *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct mmsghdr* mmsghdr = ctx->mmsg;
    __u32 vlen = ctx->vlen;
    if (mmsghdr == NULL || vlen <= 0) {
        return 0;
    }

    struct connect_args_t connect_args = {};
    struct sockaddr* addr=NULL;
    struct sock_data_args_t data_args = {};
    if (bpf_core_field_exists(mmsghdr->msg_hdr)) {
        BPF_CORE_READ_INTO(&addr, mmsghdr, msg_hdr.msg_name);
        if (addr != NULL) {
            connect_args.addr = addr;
        }
        BPF_CORE_READ_INTO(&data_args.iovec, mmsghdr, msg_hdr.msg_iov);
        size_t msg_iovlen;
        BPF_CORE_READ_INTO(&msg_iovlen, mmsghdr, msg_hdr.msg_iovlen);
        data_args.iovlen = msg_iovlen;
        data_args.msg_len = (unsigned int*)(&msg_iovlen);
    } else {
        const char fmt_str[] = "enter_sendmmsgnot not found msg_hdr %d\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), id);
    }

    connect_args.fd = ctx->fd;
    connect_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);

    data_args.fd = ctx->fd;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_SENDMSG, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int tracepoint_exit_sendmmsg(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ctx->ret;

     // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDMMSG, CONNECTION_ROLE_TYPE_CLIENT);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        __u32 bytes_count;
        BPF_PROBE_READ_VAR(bytes_count, data_args->msg_len);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_SENDMMSG, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_enter_read(struct trace_point_common_write *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    data_args.buf = ctx->buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_READ, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_exit_read(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = ctx->ret;
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_READ, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint_enter_readv(struct trace_point_common_readv *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    data_args.iovec = ctx->vec;
    data_args.iovlen = ctx->count;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_READV, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int tracepoint_exit_readv(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = ctx->ret;
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_READV, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/recv")
int sys_recv(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    char* buf = (void *)SYSCALL_PARM_2(ctx);
    struct sock_data_args_t data_args = {};
    data_args.fd = SYSCALL_PARM_1(ctx);
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECV, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/recv")
int sys_recv_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_RECV, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_enter_recvfrom(struct trace_point_enter_recvfrom *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }

    if (ctx->addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = ctx->addr;
        connect_args.fd = ctx->fd;
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    data_args.buf = ctx->buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECVFROM, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint_exit_recvfrom(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ctx->ret;

    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVFROM, CONNECTION_ROLE_TYPE_SERVER);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_RECVFROM, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint_enter_recvmsg(struct trace_point_common_recvmsg *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct user_msghdr* msghdr = ctx->msg;
    if (msghdr == NULL) {
        return 0;
    }

    struct connect_args_t connect_args = {};
    struct sockaddr* addr=NULL;
    if (bpf_core_field_exists(msghdr->msg_name)) {
        BPF_CORE_READ_INTO(&addr, msghdr, msg_name);
        if (addr != NULL) {
            connect_args.addr = addr;
        }
    } else {
        const char fmt_str[] = "enter_recvmsgnot not found msg_name %d\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), id);
    }
    connect_args.fd = ctx->fd;
    connect_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);

    struct sock_data_args_t data_args = {};
    data_args.fd = ctx->fd;
    if (bpf_core_field_exists(msghdr->msg_iov)) {
        BPF_CORE_READ_INTO(&data_args.iovec, msghdr, msg_iov);
    }
    if (bpf_core_field_exists(msghdr->msg_iovlen)) {
        BPF_CORE_READ_INTO(&data_args.iovlen, msghdr, msg_iovlen);
    }
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECVMSG, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tracepoint_exit_recvmsg(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ctx->ret;

     // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVMSG, CONNECTION_ROLE_TYPE_SERVER);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_RECVMSG, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int tracepoint_enter_recvmmsg(struct trace_point_common_recvmmsg *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    if (tgid_should_trace(id >> 32) == false) {
        return 0;
    }
    struct mmsghdr* mmsghdr = ctx->mmsg;
    __u32 vlen = ctx->vlen;
    if (mmsghdr == NULL || vlen <= 0) {
        return 0;
    }

    struct connect_args_t connect_args = {};
    struct sockaddr* addr=NULL;
    struct sock_data_args_t data_args = {};
    if (bpf_core_field_exists(mmsghdr->msg_hdr)) {
        BPF_CORE_READ_INTO(&addr, mmsghdr, msg_hdr.msg_name);
        if (addr != NULL) {
            connect_args.addr = addr;
        }
        BPF_CORE_READ_INTO(&data_args.iovec, mmsghdr, msg_hdr.msg_iov);
        size_t msg_iovlen;
        BPF_CORE_READ_INTO(&msg_iovlen, mmsghdr, msg_hdr.msg_iovlen);
        data_args.iovlen = msg_iovlen;
        data_args.msg_len = (unsigned int*)(&msg_iovlen);
    } else {
        const char fmt_str[] = "enter_recvmmsgnot not found msg_hdr %d\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), id);
    }
    connect_args.fd = ctx->fd;
    connect_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);

    data_args.fd = ctx->fd;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECVMMSG, false);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmmsg")
int tracepoint_exit_recvmmsg(struct trace_point_common_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ctx->ret;

     // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVMMSG, CONNECTION_ROLE_TYPE_SERVER);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        __u32 bytes_count;
        BPF_PROBE_READ_VAR(bytes_count, data_args->msg_len);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_RECVMMSG, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("tracepoint/skb/skb_copy_datagram_iovec")
int tracepoint_skb_copy_datagram_iovec(struct trace_point_skb_copy_datagram_iovec* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sk_buff *buff = ctx->skb;
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args == NULL) {
        bpf_map_delete_elem(&sk_buff_receive_detail_map, &buff);
        return 0;
    }

    struct sock *sock=NULL;
    if (bpf_core_field_exists(buff->sk)) {
        BPF_CORE_READ_INTO(&sock, buff, sk);
    }
    if (sock != NULL) {
        data_args->sk_role = get_sock_role(data_args->sk_role, sock);
    }

    data_args->package_count++;
    if (bpf_core_field_exists(buff->len)) {
        data_args->total_package_size += _(buff->len);
    }

    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &buff);
    if (detail == NULL) {
        return 0;
    }
    bpf_map_delete_elem(&sk_buff_receive_detail_map, &buff);

    // l4
    data_args->enter_l4_time = detail->enter_tcp_rcv_time;
    data_args->exit_l4_time = detail->exit_tcp_rcv_time;

    // l3
    if (detail->exit_ip_rcv_time > 0 && detail->enter_ip_rcv_time > 0) {
        data_args->l3_duration += detail->exit_ip_rcv_time - detail->enter_ip_rcv_time;
    }
    if (detail->ip_rcv_finish_time > 0 && detail->enter_ip_rcv_time > 0) {
        data_args->l3_rcv_duration += detail->ip_rcv_finish_time - detail->enter_ip_rcv_time;
    }
    if (detail->ip_local_finish_time > 0 && detail->ip_local_time > 0) {
        data_args->l3_local_duration += detail->ip_local_finish_time - detail->ip_local_time;
    }
    data_args->total_net_filter_count += detail->total_nf_count;
    data_args->total_net_filter_time += detail->total_nf_time;

    // l2
    data_args->ifindex = detail->ifindex;
    if (detail->netif_receive_time > 0 && detail->ip_local_time > 0) {
        data_args->total_package_to_queue_time += detail->ip_local_time - detail->netif_receive_time;
    }
    if (detail->ip_local_time > 0) {
        data_args->total_package_receive_from_queue_time += bpf_ktime_get_ns() - detail->ip_local_time;
    }

    return 0;
}

SEC("kprobe/security_socket_sendmsg")
int security_socket_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        data_args->is_sock_event = true;
    }
    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int security_socket_recvmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        data_args->is_sock_event = true;
    }
    return 0;
}