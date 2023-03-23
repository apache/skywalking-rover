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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <asm/errno.h>
#include <asm/socket.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "network.h"
#include "protocol_analyzer.h"

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline bool socket_should_trace(__u64 id, struct sock *sock) {
    // check the pid is monitoring
    __u32 tgid = (__u32)(id >> 32);
    if (tgid_should_trace(tgid) == false) {
        return false;
    }

    // check the socket if server side
    int max_ack_backlog = 0;
    if (0 != bpf_core_read(&max_ack_backlog, sizeof(max_ack_backlog),
                &sock->sk_max_ack_backlog)) {
        return true;
    }
    if (max_ack_backlog == 0) {
        return false;
    }
    return true;
}

static __always_inline void process_data(struct pt_regs *ctx, __u64 id, void *channel_ref, char *buf, __u64 size, __u64 timestamp) {
    if (size <= 0) {
        return;
    }

    if (size > MAX_PROTOCOL_SOCKET_READ_LENGTH) {
        size = MAX_PROTOCOL_SOCKET_READ_LENGTH;
    }
    __u32 kZero = 0;
    struct socket_buffer_reader_t* reader = bpf_map_lookup_elem(&socket_buffer_reader_map, &kZero);
    if (reader == NULL) {
        return;
    }
    asm volatile("%[size] &= 0xff;\n" ::[size] "+r"(size) :);
    bpf_probe_read(&reader->buffer, size & MAX_PROTOCOL_SOCKET_READ_LENGTH, buf);
    __u8 protocol;
    __u32 direction = analyze_protocol(reader->buffer, size & MAX_PROTOCOL_SOCKET_READ_LENGTH, &protocol);
    if (protocol != CONNECTION_PROTOCOL_UNKNOWN) {
        reader->timestamp = timestamp;
        reader->channel_ref = channel_ref;
        reader->pid = (__u32)(id >> 32);
        reader->protocol = protocol;
        reader->direction = (__u8)direction;
        reader->size = size & MAX_PROTOCOL_SOCKET_READ_LENGTH;
        bpf_perf_event_output(ctx, &socket_buffer_send_queue, BPF_F_CURRENT_CPU, reader, sizeof(*reader));
    }
}

static __always_inline void process_msghdr_data(struct pt_regs *ctx, __u64 id, void *channel_ref, struct msghdr *msg) {
    const struct iovec *iovec;
    iovec = _KERNEL(msg->msg_iter.iov);
    struct iovec iov;
    bpf_probe_read(&iov, sizeof(iov), iovec);
    char* buf = (char *)iov.iov_base;
    __u64 size = iov.iov_len;

    return process_data(ctx, id, channel_ref, buf, size, bpf_ktime_get_ns());
}

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock *s = (void *)PT_REGS_PARM1(ctx);
    if (socket_should_trace(id, s) == false) {
        return 0;
    }

    struct msghdr *msg = (void *)PT_REGS_PARM2(ctx);
    process_msghdr_data(ctx, id, s, msg);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int tcp_recvmsg(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock *s = (void *)PT_REGS_PARM1(ctx);
    if (socket_should_trace(id, s) == false) {
        return 0;
    }

    struct msghdr *msg = (void *)PT_REGS_PARM2(ctx);
    struct recv_msg_args args = {};
    args.sock = s;
    args.msg = msg;
    bpf_map_update_elem(&receiving_args, &id, &args, 0);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int ret_tcp_recvmsg(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct recv_msg_args *args = bpf_map_lookup_elem(&receiving_args, &id);
    int bytes_count = PT_REGS_RC(ctx);
    if (args != NULL && bytes_count > 0) {
        process_msghdr_data(ctx, id, args->sock, args->msg);
    }
    bpf_map_delete_elem(&receiving_args, &id);
    return 0;
}

#include "openssl.c"
#include "go_tls.c"
