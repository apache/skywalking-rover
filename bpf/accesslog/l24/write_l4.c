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

// L4 of a send: the time in tcp_sendmsg, the sk_buffs __tcp_transmit_skb sends and the retransmits, while the thread is
// in a socket call. (The role of the socket is taken by the tcp_sendmsg program of syscalls/tcp_sendmsg.c.)

#include "l24.h"

struct trace_event_raw_tcp_event_sk_skb {
    struct trace_entry ent;
    const void *skbaddr;
} __attribute__((preserve_access_index));

SEC("kprobe/tcp_sendmsg")
int l24_tcp_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {
        l24_args_own(data_args);
        data_args->enter_l4_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int l24_tcp_sendmsg_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {
        l24_args_own(data_args);
    }
    if (data_args != NULL && data_args->enter_l4_time != 0) {
        data_args->l4_duration += bpf_ktime_get_ns() - data_args->enter_l4_time;
        data_args->enter_l4_time = 0;
    }
    return 0;
}

// __tcp_transmit_skb(sk, skb, clone_it, gfp_mask, rcv_nxt)
SEC("kprobe/__tcp_transmit_skb")
int l24_tcp_transmit_skb(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {
        struct sk_buff *skb = (void *)PT_REGS_PARM2(ctx);
        l24_args_own(data_args);
        data_args->l4_transmit_package_count++;
        data_args->l4_transmit_package_size += _(skb->len);
    }
    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int l24_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *args) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL && data_args->retransmit_package_count < 0xff) {
        data_args->retransmit_package_count++;
    }
    return 0;
}
