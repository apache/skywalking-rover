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

#include "l24.h"
#include "../common/data_args.h"
#include "../common/sock.h"

struct kfree_skb_args {
  unsigned long pad;

  void *skb;
  void *location;
};

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        data_args->enter_l4_time = bpf_ktime_get_ns();

        // getting the socket role is client or server
        struct sock *sk = (void *)PT_REGS_PARM1(ctx);
        data_args->sk_role = get_sock_role(data_args->sk_role, sk);
    }
    return 0;
};

SEC("kretprobe/tcp_sendmsg")
int tcp_sendmsg_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        data_args->exit_l4_time = bpf_ktime_get_ns();
    }
    return 0;
};

SEC("kprobe/tcp_transmit_skb")
int tcp_transmit_skb(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        struct sk_buff *skb = (void *)PT_REGS_PARM2(ctx);
        data_args->package_count++;
        data_args->total_package_size += _(skb->len);
    }
    return 0;
};

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint_tcp_retransmit_skb() {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        data_args->retransmit_package_count++;
    }
    return 0;
}

#define UPDATE_LOSS_PACKAGE(detail, loc, count, location) \
    if ((detail)->loc == 0) { \
        (detail)->loc = (__u64)(location); \
        (detail)->count = 1; \
        return 0; \
    } else if ((detail)->loc == (__u64)(location)) { \
        (detail)->count++; \
        return 0; \
    }

SEC("tracepoint/skb/kfree_skb")
int kfree_skb(struct kfree_skb_args *args) {
    struct sk_buff *skb = args->skb;
    if (skb == NULL) {
        return 0;
    }
    void* location = args->location;
    if (location == NULL) {
        return 0;
    }
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        UPDATE_LOSS_PACKAGE(detail, loss_package_location1, loss_package_count1, location);
        UPDATE_LOSS_PACKAGE(detail, loss_package_location2, loss_package_count2, location);
        UPDATE_LOSS_PACKAGE(detail, loss_package_location3, loss_package_count3, location);
        UPDATE_LOSS_PACKAGE(detail, loss_package_location4, loss_package_count4, location);
    }
    return 0;
}