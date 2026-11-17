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

// L3 of a receive: ip_rcv (or ip_list_rcv for a list of sk_buffs), ip_rcv_finish, ip_local_deliver of the sk_buffs of
// skb_receive_detail

#include "l24.h"

// ip_rcv(skb, dev, pt, orig_dev)
SEC("kprobe/ip_rcv")
int l24_ip_rcv(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        __u64 now = bpf_ktime_get_ns();
        detail->enter_ip_rcv_time = now;
        save_l24_tmp_args(L24_TEMP_ARGS_IP_RCV, skb, now);
    }
    return 0;
}

SEC("kretprobe/ip_rcv")
int l24_ip_rcv_ret(struct pt_regs * ctx) {
    struct l24_tmp_args_value kept = {};
    if (!take_l24_tmp_args(L24_TEMP_ARGS_IP_RCV, &kept)) {
        return 0;
    }
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &kept.skb);
    if (detail != NULL) {
        detail->exit_ip_rcv_time = bpf_ktime_get_ns();
    }
    return 0;
}

// the sk_buffs of a list (ip_list_rcv, ip_sublist_rcv_finish) that are followed: at most L24_LIST_MAX of them, the
// list_head of an sk_buff is its first member
#define L24_LIST_MAX 8
struct l24_skb_list {
    struct sk_buff *skbs[L24_LIST_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct l24_tmp_args_key);
	__type(value, struct l24_skb_list);
} ip_list_rcv_args_map SEC(".maps");

// l24_list_mark sets the time at the location of the followed sk_buffs of the list (0: enter_ip_rcv_time, 1:
// ip_rcv_finish_time) and keeps them in the list given, when not NULL
static __always_inline void l24_list_mark(struct list_head *head, int location, __u64 now, struct l24_skb_list *kept) {
    struct list_head *node = _(head->next);
#pragma unroll
    for (int i = 0; i < L24_LIST_MAX; i++) {
        if (node == NULL || node == head) {
            break;
        }
        struct sk_buff *skb = (struct sk_buff *)node;
        struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
        if (detail != NULL) {
            if (location == 0) {
                detail->enter_ip_rcv_time = now;
            } else {
                detail->ip_rcv_finish_time = now;
            }
            if (kept != NULL) {
                kept->skbs[i] = skb;
            }
        }
        node = _(node->next);
    }
}

// ip_list_rcv(head, pt, orig_dev)
SEC("kprobe/ip_list_rcv")
int l24_ip_list_rcv(struct pt_regs * ctx) {
    struct list_head *head = (struct list_head *)PT_REGS_PARM1(ctx);
    if (head == NULL) {
        return 0;
    }
    struct l24_skb_list kept = {};
    l24_list_mark(head, 0, bpf_ktime_get_ns(), &kept);
    struct l24_tmp_args_key key = {};
    l24_tmp_args_key(&key, L24_TEMP_ARGS_IP_RCV);
    bpf_map_update_elem(&ip_list_rcv_args_map, &key, &kept, BPF_ANY);
    return 0;
}

SEC("kretprobe/ip_list_rcv")
int l24_ip_list_rcv_ret(struct pt_regs * ctx) {
    struct l24_tmp_args_key key = {};
    l24_tmp_args_key(&key, L24_TEMP_ARGS_IP_RCV);
    struct l24_skb_list *kept = bpf_map_lookup_elem(&ip_list_rcv_args_map, &key);
    if (kept == NULL) {
        return 0;
    }
    __u64 now = bpf_ktime_get_ns();
#pragma unroll
    for (int i = 0; i < L24_LIST_MAX; i++) {
        struct sk_buff *skb = kept->skbs[i];
        if (skb == NULL) {
            continue;
        }
        struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
        if (detail != NULL) {
            detail->exit_ip_rcv_time = now;
        }
    }
    bpf_map_delete_elem(&ip_list_rcv_args_map, &key);
    return 0;
}

// ip_rcv_finish(net, sk, skb) (static: not every kernel has a symbol to probe)
SEC("kprobe/ip_rcv_finish")
int l24_ip_rcv_finish(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->ip_rcv_finish_time = bpf_ktime_get_ns();
    }
    return 0;
}

// ip_sublist_rcv_finish(head)
SEC("kprobe/ip_sublist_rcv_finish")
int l24_ip_sublist_rcv_finish(struct pt_regs * ctx) {
    struct list_head *head = (struct list_head *)PT_REGS_PARM1(ctx);
    if (head == NULL) {
        return 0;
    }
    l24_list_mark(head, 1, bpf_ktime_get_ns(), NULL);
    return 0;
}

// ip_local_deliver(skb)
SEC("kprobe/ip_local_deliver")
int l24_ip_local_deliver(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->ip_local_time = bpf_ktime_get_ns();
    }
    return 0;
}

// ip_local_deliver_finish(net, sk, skb) (static: not every kernel has a symbol to probe)
SEC("kprobe/ip_local_deliver_finish")
int l24_ip_local_deliver_finish(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->ip_local_finish_time = bpf_ktime_get_ns();
    }
    return 0;
}
