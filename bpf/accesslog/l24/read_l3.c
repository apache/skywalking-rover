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
#include "list.h"

SEC("kprobe/ip_rcv")
int ip_rcv(struct pt_regs * ctx) {
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->enter_ip_rcv_time = bpf_ktime_get_ns();
        save_l24_tmp_args(L24_TEMP_ARGS_IP_RCV, skb);
    }
    return 0;
}

SEC("kretprobe/ip_rcv")
int ip_rcv_ret(struct pt_regs * ctx) {
    struct skb_receive_detail* detail = get_l24_rcv_tmp_args(L24_TEMP_ARGS_IP_RCV);
    if (detail != NULL) {
        detail->exit_ip_rcv_time = bpf_ktime_get_ns();
    }
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct bpf_list_head);
} ip_list_rcv_args_map SEC(".maps");

#define ip_list_foreach_skb(loc, time)                                      \
    list_for_each_entry_data(skb, next, head, list) {                       \
        detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);    \
        if (detail != NULL) {                                               \
            detail->loc = time;                                             \
            skb_list = append_bpf_list_head(&skb_list, skb);                 \
        }                                                                   \
    };

#define bpf_list_foreach_skb(loc, time)                                      \
    bpf_list_for_each_foreach(skb, head) {                                   \
        detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);     \
        if (detail != NULL) {                                                \
            detail->loc = time;                                              \
        }                                                                    \
    };

SEC("kprobe/ip_list_rcv")
int ip_list_rcv(struct pt_regs * ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct list_head *head = (struct list_head *)PT_REGS_PARM1(ctx);
    if (head == NULL) {
        return 0;
    }
    __u64 enter_rcv_time = bpf_ktime_get_ns();
    struct skb_receive_detail *detail = NULL;

    struct sk_buff *skb = NULL, *next = NULL;
    struct bpf_list_head skb_list = init_bpf_list_head();
    list_for_each_entry_init()
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)
    ip_list_foreach_skb(enter_ip_rcv_time, enter_rcv_time)


    bpf_map_update_elem(&ip_list_rcv_args_map, &id, &skb_list, BPF_ANY);
    return 0;
}

SEC("kretprobe/ip_list_rcv")
int ip_list_rcv_ret(struct pt_regs * ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct bpf_list_head *head = bpf_map_lookup_elem(&ip_list_rcv_args_map, &id);
    if (head == NULL) {
        return 0;
    }

    struct sk_buff *skb = NULL;
    bpf_list_for_each_init()
    struct skb_receive_detail *detail = NULL;
    __u64 exit_rcv_time = bpf_ktime_get_ns();
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)
    bpf_list_foreach_skb(exit_ip_rcv_time, exit_rcv_time)

    bpf_map_delete_elem(&ip_list_rcv_args_map, &id);
    return 0;
}

SEC("kprobe/ip_rcv_finish")
int ip_rcv_finish(struct pt_regs * ctx){
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->ip_rcv_finish_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("kprobe/ip_sublist_rcv_finish")
int ip_sublist_rcv_finish(struct pt_regs * ctx) {
    struct list_head *head = (struct list_head *)PT_REGS_PARM1(ctx);
    if (head == NULL) {
        return 0;
    }
    __u64 rcv_finish_time = bpf_ktime_get_ns();
    struct skb_receive_detail *detail = NULL;

    struct sk_buff *skb = NULL, *next = NULL;
    struct bpf_list_head skb_list = init_bpf_list_head();
    list_for_each_entry_init()
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)
    ip_list_foreach_skb(ip_rcv_finish_time, rcv_finish_time)

    return 0;
}

SEC("kprobe/ip_local_deliver")
int ip_local_deliver(struct pt_regs * ctx){
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->ip_local_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("kprobe/ip_local_deliver_finish")
int ip_local_deliver_finish(struct pt_regs * ctx){
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->ip_local_finish_time = bpf_ktime_get_ns();
    }
    return 0;
}
