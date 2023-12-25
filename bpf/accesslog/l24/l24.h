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

#pragma once

#include "api.h"
#include "socket.h"
#include "socket_opts.h"

struct skb_receive_detail {
    __u64 netif_receive_time;
    __u64 enter_ip_rcv_time;
    __u64 exit_ip_rcv_time;
    __u64 ip_rcv_finish_time;
    __u64 ip_local_time;
    __u64 ip_local_finish_time;
    __u64 enter_tcp_rcv_time;
    __u64 exit_tcp_rcv_time;
    __u64 enter_nf_time;
    __u32 ifindex;
    __u32 total_nf_count;
    __u64 total_nf_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct sk_buff *);
	__type(value, struct skb_receive_detail);
} sk_buff_receive_detail_map SEC(".maps");

struct skb_transmit_detail {
    // l3
    __u64 l3_enter_time;
    __u64 l3_exit_time;
    __u64 l3_local_time;
    __u64 l3_output_time;
    __u64 l3_finish_time;
    __u16 total_nf_count;
    __u16 total_resolve_neigh_count;
    __u32 ifindex;
    __u64 enter_nf_time;
    __u64 enter_resolve_neigh_time;
    __u64 total_nf_time;
    __u64 total_resolve_neigh_time;

    // l2
    __u64 l2_enter_time;
    __u64 l2_exit_time;
    __u64 l2_start_xmit_time;
    __u64 l2_finish_xmit_time;
    // for loss package, for now, we only support first 4 locations, it could be changes to map-in-map
    __u64 loss_package_location1;
    __u64 loss_package_location2;
    __u64 loss_package_location3;
    __u64 loss_package_location4;
    __u16 loss_package_count1;
    __u16 loss_package_count2;
    __u16 loss_package_count3;
    __u16 loss_package_count4;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct sk_buff *);
	__type(value, struct skb_transmit_detail);
} sk_buff_transmit_detail_map SEC(".maps");

#define L24_TEMP_ARGS_TRANSMIT_NF_HOOK_SLOW 1
#define L24_TEMP_ARGS_NEIGHT_RESOLVE_OUTPUT 2
#define L24_TEMP_ARGS_DEV_QUEUE_EMIT 3
#define L24_TEMP_ARGS_IP_RCV 4
#define L24_TEMP_ARGS_TCP_RCV 5
#define L24_TEMP_ARGS_RCV_NF_HOOK_SLOW 1

struct l24_tmp_args_key {
    __u64 id;
    __u64 type;
};
struct l24_tmp_args_value {
    struct skb_transmit_detail *detail;
    __u64 start_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct l24_tmp_args_key);
	__type(value, struct sk_buff *);
} sk_temp_args_map SEC(".maps");

static __always_inline void save_l24_tmp_args(__u64 tpe, struct sk_buff *skb) {
    struct l24_tmp_args_key key = {
        .id = bpf_get_current_pid_tgid(),
        .type = tpe,
    };
    bpf_map_update_elem(&sk_temp_args_map, &key, &skb, BPF_ANY);
}

static __always_inline struct skb_transmit_detail* get_l24_transmit_tmp_args(__u64 tpe) {
    struct l24_tmp_args_key key = {
        .id = bpf_get_current_pid_tgid(),
        .type = tpe,
    };
    struct sk_buff* buff = bpf_map_lookup_elem(&sk_temp_args_map, &key);
    if (buff == NULL) {
        return NULL;
    }
    bpf_map_delete_elem(&sk_temp_args_map, &key);
    return bpf_map_lookup_elem(&sk_buff_transmit_detail_map, buff);
}

static __always_inline struct skb_receive_detail* get_l24_rcv_tmp_args(__u64 tpe) {
    struct l24_tmp_args_key key = {
        .id = bpf_get_current_pid_tgid(),
        .type = tpe,
    };
    struct sk_buff* buff = bpf_map_lookup_elem(&sk_temp_args_map, &key);
    if (buff == NULL) {
        return NULL;
    }
    bpf_map_delete_elem(&sk_temp_args_map, &key);
    return bpf_map_lookup_elem(&sk_buff_receive_detail_map, buff);
}