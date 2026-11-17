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

// The L2 to L4 details of the socket calls (access_log.kernel_metrics.l2_l3). The programs of this directory are only
// attached with the switch on (pkg/accesslog/collector/l24.go) and are loaded as stubs without it
// (pkg/accesslog/bpf/l24.go). They follow the sk_buffs a socket call sends (from __ip_queue_xmit down to the device)
// and the ones it receives (from the device up to the copy to the reader) and add what they took into the L2 to L4
// fields of the arguments of the call (sock_data_args_t, from buffer on), which the exit of the call sends in an event
// of its own (l24_upload, socket_l24_queue): the socket data event stays as it is.
//
// The details of an sk_buff live in two maps keyed by its address. Both are LRU maps: an sk_buff of the receive map
// that is never copied to a reader (an ACK, a packet of a socket nobody reads, one merged by GRO into another) is
// evicted by the newer ones instead of filling the map, and an entry of the transmit map is deleted when its
// __ip_queue_xmit returns. The maps are made with one entry when the switch is off (the loader).

#include "api.h"
#include "socket.h"
#include "socket_opts.h"
#include "queue.h"
#include "../common/data_args.h"

struct skb_receive_detail {
    __u64 netif_receive_time;
    __u64 enter_ip_rcv_time;
    __u64 exit_ip_rcv_time;
    __u64 ip_rcv_finish_time;
    __u64 ip_local_time;
    __u64 ip_local_finish_time;
    // the time spent in tcp_v4_rcv/tcp_v6_rcv
    __u64 tcp_rcv_duration;
    __u64 total_nf_time;
    __u32 ifindex;
    __u32 total_nf_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100000);
	__type(key, struct sk_buff *);
	__type(value, struct skb_receive_detail);
} sk_buff_receive_detail_map SEC(".maps");

struct skb_transmit_detail {
    // l3
    __u64 l3_enter_time;
    __u64 l3_local_time;
    __u64 l3_output_time;
    __u64 l3_finish_time;
    __u64 total_nf_time;
    __u64 total_resolve_neigh_time;
    __u32 total_nf_count;
    __u32 total_resolve_neigh_count;
    __u32 ifindex;
    __u32 pad;
    // l2
    __u64 l2_enter_time;
    __u64 l2_exit_time;
    __u64 l2_start_xmit_time;
    __u64 l2_finish_xmit_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct sk_buff *);
	__type(value, struct skb_transmit_detail);
} sk_buff_transmit_detail_map SEC(".maps");

// the functions whose kprobe keeps the sk_buff and the enter time for its kretprobe
#define L24_TEMP_ARGS_NF_HOOK_SLOW 1
#define L24_TEMP_ARGS_NEIGH_RESOLVE_OUTPUT 2
#define L24_TEMP_ARGS_DEV_QUEUE_XMIT 3
#define L24_TEMP_ARGS_IP_RCV 4
#define L24_TEMP_ARGS_TCP_RCV 5

// A kprobe and its kretprobe run on the same CPU for the functions below (they run with the bottom halves or
// preemption off), but in the context of the interrupted task, whose pid_tgid is 0 on an idle CPU: the CPU is part of
// the key. An LRU map: an entry whose kretprobe never ran (a kretprobe instance missed) is evicted.
struct l24_tmp_args_key {
    __u64 id;
    __u32 cpu;
    __u32 type;
};
struct l24_tmp_args_value {
    struct sk_buff *skb;
    __u64 start_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct l24_tmp_args_key);
	__type(value, struct l24_tmp_args_value);
} sk_temp_args_map SEC(".maps");

static __always_inline void l24_tmp_args_key(struct l24_tmp_args_key *key, __u32 type) {
    key->id = bpf_get_current_pid_tgid();
    key->cpu = bpf_get_smp_processor_id();
    key->type = type;
}

static __always_inline void save_l24_tmp_args(__u32 type, struct sk_buff *skb, __u64 start_time) {
    struct l24_tmp_args_key key = {};
    l24_tmp_args_key(&key, type);
    struct l24_tmp_args_value value = {.skb = skb, .start_time = start_time};
    bpf_map_update_elem(&sk_temp_args_map, &key, &value, BPF_ANY);
}

// take_l24_tmp_args gives the sk_buff and the enter time the kprobe kept for the kretprobe, false when there is none
static __always_inline bool take_l24_tmp_args(__u32 type, struct l24_tmp_args_value *value) {
    struct l24_tmp_args_key key = {};
    l24_tmp_args_key(&key, type);
    struct l24_tmp_args_value *kept = bpf_map_lookup_elem(&sk_temp_args_map, &key);
    if (kept == NULL) {
        return false;
    }
    value->skb = kept->skb;
    value->start_time = kept->start_time;
    bpf_map_delete_elem(&sk_temp_args_map, &key);
    return true;
}

// l24_args_own makes the L2 to L4 details of the arguments (from l24_stamp on) those of the call the arguments are of:
// zeroed and marked with its start the first time an l24 program of the call writes them (the enter of the call does
// not zero them, see sock_data_args_t)
static __always_inline void l24_args_own(struct sock_data_args_t *args) {
    if (args->l24_stamp != args->start_nacs) {
        __builtin_memset(&args->buffer, 0, sizeof(*args) - __builtin_offsetof(struct sock_data_args_t, buffer));
        args->l24_stamp = args->start_nacs;
    }
}

// The event of the L2 to L4 details of a socket call, sent at its exit after the socket data event of the call
// (pkg/accesslog/events/l24.go reads it): the user space joins it to the kernel log of the call by the connection,
// the random id and the data id. Only a call with a detail sends one.
struct socket_l24_event {
    __u64 conid;
    __u64 random_id;
    __u64 data_id;
    __u64 l4_duration;
    __u64 l3_duration;
    __u64 l3_rcv_duration;
    __u64 l3_local_duration;
    __u64 l3_output_duration;
    __u64 l3_resolve_mac_duration;
    __u64 l3_net_filter_duration;
    __u64 l2_duration;
    __u64 l2_ready_send_duration;
    __u64 l2_send_duration;
    __u64 l2_package_to_queue_duration;
    __u64 l2_rcv_package_from_queue_duration;
    __u32 ifindex;
    __u32 l4_transmit_package_count;
    __u32 l4_transmit_package_size;
    __u32 l3_resolve_mac_count;
    __u32 l3_net_filter_count;
    __u32 l2_enter_queue_count;
    __u8 l4_retransmit_package_count;
    __u8 direction;
    __u8 func_name;
    __u8 pad[5];
};
_Static_assert(sizeof(struct socket_l24_event) == 152, "the l24 event is 152 bytes");

DATA_QUEUE(socket_l24_queue);

// l24_upload sends the L2 to L4 details of the call that exits (kernel_metrics_l2_l3), when it has any
static __noinline void l24_upload(void *ctx, struct sock_data_args_t *args, __u64 conid, __u64 random_id, __u64 direction_func) {
    // the details from l24_stamp on are this call's only when an l24 program of the call wrote them
    bool own = args->l24_stamp == args->start_nacs;
    if (own && (args->l4_duration | args->l3_duration | args->l2_duration | args->total_package_receive_from_queue_time |
                args->l4_transmit_package_count) == 0) {
        own = false;
    }
    if (!own && (args->ifindex | args->retransmit_package_count | args->l2_enter_queue_count) == 0) {
        return;
    }
    struct socket_l24_event *event = rover_reserve_buf(&socket_l24_queue, sizeof(*event));
    if (event == NULL) {
        return;
    }
    event->conid = conid;
    event->random_id = random_id;
    event->data_id = args->data_id;
    if (own) {
        __u8 write = (__u8)direction_func == SOCK_DATA_DIRECTION_EGRESS;
        event->l4_duration = args->l4_duration;
        event->l3_duration = args->l3_duration;
        event->l3_rcv_duration = write ? 0 : args->l3_output_rcv_duration;
        event->l3_local_duration = args->l3_local_duration;
        event->l3_output_duration = write ? args->l3_output_rcv_duration : 0;
        event->l3_resolve_mac_duration = args->total_resolve_mac_time;
        event->l3_net_filter_duration = args->total_net_filter_time;
        event->l2_duration = args->l2_duration;
        event->l2_ready_send_duration = args->l2_ready_send_duration;
        event->l2_send_duration = args->l2_send_duration;
        event->l2_package_to_queue_duration = args->total_package_to_queue_time;
        event->l2_rcv_package_from_queue_duration = args->total_package_receive_from_queue_time;
        event->l4_transmit_package_count = args->l4_transmit_package_count;
        event->l4_transmit_package_size = args->l4_transmit_package_size;
        event->l3_resolve_mac_count = args->total_resolve_mac_count;
        event->l3_net_filter_count = args->total_net_filter_count;
    } else {
        __builtin_memset(&event->l4_duration, 0, __builtin_offsetof(struct socket_l24_event, ifindex) -
                                                 __builtin_offsetof(struct socket_l24_event, l4_duration));
        event->l4_transmit_package_count = 0;
        event->l4_transmit_package_size = 0;
        event->l3_resolve_mac_count = 0;
        event->l3_net_filter_count = 0;
    }
    event->ifindex = args->ifindex;
    event->l2_enter_queue_count = args->l2_enter_queue_count;
    event->l4_retransmit_package_count = args->retransmit_package_count;
    event->direction = (__u8)direction_func;
    event->func_name = (__u8)(direction_func >> 8);
    __builtin_memset(event->pad, 0, sizeof(event->pad));
    rover_submit_buf(ctx, &socket_l24_queue, event, sizeof(*event));
}
