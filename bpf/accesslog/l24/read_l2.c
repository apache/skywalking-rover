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

// L2 of a receive: the device an sk_buff comes from and when (skb_receive_detail, for every sk_buff the host receives),
// and the copy of an sk_buff to the reader, which adds its details into the call (l24_skb_copy_datagram_iovec)

#include "l24.h"

struct trace_event_raw_net_dev_template {
    struct trace_entry ent;
    void *skbaddr;
} __attribute__((preserve_access_index));

SEC("tracepoint/net/netif_receive_skb")
int l24_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx) {
    struct sk_buff * skb = (struct sk_buff *)ctx->skbaddr;
    struct net_device *device = _(skb->dev);
    int ifindex = 0;
    if (device != NULL) {
        ifindex = _(device->ifindex);
    }
    struct skb_receive_detail detail = {
        .ifindex = ifindex,
        .netif_receive_time = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&sk_buff_receive_detail_map, &skb, &detail, BPF_ANY);
    return 0;
}

// the copy of an sk_buff to the reader (skb:skb_copy_datagram_iovec, besides the program of syscalls/transfer.c, which
// counts the packages): the details of the sk_buff go into the call, once (the entry is deleted at its first copy)
SEC("tracepoint/skb/skb_copy_datagram_iovec")
int l24_skb_copy_datagram_iovec(struct trace_event_raw_skb_copy_datagram_iovec *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail == NULL) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {
        l24_args_own(data_args);
        __u64 now = bpf_ktime_get_ns();
        // l4
        data_args->l4_duration += detail->tcp_rcv_duration;
        // l3
        if (detail->exit_ip_rcv_time > 0 && detail->enter_ip_rcv_time > 0) {
            data_args->l3_duration += detail->exit_ip_rcv_time - detail->enter_ip_rcv_time;
        }
        if (detail->ip_rcv_finish_time > 0 && detail->enter_ip_rcv_time > 0) {
            data_args->l3_output_rcv_duration += detail->ip_rcv_finish_time - detail->enter_ip_rcv_time;
        }
        if (detail->ip_local_finish_time > 0 && detail->ip_local_time > 0) {
            data_args->l3_local_duration += detail->ip_local_finish_time - detail->ip_local_time;
        }
        data_args->total_net_filter_count += detail->total_nf_count;
        data_args->total_net_filter_time += detail->total_nf_time;
        // l2
        if (detail->ifindex != 0) {
            data_args->ifindex = detail->ifindex;
        }
        if (detail->netif_receive_time > 0 && detail->ip_local_time > 0) {
            data_args->total_package_to_queue_time += detail->ip_local_time - detail->netif_receive_time;
        }
        if (detail->ip_local_time > 0) {
            data_args->total_package_receive_from_queue_time += now - detail->ip_local_time;
        }
    }
    bpf_map_delete_elem(&sk_buff_receive_detail_map, &skb);
    return 0;
}
