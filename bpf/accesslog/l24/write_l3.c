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

// L3 of a send: from __ip_queue_xmit to the device, per sk_buff (skb_transmit_detail), added into the call at the
// return of __ip_queue_xmit (the L2 tracepoints of an sk_buff the device queue sends later are not seen)

#include "l24.h"

// __ip_queue_xmit(sk, skb, fl, tos)
SEC("kprobe/__ip_queue_xmit")
int l24_ip_queue_xmit(struct pt_regs * ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {
        struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
        l24_args_own(data_args);
        // the sk_buff of the transmit in progress
        data_args->buffer = skb;
        struct skb_transmit_detail detail = {};
        detail.l3_enter_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&sk_buff_transmit_detail_map, &skb, &detail, BPF_ANY);
    }
    return 0;
}

SEC("kretprobe/__ip_queue_xmit")
int l24_ip_queue_xmit_ret(struct pt_regs * ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args == NULL) {
        return 0;
    }
    l24_args_own(data_args);
    struct sk_buff *skb = data_args->buffer;
    if (skb == NULL) {
        return 0;
    }
    data_args->buffer = NULL;
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail == NULL) {
        return 0;
    }
    __u64 now = bpf_ktime_get_ns();
    if (detail->l3_enter_time > 0) {
        data_args->l3_duration += now - detail->l3_enter_time;
    }
    if (detail->l3_output_time > 0 && detail->l3_local_time > 0) {
        data_args->l3_local_duration += detail->l3_output_time - detail->l3_local_time;
    }
    if (detail->l3_finish_time > 0 && detail->l3_output_time > 0) {
        data_args->l3_output_rcv_duration += detail->l3_finish_time - detail->l3_output_time;
    }
    data_args->total_resolve_mac_count += detail->total_resolve_neigh_count;
    data_args->total_resolve_mac_time += detail->total_resolve_neigh_time;
    data_args->total_net_filter_count += detail->total_nf_count;
    data_args->total_net_filter_time += detail->total_nf_time;
    if (detail->l2_enter_time > 0 && detail->l2_exit_time > 0) {
        data_args->l2_duration += detail->l2_exit_time - detail->l2_enter_time;
        data_args->l2_enter_queue_count++;
    }
    if (detail->ifindex != 0) {
        data_args->ifindex = detail->ifindex;
    }
    if (detail->l2_start_xmit_time > 0 && detail->l2_enter_time > 0) {
        data_args->l2_ready_send_duration += detail->l2_start_xmit_time - detail->l2_enter_time;
    }
    if (detail->l2_finish_xmit_time > 0 && detail->l2_start_xmit_time > 0) {
        data_args->l2_send_duration += detail->l2_finish_xmit_time - detail->l2_start_xmit_time;
    }
    bpf_map_delete_elem(&sk_buff_transmit_detail_map, &skb);
    return 0;
}

// __ip_local_out(net, sk, skb)
SEC("kprobe/__ip_local_out")
int l24_ip_local_out(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->l3_local_time = bpf_ktime_get_ns();
    }
    return 0;
}

// ip_output(net, sk, skb)
SEC("kprobe/ip_output")
int l24_ip_output(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->l3_output_time = bpf_ktime_get_ns();
    }
    return 0;
}

// ip_finish_output2(net, sk, skb): the device of the route
SEC("kprobe/ip_finish_output2")
int l24_ip_finish_output2(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        long unsigned int refdst = _(skb->_skb_refdst);
        struct dst_entry *entry = (void *)(refdst & SKB_DST_PTRMASK);
        if (entry != NULL) {
            struct net_device *device = _(entry->dev);
            if (device != NULL) {
                detail->ifindex = _(device->ifindex);
            }
        }
        detail->l3_finish_time = bpf_ktime_get_ns();
    }
    return 0;
}

// neigh_resolve_output(neigh, skb)
SEC("kprobe/neigh_resolve_output")
int l24_neigh_resolve_output(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        save_l24_tmp_args(L24_TEMP_ARGS_NEIGH_RESOLVE_OUTPUT, skb, bpf_ktime_get_ns());
    }
    return 0;
}

SEC("kretprobe/neigh_resolve_output")
int l24_neigh_resolve_output_ret(struct pt_regs * ctx) {
    struct l24_tmp_args_value kept = {};
    if (!take_l24_tmp_args(L24_TEMP_ARGS_NEIGH_RESOLVE_OUTPUT, &kept)) {
        return 0;
    }
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &kept.skb);
    if (detail != NULL) {
        detail->total_resolve_neigh_count++;
        detail->total_resolve_neigh_time += bpf_ktime_get_ns() - kept.start_time;
    }
    return 0;
}
