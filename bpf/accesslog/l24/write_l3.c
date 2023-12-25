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

SEC("kprobe/__ip_queue_xmit")
int ip_queue_xmit(struct pt_regs * ctx){
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
        // update current transmit skb
        data_args->buffer = skb;

        // adding skb detail into map(for getting all l2-3 detail from skb)
        struct skb_transmit_detail detail = {};
        detail.l3_enter_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&sk_buff_transmit_detail_map, &skb, &detail, 0);
    }
    return 0;
}

SEC("kretprobe/__ip_queue_xmit")
int ip_queue_xmit_ret(struct pt_regs * ctx){
    __u64 id = bpf_get_current_pid_tgid();
    // getting skb
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
	if (data_args == NULL) {
	    return 0;
	}
	// getting all l2-3 detail
	struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &data_args->buffer);
	if (detail == NULL) {
	    return 0;
	}

    data_args->l3_duration += bpf_ktime_get_ns() - detail->l3_enter_time;
    if (detail->l3_output_time > 0 && detail->l3_local_time > 0) {
        data_args->l3_local_duration += detail->l3_output_time - detail->l3_local_time;
    }
    if (detail->l3_finish_time > 0 && detail->l3_output_time > 0) {
        data_args->l3_output_duration += detail->l3_finish_time - detail->l3_output_time;
    }
    data_args->total_resolve_mac_count = detail->total_resolve_neigh_count;
    data_args->total_resolve_mac_time = detail->total_resolve_neigh_time;
    data_args->total_net_filter_count = detail->total_nf_count;
    data_args->total_net_filter_time = detail->total_nf_time;

    if (detail->l2_enter_time > 0 && detail->l2_exit_time > 0) {
        data_args->l2_duration = detail->l2_exit_time - detail->l2_enter_time;
        data_args->l2_enter_queue_count++;
    }
    data_args->ifindex = _(detail->ifindex);
    if (detail->l2_enter_time > 0) {
        data_args->l2_enter_queue_package_count++;
    }
    if (detail->l2_start_xmit_time > 0 && detail->l2_enter_time > 0) {
        data_args->l2_ready_send_duration += detail->l2_start_xmit_time - detail->l2_enter_time;
    }
    if (detail->l2_finish_xmit_time > 0 && detail->l2_start_xmit_time > 0) {
        data_args->l2_send_duration += detail->l2_finish_xmit_time - detail->l2_start_xmit_time;
    }
    return 0;
}

SEC("kprobe/ip_local_out")
int ip_local(struct pt_regs * ctx){
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->l3_local_time = bpf_ktime_get_ns();
    }
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sk_buff *);
} ip_output_temp SEC(".maps");


SEC("kprobe/ip_output")
int ip_output(struct pt_regs * ctx){
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->l3_output_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("kprobe/ip_finish_output2")
int ip_finish_output2(struct pt_regs * ctx){
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        long unsigned int _skb_refdst;
        bpf_probe_read(&_skb_refdst, sizeof(_skb_refdst), &skb->_skb_refdst);
        struct dst_entry *entry = (void *)(_skb_refdst & SKB_DST_PTRMASK);
        struct net_device *device;
        bpf_probe_read(&device, sizeof(device), &entry->dev);

        int ifindex;
        bpf_probe_read(&ifindex, sizeof(ifindex), &device->ifindex);
        detail->ifindex = ifindex;
        detail->l3_finish_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("kprobe/neigh_resolve_output")
int neigh_resolve_output(struct pt_regs * ctx){
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->enter_resolve_neigh_time = bpf_ktime_get_ns();
        save_l24_tmp_args(L24_TEMP_ARGS_NEIGHT_RESOLVE_OUTPUT, skb);
    }
    return 0;
}

SEC("kretprobe/neigh_resolve_output")
int neigh_resolve_output_ret(struct pt_regs * ctx){
    struct skb_transmit_detail *detail = get_l24_transmit_tmp_args(L24_TEMP_ARGS_NEIGHT_RESOLVE_OUTPUT);
    if (detail != NULL) {
        detail->total_resolve_neigh_count++;
        detail->total_resolve_neigh_time = bpf_ktime_get_ns() - detail->enter_resolve_neigh_time;
    }
    return 0;
}
