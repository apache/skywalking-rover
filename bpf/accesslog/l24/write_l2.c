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

struct trace_event_raw_net_dev_start_xmit {
        struct trace_entry ent;
        __u32 __data_loc_name;
        __u16 queue_mapping;
        const void *skbaddr;
} __attribute__((aligned(8))) __attribute__((preserve_access_index)) ;


struct trace_event_raw_net_dev_xmit {
    struct trace_entry ent;
    void *skbaddr;
} __attribute__((preserve_access_index));


SEC("kprobe/__dev_queue_xmit")
int dev_queue_emit(struct pt_regs * ctx){
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->l2_enter_time = bpf_ktime_get_ns();
        save_l24_tmp_args(L24_TEMP_ARGS_DEV_QUEUE_EMIT, skb);
    }
    return 0;
}

SEC("kretprobe/__dev_queue_xmit")
int dev_queue_emit_ret(struct pt_regs * ctx){
    struct skb_transmit_detail *detail = get_l24_transmit_tmp_args(L24_TEMP_ARGS_DEV_QUEUE_EMIT);
    if (detail != NULL) {
        detail->l2_exit_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("tracepoint/net/net_dev_start_xmit")
int tracepoint_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *args) {
    struct sk_buff * skb = (struct sk_buff *)args->skbaddr;
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->l2_start_xmit_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("tracepoint/net/net_dev_xmit")
int tracepoint_net_dev_xmit(struct trace_event_raw_net_dev_xmit *args) {
    struct sk_buff * skb = (struct sk_buff *)args->skbaddr;
    struct skb_transmit_detail *detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
    if (detail != NULL) {
        detail->l2_finish_xmit_time = bpf_ktime_get_ns();
    }
    return 0;
}