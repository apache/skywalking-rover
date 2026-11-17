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

// the netfilter hooks an sk_buff of a send or of a receive goes through: their count and time

#include "l24.h"

// nf_hook_slow(skb, state, e, s)
SEC("kprobe/nf_hook_slow")
int l24_nf_hook_slow(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb) != NULL ||
        bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb) != NULL) {
        save_l24_tmp_args(L24_TEMP_ARGS_NF_HOOK_SLOW, skb, bpf_ktime_get_ns());
    }
    return 0;
}

SEC("kretprobe/nf_hook_slow")
int l24_nf_hook_slow_ret(struct pt_regs * ctx) {
    struct l24_tmp_args_value kept = {};
    if (!take_l24_tmp_args(L24_TEMP_ARGS_NF_HOOK_SLOW, &kept)) {
        return 0;
    }
    __u64 duration = bpf_ktime_get_ns() - kept.start_time;
    struct skb_transmit_detail *transmit = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &kept.skb);
    if (transmit != NULL) {
        transmit->total_nf_count++;
        transmit->total_nf_time += duration;
        return 0;
    }
    struct skb_receive_detail *receive = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &kept.skb);
    if (receive != NULL) {
        receive->total_nf_count++;
        receive->total_nf_time += duration;
    }
    return 0;
}
