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

#include "api.h"
#include "l24.h"

SEC("kprobe/nf_hook_slow")
int nf_hook_slow(struct pt_regs * ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct skb_transmit_detail *transmit_detail = bpf_map_lookup_elem(&sk_buff_transmit_detail_map, &skb);
	if (transmit_detail != NULL) {
	    transmit_detail->enter_nf_time = bpf_ktime_get_ns();
	    save_l24_tmp_args(L24_TEMP_ARGS_TRANSMIT_NF_HOOK_SLOW, skb);
	    return 0;
	}
	struct skb_receive_detail *recv_detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
	if (recv_detail != NULL) {
        recv_detail->enter_nf_time = bpf_ktime_get_ns();
        save_l24_tmp_args(L24_TEMP_ARGS_RCV_NF_HOOK_SLOW, skb);
        return 0;
    }
	return 0;
}

SEC("kretprobe/nf_hook_slow")
int nf_hook_slow_ret(struct pt_regs * ctx) {
    struct skb_transmit_detail *transmit_detail = get_l24_transmit_tmp_args(L24_TEMP_ARGS_TRANSMIT_NF_HOOK_SLOW);
    if (transmit_detail != NULL) {
        transmit_detail->total_nf_count++;
        transmit_detail->total_nf_time = bpf_ktime_get_ns() - transmit_detail->enter_nf_time;
        return 0;
    }
    struct skb_receive_detail* rcv_detail = get_l24_rcv_tmp_args(L24_TEMP_ARGS_RCV_NF_HOOK_SLOW);
    if (rcv_detail != NULL) {
        rcv_detail->total_nf_count++;
        rcv_detail->total_nf_time = bpf_ktime_get_ns() - rcv_detail->enter_nf_time;
        return 0;
    }
	return 0;
}