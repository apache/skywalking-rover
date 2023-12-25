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

SEC("kprobe/tcp_v4_rcv")
int tcp_v4_rcv(struct pt_regs * ctx) {
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->enter_tcp_rcv_time = bpf_ktime_get_ns();
        save_l24_tmp_args(L24_TEMP_ARGS_TCP_RCV, skb);
    }
    return 0;
}

SEC("kretprobe/tcp_v4_rcv")
int tcp_v4_rcv_ret(struct pt_regs * ctx) {
    struct skb_receive_detail* detail = get_l24_rcv_tmp_args(L24_TEMP_ARGS_TCP_RCV);
    if (detail != NULL) {
        detail->exit_tcp_rcv_time = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("kprobe/tcp_v6_rcv")
int tcp_v6_rcv(struct pt_regs * ctx) {
	struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        detail->enter_tcp_rcv_time = bpf_ktime_get_ns();
        save_l24_tmp_args(L24_TEMP_ARGS_TCP_RCV, skb);
    }
    return 0;
}

SEC("kretprobe/tcp_v6_rcv")
int tcp_v6_rcv_ret(struct pt_regs * ctx) {
    struct skb_receive_detail* detail = get_l24_rcv_tmp_args(L24_TEMP_ARGS_TCP_RCV);
    if (detail != NULL) {
        detail->exit_tcp_rcv_time = bpf_ktime_get_ns();
    }
    return 0;
}
