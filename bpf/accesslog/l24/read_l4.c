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

// L4 of a receive: the time an sk_buff of skb_receive_detail spends in tcp_v4_rcv or tcp_v6_rcv

#include "l24.h"

static __always_inline int l24_tcp_rcv_enter(struct pt_regs *ctx) {
    struct sk_buff * skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &skb);
    if (detail != NULL) {
        save_l24_tmp_args(L24_TEMP_ARGS_TCP_RCV, skb, bpf_ktime_get_ns());
    }
    return 0;
}

static __always_inline int l24_tcp_rcv_exit() {
    struct l24_tmp_args_value kept = {};
    if (!take_l24_tmp_args(L24_TEMP_ARGS_TCP_RCV, &kept)) {
        return 0;
    }
    struct skb_receive_detail *detail = bpf_map_lookup_elem(&sk_buff_receive_detail_map, &kept.skb);
    if (detail != NULL) {
        detail->tcp_rcv_duration += bpf_ktime_get_ns() - kept.start_time;
    }
    return 0;
}

SEC("kprobe/tcp_v4_rcv")
int l24_tcp_v4_rcv(struct pt_regs * ctx) {
    return l24_tcp_rcv_enter(ctx);
}

SEC("kretprobe/tcp_v4_rcv")
int l24_tcp_v4_rcv_ret(struct pt_regs * ctx) {
    return l24_tcp_rcv_exit();
}

SEC("kprobe/tcp_v6_rcv")
int l24_tcp_v6_rcv(struct pt_regs * ctx) {
    return l24_tcp_rcv_enter(ctx);
}

SEC("kretprobe/tcp_v6_rcv")
int l24_tcp_v6_rcv_ret(struct pt_regs * ctx) {
    return l24_tcp_rcv_exit();
}
