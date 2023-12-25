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

struct netif_receive_skb {
	unsigned long long pad;
	void * skbaddr;
};

SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct netif_receive_skb *ctx) {
    struct sk_buff * skb = (struct sk_buff *)ctx->skbaddr;

    struct net_device *device = _(skb->dev);
    int ifindex;
    bpf_probe_read(&ifindex, sizeof(ifindex), &device->ifindex);

    struct skb_receive_detail detail = {
        .ifindex = ifindex,
        .netif_receive_time = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&sk_buff_receive_detail_map, &skb, &detail, 0);
    return 0;
}
