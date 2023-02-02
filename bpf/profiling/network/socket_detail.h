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

#include "common.h"

struct socket_detail_t {
    __u64 connection_id;
    __u64 random_id;
    __u64 data_id;
    __u64 total_package_size;
    __u32 ifindex;
    __u8 package_count;
    __u8 func_name;
    __u8 rtt_count;
    __u8 protocol;
    __u32 rtt_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_detail_t);
    __uint(max_entries, 1);
} socket_detail_event_per_cpu_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_detail_data_queue SEC(".maps");

static __inline void upload_socket_detail(void *ctx, __u64 conid, struct active_connection_t *connection, __u8 func_name, struct sock_data_args_t *data_args, bool ssl) {
    // only send the original socket syscall(not ssl) and the protocol must been set
    if (ssl == true || connection->protocol == CONNECTION_PROTOCOL_UNKNOWN) {
        return;
    }
    __u32 kZero = 0;
    struct socket_detail_t *detail = bpf_map_lookup_elem(&socket_detail_event_per_cpu_map, &kZero);
    if (detail == NULL) {
        return;
    }

    detail->connection_id = conid;
    detail->random_id = connection->random_id;
    detail->data_id = data_args->data_id;
    detail->func_name = func_name;
    detail->total_package_size = data_args->total_package_size;
    detail->ifindex = data_args->ifindex;
    detail->package_count = data_args->package_count;
    detail->protocol = connection->protocol;

    if (data_args->rtt_count > 0) {
        detail->rtt_count = data_args->rtt_count;
        detail->rtt_time = data_args->rtt_time;
    }

    bpf_perf_event_output(ctx, &socket_detail_data_queue, BPF_F_CURRENT_CPU, detail, sizeof(*detail));
}