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

#include "socket_opts.h"

struct connect_track_remote {
    __u64 iph;
    __u64 ipl;
    __u16 port;
};

struct sock_data_args_t {
    __u32 fd;
    // current read/write is calls on the sockets.
    __u32 is_sock_event;
    size_t iovlen;
    unsigned int* msg_len;
    __u64 start_nacs;
    // buffer
    char* buf;
    struct iovec *iovec;
    __u64 data_id;
    // for openssl
    __u32 excepted_size;
    __u32 ifindex;
    __u64 total_package_size;
    __u8 package_count;
    __u8 retransmit_package_count;
    __u8 ssl_buffer_force_unfinished;
    __u8 sk_role;
    __u32 l2_enter_queue_count;
    struct sk_buff *buffer;
    __u64 enter_l4_time;
    __u64 exit_l4_time;
    __u64 l3_duration;
    __u64 l3_rcv_duration;
    __u64 l3_local_duration;
    __u64 l3_output_duration;
    __u32 total_resolve_mac_count;
    __u32 total_net_filter_count;
    __u64 total_resolve_mac_time;
    __u64 total_net_filter_time;
    __u64 total_package_to_queue_time;
    __u64 total_package_receive_from_queue_time;

    __u64 l2_duration;
    __u64 l2_enter_queue_package_count;
    __u64 l2_ready_send_duration;
    __u64 l2_send_duration;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} socket_data_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, __u64);
} socket_data_id_generate_map SEC(".maps");

static __inline __u64 get_socket_data_id(__u8 from, __u64 id, __u32 fd) {
    __u32 tgid = (__u32)(id >> 32);
    __u64 key = ((__u64)tgid << 32) | fd;
    __u64 *data_id = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
    if (!data_id) {
        return 0;
    }
    return *data_id;
}

static __inline __u64 generate_socket_data_id(__u64 id, __u32 fd, __u32 func_name, bool check) {
    __u32 tgid = (__u32)(id >> 32);
    __u64 key = ((__u64)tgid << 32) | fd;
    if (check) {
        if (tgid_should_trace(tgid) == false) {
            return 0;
        }
    }
    __u64 *data_id = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
    if (!data_id) {
        __u64 tmp = 0;
        bpf_map_update_elem(&socket_data_id_generate_map, &key, &tmp, BPF_NOEXIST);
        data_id = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
        if (!data_id) {
            return 0;
        }
    }
    (*data_id)++;
    return *data_id;
}