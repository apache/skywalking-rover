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
#include "socket_opts.h"
#include "socket_data.h"
#include "socket_reader.h"
#include "protocol_analyzer.h"
#include "../common/connection.h"
#include "../common/data_args.h"



// openssl read or write
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} openssl_sock_data_args SEC(".maps");

struct socket_detail_t {
    // basic information
    __u64 connection_id;
    __u64 random_id;
    __u64 data_id;

    // socket data operation times
    __u64 start_nacs;
    __u64 end_nacs;

    // l2-l4
    __u32 l4_duration;
    __u32 l3_duration;
    __u32 l3_local_duration;
    __u32 l3_output_duration;
    __u32 l3_resolve_mac_duration;
    __u32 l3_net_filter_duration;
    __u32 l2_duration;
    __u32 l2_ready_send_duration;
    __u32 l2_send_duration;
    __u32 l2_package_to_queue_time;
    __u32 l3_total_recv_time;
    __u32 ifindex;
    __u64 l4_package_rcv_from_queue_time;
    __u64 l4_total_package_size;
    __u8 l2_enter_queue_count;
    __u8 l4_package_count;
    __u8 l4_retransmit_package_count;
    __u8 l3_resolve_mac_count;
    __u8 l3_net_filter_count;
    __u8 op_func_name;
    __u8 data_protocol;
    __u8 ssl;
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


static __inline void upload_socket_detail(void *ctx, __u64 conid, struct active_connection_t *connection, __u8 func_name, struct sock_data_args_t *data_args, bool ssl, __u64 end_nacs) {
    // detail can only be send when the ssl are same:
    // 1. when the SSL connection sends SSL(unencrypted) message
    // 2. when the not SSL connection sends plain data
    if (connection->ssl == ssl) {
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

    detail->start_nacs = data_args->start_nacs;
    detail->end_nacs = end_nacs;

    detail->l4_duration = data_args->exit_l4_time - data_args->enter_l4_time;
    detail->l3_duration = data_args->l3_duration;
    detail->l3_local_duration = data_args->l3_local_duration;
    detail->l3_output_duration = data_args->l3_output_duration;
    detail->l3_resolve_mac_duration = data_args->total_resolve_mac_time;
    detail->l3_net_filter_duration = data_args->total_net_filter_time;
    detail->l2_duration = data_args->l2_duration;
    detail->l2_ready_send_duration = data_args->l2_ready_send_duration;
    detail->l2_send_duration = data_args->l2_send_duration;
    detail->ifindex = data_args->ifindex;
    detail->l4_total_package_size = data_args->total_package_size;
    detail->l4_package_count = data_args->package_count;
    detail->l4_retransmit_package_count = data_args->retransmit_package_count;
    detail->l3_resolve_mac_count = data_args->total_resolve_mac_count;
    detail->l3_net_filter_count = data_args->total_net_filter_count;
    detail->op_func_name = func_name;
    detail->data_protocol = connection->protocol;
    detail->ssl = connection->ssl;
    detail->l2_package_to_queue_time = data_args->total_package_to_queue_time;
    detail->l3_total_recv_time = data_args->l3_rcv_duration;
    detail->l2_enter_queue_count = data_args->l2_enter_queue_count;
    detail->l4_package_rcv_from_queue_time = data_args->total_package_receive_from_queue_time;

    // loss package detail

    bpf_perf_event_output(ctx, &socket_detail_data_queue, BPF_F_CURRENT_CPU, detail, sizeof(*detail));
}

static __always_inline void process_write_data(void *ctx, __u64 id, struct sock_data_args_t *args, ssize_t bytes_count,
                                        __u32 data_direction, const bool vecs, __u8 func_name, bool ssl) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    __u32 tgid = (__u32)(id >> 32);

    if (vecs && args->iovlen <= 0) {
        return;
    }
    if (args->fd < 0) {
        return;
    }
    if (bytes_count <= 0) {
        return;
    }

    // get current connection
    struct active_connection_t *conn = get_or_create_active_conn(ctx, tgid, args->fd, func_name, args->sk_role);
    if (conn == NULL) {
        return;
    }
    // only trace ipv4, v6, or unknown
    if (family_should_trace(conn->socket_family) == false) {
        return;
    }
    // process the ssl request if the fd not found
    struct sock_data_args_t *ssl_data_args = bpf_map_lookup_elem(&openssl_sock_data_args, &id);
    if (ssl_data_args != NULL && ssl_data_args->fd == 0) {
        ssl_data_args->fd = args->fd;
        conn->ssl = true;
    } else if (ssl) {
        conn->ssl = true;
    }

    // if the cannot getting the package size and count, then try to get it from the data args
    if (args->total_package_size == 0 && args->package_count == 0) {
        args->total_package_size = bytes_count;
        args->package_count = 1;
    }

    // if the protocol or role is unknown in the connection and the current data content is plaintext
    // then try to use protocol analyzer to analyze request or response and protocol type
    __u32 msg_type = 0;
    if ((conn->role == CONNECTION_ROLE_TYPE_UNKNOWN || conn->protocol == 0) && conn->ssl == ssl) {
        struct socket_buffer_reader_t *buf_reader = read_socket_data(args->buf, args->iovec, bytes_count);
        if (buf_reader != NULL) {
            msg_type = analyze_protocol(buf_reader->buffer, buf_reader->data_len, &conn->protocol);
            // if send request data to remote address or receive response data from remote address
            // then, recognized current connection is client
            if ((msg_type == CONNECTION_MESSAGE_TYPE_REQUEST && data_direction == SOCK_DATA_DIRECTION_EGRESS) ||
                (msg_type == CONNECTION_MESSAGE_TYPE_RESPONSE && data_direction == SOCK_DATA_DIRECTION_INGRESS)) {
                conn->role = CONNECTION_ROLE_TYPE_CLIENT;

            // if send response data to remote address or receive request data from remote address
            // then, recognized current connection is server
            } else if ((msg_type == CONNECTION_MESSAGE_TYPE_RESPONSE && data_direction == SOCK_DATA_DIRECTION_EGRESS) ||
                       (msg_type == CONNECTION_MESSAGE_TYPE_REQUEST && data_direction == SOCK_DATA_DIRECTION_INGRESS)) {
                conn->role = CONNECTION_ROLE_TYPE_SERVER;
            }
        }
    }

    __u64 conid = gen_tgid_fd(tgid, args->fd);
    // upload the socket detail
    upload_socket_detail(ctx, conid, conn, func_name, args, ssl, curr_nacs);

    // upload the socket data if need
    struct upload_data_args *upload_data_args = generate_socket_upload_args();
    if (upload_data_args != NULL) {
        upload_data_args->start_time = args->start_nacs;
        upload_data_args->end_time = curr_nacs;
        upload_data_args->con_id = conid;
        upload_data_args->random_id = conn->random_id;
        upload_data_args->socket_data_id = args->data_id;
        upload_data_args->socket_data_iovec = args->iovec;
        upload_data_args->socket_data_iovlen = args->iovlen;
        upload_data_args->bytes_count = bytes_count;
        upload_data_args->socket_data_buf = args->buf;
        upload_data_args->data_direction = data_direction;
        upload_data_args->connection_protocol = conn->protocol;
        upload_data_args->connection_ssl = conn->ssl;
        upload_data_args->socket_ssl_buffer_force_unfinished = args->ssl_buffer_force_unfinished;
        upload_data_args->connection_skip_data_upload = conn->skip_data_upload;
        upload_data_args->socket_data_ssl = ssl;
        upload_socket_data(ctx, upload_data_args);
    };
}