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
#include "socket_reader.h"
#include "protocol_analyzer.h"
#include "../common/connection.h"
#include "../common/data_args.h"

#define SOCKET_UPLOAD_CHUNK_LIMIT 12

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

struct socket_data_upload_event {
    __u8 protocol;
    __u8 have_reduce_after_chunk;
    __u8 direction;
    __u8 finished;
    __u16 sequence;
    __u16 data_len;
    __u64 start_time;
    __u64 end_time;
    __u64 conid;
    __u64 randomid;
    __u64 data_id;
    __u64 total_size;
    char buffer[MAX_TRANSMIT_SOCKET_READ_LENGTH + 1];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_data_upload_event);
    __uint(max_entries, 1);
} socket_data_upload_event_per_cpu_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_data_upload_event_queue SEC(".maps");

struct socket_data_sequence_t {
    __u64 data_id;
    __u16 sequence;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1000);
	__type(key, __u64);
	__type(value, struct socket_data_sequence_t);
} socket_data_sequence_generator SEC(".maps");
static __inline __u16 generate_socket_sequence(__u64 conid, __u64 data_id) {
    struct socket_data_sequence_t *seq = bpf_map_lookup_elem(&socket_data_sequence_generator, &conid);
    if (seq == NULL) {
        struct socket_data_sequence_t data = {};
        data.data_id = data_id;
        data.sequence = 0;
        bpf_map_update_elem(&socket_data_sequence_generator, &conid, &data, BPF_NOEXIST);
        return 0;
    }
    if (seq->data_id != data_id) {
        seq->data_id = data_id;
        seq->sequence = 0;
    } else {
        seq->sequence++;
    }
    return seq->sequence;
}

static __inline void upload_socket_detail(void *ctx, __u64 conid, struct active_connection_t *connection, __u8 func_name, struct sock_data_args_t *data_args, bool ssl, __u64 end_nacs) {
    // only send the original socket syscall(not ssl)
    if (ssl == true) {
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

static __always_inline void __upload_socket_data_with_buffer(void *ctx, __u8 index, char* buf, size_t size, __u32 is_finished, __u8 have_reduce_after_chunk, struct socket_data_upload_event *event) {
    event->sequence = index;
    event->data_len = size;
    event->finished = is_finished;
    event->have_reduce_after_chunk = have_reduce_after_chunk;
    if (size <= 0) {
        return;
    }
    asm volatile("%[size] &= 0x7ff;\n" ::[size] "+r"(size) :);
    bpf_probe_read(&event->buffer, size & 0x7ff, buf);

    bpf_perf_event_output(ctx, &socket_data_upload_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

static __always_inline void upload_socket_data_buf(void *ctx, char* buf, ssize_t size, struct socket_data_upload_event *event, __u8 force_unfinished) {
    ssize_t already_send = 0;
#pragma unroll
    for (__u8 index = 0; index < SOCKET_UPLOAD_CHUNK_LIMIT; index++) {
        // calculate bytes need to send
        ssize_t remaining = size - already_send;
        size_t need_send_in_chunk = 0;
        __u8 have_reduce_after_chunk = 0;
        if (remaining > MAX_TRANSMIT_SOCKET_READ_LENGTH) {
            need_send_in_chunk = MAX_TRANSMIT_SOCKET_READ_LENGTH;
            have_reduce_after_chunk = 1;
        } else {
            need_send_in_chunk = remaining;
        }

        __u32 is_finished = (need_send_in_chunk + already_send) >= size || index == (SOCKET_UPLOAD_CHUNK_LIMIT - 1) ? true : false;
        __u8 sequence = index;
        if (force_unfinished == 1 && need_send_in_chunk > 0) {
            is_finished = 0;
            sequence = generate_socket_sequence(event->conid, event->data_id);
        }
        __upload_socket_data_with_buffer(ctx, sequence, buf + already_send, need_send_in_chunk, is_finished, have_reduce_after_chunk, event);
        already_send += need_send_in_chunk;

    }
}

#define UPLOAD_PER_SOCKET_DATA_IOV() \
if (iov_index < iovlen) {                                                   \
    struct iovec cur_iov;                                                   \
    bpf_probe_read(&cur_iov, sizeof(cur_iov), &iov[iov_index]);             \
    ssize_t remaining = size - already_send;                                \
    size_t need_send_in_chunk = remaining - cur_iov_sended;                 \
    __u8 have_reduce_after_chunk = 0;                                       \
    if (cur_iov_sended + need_send_in_chunk > cur_iov.iov_len) {            \
        need_send_in_chunk = cur_iov.iov_len - cur_iov_sended;              \
        if (need_send_in_chunk > MAX_TRANSMIT_SOCKET_READ_LENGTH) {         \
            need_send_in_chunk = MAX_TRANSMIT_SOCKET_READ_LENGTH;           \
            have_reduce_after_chunk = 1;                                    \
        } else {                                                            \
            iov_index++;                                                    \
            cur_iov_sended = 0;                                             \
        }                                                                   \
    } else if (need_send_in_chunk > MAX_TRANSMIT_SOCKET_READ_LENGTH) {      \
        need_send_in_chunk = MAX_TRANSMIT_SOCKET_READ_LENGTH;               \
        have_reduce_after_chunk = 1;                                        \
    }                                                                       \
    __u32 is_finished = (need_send_in_chunk + already_send) >= size || loop_count == (SOCKET_UPLOAD_CHUNK_LIMIT - 1) ? true : false;                            \
    __upload_socket_data_with_buffer(ctx, loop_count, cur_iov.iov_base + cur_iov_sended, need_send_in_chunk, is_finished, have_reduce_after_chunk, event);      \
    already_send += need_send_in_chunk;                                                                                              \
    loop_count++;                                                                                                                    \
}

static __always_inline void upload_socket_data_iov(void *ctx, struct iovec* iov, const size_t iovlen, ssize_t size, struct socket_data_upload_event *event) {
    ssize_t already_send = 0;
    ssize_t cur_iov_sended = 0;
    __u8 iov_index = 0;
    __u8 loop_count = 0;

    // each count is same with SOCKET_UPLOAD_CHUNK_LIMIT
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
}

static __inline void upload_socket_data(void *ctx, __u64 start_time, __u64 end_time, __u64 conid, struct active_connection_t *connection, struct sock_data_args_t *args, ssize_t bytes_count, __u32 existing_msg_type, __u32 data_direction, bool ssl) {
    // must have protocol and ssl must same(plain)
    // if the connection data is needs to skip upload, then skip
    if (connection->protocol == CONNECTION_PROTOCOL_UNKNOWN || connection->ssl != ssl || connection->skip_data_upload == 1) {
        return;
    }
    // generate event
    __u32 kZero = 0;
    struct socket_data_upload_event *event = bpf_map_lookup_elem(&socket_data_upload_event_per_cpu_map, &kZero);
    if (event == NULL) {
        return;
    }

    // basic data
    event->start_time = start_time;
    event->end_time = end_time;
    event->protocol = connection->protocol;
    event->direction = data_direction;
    event->conid = conid;
    event->randomid = connection->random_id;
    event->total_size = bytes_count;
    event->data_id = args->data_id;

    if (args->buf != NULL) {
        upload_socket_data_buf(ctx, args->buf, bytes_count, event, args->ssl_buffer_force_unfinished);
    } else if (args->iovec != NULL) {
        upload_socket_data_iov(ctx, args->iovec, args->iovlen, bytes_count, event);
    }
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
    upload_socket_data(ctx, args->start_nacs, curr_nacs, conid, conn, args, bytes_count, msg_type, data_direction, ssl);
}