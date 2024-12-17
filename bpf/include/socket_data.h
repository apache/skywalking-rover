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
#include "protocol_analyzer.h"
#include "queue.h"

#define SOCKET_UPLOAD_CHUNK_LIMIT 12

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
    __u64 prev_data_id;
    __u64 total_size;
    char buffer[MAX_TRANSMIT_SOCKET_READ_LENGTH];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_data_upload_event);
    __uint(max_entries, 1);
} socket_data_upload_event_per_cpu_map SEC(".maps");
DATA_QUEUE(socket_data_upload_queue);

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

struct upload_data_args {
    __u64 start_time;
    __u64 end_time;
    __u64 con_id;
    __u64 random_id;

    __u64 socket_data_id;
    __u64 prev_socket_data_id;
    struct iovec *socket_data_iovec;
    size_t socket_data_iovlen;
    ssize_t bytes_count;
    char* socket_data_buf;

    __u32 data_direction;
    __u8 connection_protocol;
    __u8 connection_ssl;
    __u8 socket_ssl_buffer_force_unfinished;
    // skip data upload when the protocol break(such as HTTP2)
    __u8 connection_skip_data_upload;
    bool socket_data_ssl;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct upload_data_args);
    __uint(max_entries, 1);
} socket_data_upload_args_per_cpu_map SEC(".maps");
static __always_inline struct upload_data_args* generate_socket_upload_args() {
    __u32 kZero = 0;
    return bpf_map_lookup_elem(&socket_data_upload_args_per_cpu_map, &kZero);
}

static __always_inline void __upload_socket_data_with_buffer(void *ctx, __u8 index, char* buf, size_t size, __u32 is_finished, __u8 have_reduce_after_chunk, struct upload_data_args *args) {
    struct socket_data_upload_event *socket_data_event;
    socket_data_event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*socket_data_event));
    if (socket_data_event == NULL) {
        return;
    }

    if (size > sizeof(socket_data_event->buffer)) {
        size = sizeof(socket_data_event->buffer);
    }
    if (size <= 0) {
        rover_discard_buf(socket_data_event);
        return;
    }

    // basic data
    socket_data_event->start_time = args->start_time;
    socket_data_event->end_time = args->end_time;
    socket_data_event->protocol = args->connection_protocol;
    socket_data_event->direction = args->data_direction;
    socket_data_event->conid = args->con_id;
    socket_data_event->randomid = args->random_id;
    socket_data_event->total_size = args->bytes_count;
    socket_data_event->data_id = args->socket_data_id;
    socket_data_event->prev_data_id = args->prev_socket_data_id;

    socket_data_event->sequence = index;
    socket_data_event->data_len = size;
    socket_data_event->finished = is_finished;
    socket_data_event->have_reduce_after_chunk = have_reduce_after_chunk;
    asm volatile("%[size] &= 0x7ff;\n" ::[size] "+r"(size) :);
    bpf_probe_read(&socket_data_event->buffer, size, buf);
    rover_submit_buf(ctx, &socket_data_upload_queue, socket_data_event, sizeof(*socket_data_event));
}

static __always_inline void upload_socket_data_buf(void *ctx, char* buf, ssize_t size, struct upload_data_args *args, __u8 force_unfinished) {
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
            sequence = generate_socket_sequence(args->con_id, args->socket_data_id);
        }
        __upload_socket_data_with_buffer(ctx, sequence, buf + already_send, need_send_in_chunk, is_finished, have_reduce_after_chunk, args);
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
    __upload_socket_data_with_buffer(ctx, loop_count, cur_iov.iov_base + cur_iov_sended, need_send_in_chunk, is_finished, have_reduce_after_chunk, args);      \
    already_send += need_send_in_chunk;                                                                                              \
    loop_count++;                                                                                                                    \
}

static __always_inline void upload_socket_data_iov(void *ctx, struct iovec* iov, const size_t iovlen, ssize_t size, struct upload_data_args *args) {
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

struct socket_data_last_id_t {
    __u64 random_id;
    __u64 socket_data_id;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct socket_data_last_id_t);
} socket_data_last_id_map SEC(".maps");

static __inline void upload_socket_data(void *ctx, struct upload_data_args *args) {
    // must have protocol and ssl must same(plain)
    // if the connection data is needs to skip upload, then skip
    if (args->connection_protocol == CONNECTION_PROTOCOL_UNKNOWN || args->connection_ssl != args->socket_data_ssl || args->connection_skip_data_upload == 1) {
        return;
    }
    struct socket_data_last_id_t *latest = bpf_map_lookup_elem(&socket_data_last_id_map, &args->con_id);
    args->prev_socket_data_id = 0;
    if (latest != NULL && latest->random_id == args->random_id) {
        args->prev_socket_data_id = latest->socket_data_id;
    }
    if (args->socket_data_buf != NULL) {
        upload_socket_data_buf(ctx, args->socket_data_buf, args->bytes_count, args, args->socket_ssl_buffer_force_unfinished);
    } else if (args->socket_data_iovec != NULL) {
        upload_socket_data_iov(ctx, args->socket_data_iovec, args->socket_data_iovlen, args->bytes_count, args);
    }

    if (latest == NULL || latest->socket_data_id != args->socket_data_id) {
        struct socket_data_last_id_t data = {};
        data.random_id = args->random_id;
        data.socket_data_id = args->socket_data_id;
        bpf_map_update_elem(&socket_data_last_id_map, &args->con_id, &data, BPF_ANY);
    }
}