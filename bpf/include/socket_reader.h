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

struct socket_buffer_reader_t {
    __u32 data_len;
    char buffer[MAX_PROTOCOL_SOCKET_READ_LENGTH + 1];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_buffer_reader_t);
    __uint(max_entries, 1);
} socket_buffer_reader_map SEC(".maps");

static __inline struct socket_buffer_reader_t* read_socket_data(char* buf, struct iovec *iovec, __u32 bytes_count) {
    __u64 size = 0;
    __u32 kZero = 0;
    char* data_buf;
    struct socket_buffer_reader_t* reader = bpf_map_lookup_elem(&socket_buffer_reader_map, &kZero);
    if (reader == NULL) {
        return NULL;
    }
    if (buf != NULL) {
        data_buf = buf;
        size = bytes_count;
    } else if (iovec != NULL) {
        struct iovec iov;
        bpf_probe_read(&iov, sizeof(iov), iovec);
        __u64 tmp = iov.iov_len;
        if (tmp > bytes_count) {
            tmp = bytes_count;
        }
        data_buf = (char *)iov.iov_base;
        size = tmp;
    }
    if (size <= 0) {
        return NULL;
    }
    if (size > MAX_PROTOCOL_SOCKET_READ_LENGTH) {
        size = MAX_PROTOCOL_SOCKET_READ_LENGTH;
    }
    asm volatile("%[size] &= 0x1f;\n" ::[size] "+r"(size) :);
    bpf_probe_read(&reader->buffer, size & MAX_PROTOCOL_SOCKET_READ_LENGTH, data_buf);
    reader->data_len = size & MAX_PROTOCOL_SOCKET_READ_LENGTH;
    return reader;
}