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

#include "socket.h"

#pragma once

#define MAX_SOCKET_BUFFER_READ_LENGTH 4095

// unknown the connection type, not trigger the syscall connect,accept
#define AF_UNKNOWN 0xff

// the socket operation type
#define SOCKET_OPTS_TYPE_CONNECT    1
#define SOCKET_OPTS_TYPE_ACCEPT     2
#define SOCKET_OPTS_TYPE_CLOSE      3
#define SOCKET_OPTS_TYPE_SEND       4
#define SOCKET_OPTS_TYPE_SENDTO     5
#define SOCKET_OPTS_TYPE_SENDMSG    6
#define SOCKET_OPTS_TYPE_SENDMMSG   7
#define SOCKET_OPTS_TYPE_SENDFILE   8
#define SOCKET_OPTS_TYPE_WRITE      9
#define SOCKET_OPTS_TYPE_WRITEV     10
#define SOCKET_OPTS_TYPE_READ       11
#define SOCKET_OPTS_TYPE_READV      12
#define SOCKET_OPTS_TYPE_RECV       13
#define SOCKET_OPTS_TYPE_RECVFROM   14
#define SOCKET_OPTS_TYPE_RECVMSG    15
#define SOCKET_OPTS_TYPE_RECVMMSG   16
#define SOCKET_OPTS_TYPE_RESENT     17
#define SOCKET_OPTS_TYPE_SSL_WRITE  18
#define SOCKET_OPTS_TYPE_SSL_READ   19
#define SOCKET_OPTS_TYPE_GOTLS_WRITE 20
#define SOCKET_OPTS_TYPE_GOTLS_READ  21

// tracepoint enter
struct trace_event_raw_sys_enter {
	long int id;
	long unsigned int args[6];
	char __data[0];
};

// tracepoint exit
struct trace_event_raw_sys_exit {
	long int id;
	long int ret;
	char __data[0];
};

// syscall:connect
struct connect_args_t {
    __u32 fd;
    struct sockaddr* addr;
    struct sock *sock;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} conecting_args SEC(".maps");

// syscall:close
struct sock_close_args_t {
    int fd;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_close_args_t);
} closing_args SEC(".maps");

// syscall:accept
struct accept_args_t {
    __u32 fd;
    struct sockaddr* addr;
    struct socket* socket;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct accept_args_t);
} accepting_args SEC(".maps");

// data direction
#define SOCK_DATA_DIRECTION_INGRESS 1 //receive from
#define SOCK_DATA_DIRECTION_EGRESS 2  //write to

// syscall: data writing or receive
struct sock_data_args_t {
    __u32 fd;
    // current read/write is calls on the sockets.
    __u32 is_sock_event;
    size_t iovlen;
    unsigned int* msg_len;
    __u64 start_nacs;
    // rtt
    __u64 rtt_count;
    __u64 rtt_time;
    // buffer
    char* buf;
    struct iovec *iovec;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} socket_data_args SEC(".maps");

// syscall:sendfile, sendfile64
struct sendfile_args_t {
    __u32 out_fd;
    __u32 in_fd;
    size_t count;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sendfile_args_t);
} sendfile_args SEC(".maps");

struct socket_buffer_reader_t {
    __u32 data_len;
    char buffer[MAX_SOCKET_BUFFER_READ_LENGTH];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_buffer_reader_t);
    __uint(max_entries, 1);
} socket_buffer_reader_map SEC(".maps");
static __inline struct socket_buffer_reader_t* read_socket_data(void *buf, __u32 data_bytes) {
    __u64 size;
    __u32 kZero = 0;
    struct socket_buffer_reader_t* reader = bpf_map_lookup_elem(&socket_buffer_reader_map, &kZero);
    if (reader == NULL) {
        return NULL;
    }
    size = data_bytes;
    if (size > MAX_SOCKET_BUFFER_READ_LENGTH) {
        size = MAX_SOCKET_BUFFER_READ_LENGTH;
    }
    asm volatile("%[size] &= 0xfff;\n" ::[size] "+r"(size) :);
    bpf_probe_read(&reader->buffer, size, buf);
    reader->data_len = size;
    return reader;
}