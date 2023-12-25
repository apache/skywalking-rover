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

#include "symbol_offsets.h"
#include "openssl.h"
#include "node_tls.h"

static __inline void process_openssl_data(struct pt_regs* ctx, __u64 id, __u32 data_direction, struct sock_data_args_t* args, __u32 func_name) {
    int bytes_count = PT_REGS_RC(ctx);
    if (data_direction == SOCK_DATA_DIRECTION_INGRESS) {
        // not reading finish, needs to keep reading
        // NOTE: if the connection is server side role, and receive a unfinished message,
        // the message type and protocol may could not be recognized.
        // because some SSL framework only read one byte on each SSL_read method call,
        // unless we save the buffer data, then process the SSL data.
        size_t excepted_size = args->excepted_size;
        if (bytes_count > 0 && bytes_count >= excepted_size) {
            args->ssl_buffer_force_unfinished = 1;
        }
    }
    process_write_data(ctx, id, args, bytes_count, data_direction, false, func_name, true);
}

static int get_fd_symaddr(__u32 tgid, bool read, void* ssl) {
    struct openssl_symaddr* addr = get_openssl_symaddr(tgid);
    if (addr == NULL) {
        return -1;
    }
    __u32 bio_offset = read ? addr->bio_read_offset : addr->bio_write_offset;
    __u32 fd_offset = addr->fd_offset;

    void *bio = NULL;
    bpf_probe_read(&bio, sizeof(bio), ssl + bio_offset);
    __u32 fd;
    bpf_probe_read(&fd, sizeof(fd), bio + fd_offset);

    return fd;
}

static int get_fd(uint32_t tgid, bool read, void* ssl) {
    int fd = 0;

    fd = get_fd_symaddr(tgid, read, ssl);
    if (fd > 2) {
        return fd;
    }

    fd = get_node_tls_fd(tgid, ssl);
    if (fd > 0) {
        return fd;
    }

    return 0;
}

SEC("uprobe/ssl_write")
int openssl_write(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    __u32 fd = get_fd(tgid, false, ssl);

    char* buf = (char*)PT_REGS_PARM2(ctx);
    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&openssl_sock_data_args, &id, &data_args, 0);

    set_conn_as_ssl(ctx, tgid, fd, SOCKET_OPTS_TYPE_SSL_WRITE);
    return 0;
}

SEC("uretprobe/ssl_write")
int openssl_write_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *args = bpf_map_lookup_elem(&openssl_sock_data_args, &id);
    if (args && args->fd > 0) {
        args->data_id = get_socket_data_id(2, id, args->fd);
        process_openssl_data(ctx, id, SOCK_DATA_DIRECTION_EGRESS, args, SOCKET_OPTS_TYPE_SSL_WRITE);
    }
    bpf_map_delete_elem(&openssl_sock_data_args, &id);
    return 0;
}

SEC("uprobe/ssl_read")
int openssl_read(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    __u32 fd = get_fd(tgid, true, ssl);

    char* buf = (char*)PT_REGS_PARM2(ctx);
    size_t excepted_size = PT_REGS_PARM3(ctx);
    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    data_args.buf = buf;
    data_args.excepted_size = excepted_size;
    data_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&openssl_sock_data_args, &id, &data_args, 0);

    set_conn_as_ssl(ctx, tgid, fd, SOCKET_OPTS_TYPE_SSL_WRITE);
    return 0;
}

SEC("uretprobe/ssl_read")
int openssl_read_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *args = bpf_map_lookup_elem(&openssl_sock_data_args, &id);
    if (args && args->fd > 0) {
        args->data_id = get_socket_data_id(4, id, args->fd);
        process_openssl_data(ctx, id, SOCK_DATA_DIRECTION_INGRESS, args, SOCKET_OPTS_TYPE_SSL_READ);
    }
    bpf_map_delete_elem(&openssl_sock_data_args, &id);
    return 0;
}