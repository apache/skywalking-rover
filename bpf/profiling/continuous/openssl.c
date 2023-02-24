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

static __always_inline bool openssl_should_trace(__u64 id, void *ssl) {
    // check the pid is monitoring
    __u32 tgid = (__u32)(id >> 32);
    if (tgid_should_trace(tgid) == false) {
        return false;
    }

    // check the socket if server side
    struct openssl_symaddr* addr = get_openssl_symaddr(tgid);
    if (addr != NULL) {
        int is_server;
        bpf_probe_read(&is_server, sizeof(is_server), ssl + addr->server_offset);
        if (is_server == 1) {
            return true;
        }
        return false;
    }
    struct envoy_tls_args_symaddr_t *envoy_addr = get_envoy_tls_args_symaddr(tgid);
    if (envoy_addr != NULL) {
        __u8 is_server_from_nginx;
        bpf_probe_read(&is_server_from_nginx, sizeof(is_server_from_nginx), ssl + envoy_addr->is_server_offset);
        if (is_server_from_nginx == 1) {
            return true;
        }
        return false;
    }

    // could not check is server or client, just ignore it
    return false;
}

SEC("uprobe/ssl_write")
int openssl_write(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    void* ssl = (void*)PT_REGS_PARM1(ctx);
    if (openssl_should_trace(id, ssl) == false) {
        return 0;
    }
    char* buf = (char*)PT_REGS_PARM2(ctx);

    struct openssl_args args = {};
    args.ssl = ssl;
    args.buf = buf;
    args.timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&openssl_args_map, &id, &args, 0);
    return 0;
}

SEC("uretprobe/ssl_write")
int openssl_write_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct openssl_args *args = bpf_map_lookup_elem(&openssl_args_map, &id);
    int bytes_count = PT_REGS_RC(ctx);
    if (args && bytes_count > 0) {
        process_data(ctx, id, args->ssl, args->buf, bytes_count, args->timestamp);
    }
    bpf_map_delete_elem(&openssl_args_map, &id);
    return 0;
}

SEC("uprobe/ssl_read")
int openssl_read(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    void* ssl = (void*)PT_REGS_PARM1(ctx);
    if (openssl_should_trace(id, ssl) == false) {
        return 0;
    }
    char* buf = (char*)PT_REGS_PARM2(ctx);
    struct openssl_args args = {};
    args.ssl = ssl;
    args.buf = buf;
    bpf_map_update_elem(&openssl_args_map, &id, &args, 0);
    return 0;
}

SEC("uretprobe/ssl_read")
int openssl_read_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct openssl_args *args = bpf_map_lookup_elem(&openssl_args_map, &id);
    int bytes_count = PT_REGS_RC(ctx);
    if (args && bytes_count > 0) {
        process_data(ctx, id, args->ssl, args->buf, bytes_count, bpf_ktime_get_ns());
    }
    bpf_map_delete_elem(&openssl_args_map, &id);
    return 0;
}