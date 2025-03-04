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

#include "tls.h"
#include "go_tls.h"
#include "goid.h"

SEC("uprobe/go_tls_write")
int go_tls_write(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    __u64 goid = get_goid(id);
    if (goid == 0) {
        return 0;
    }

    struct go_tls_args_symaddr_t* symaddrs = get_go_tls_args_symaddr(tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp = (const void*)PT_REGS_SP(ctx);
    __u64* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    struct go_tls_tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;
    tgid_goid.goid = goid;

    struct go_tls_connection_args_t data_args = {};
    assign_go_tls_arg(&data_args.connection_ptr, sizeof(data_args.connection_ptr), symaddrs->write_connection_loc, sp, regs);
    assign_go_tls_arg(&data_args.buffer_ptr, sizeof(data_args.buffer_ptr), symaddrs->write_buffer_loc, sp, regs);

    struct go_interface conn_intf = {};
    conn_intf.type = 1;
    conn_intf.ptr = data_args.connection_ptr;
    int fd = get_fd_from_go_tls_conn(conn_intf, symaddrs);
    set_conn_as_ssl(ctx, tgid, fd, SOCKET_OPTS_TYPE_GOTLS_WRITE);
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.fd = fd;
    bpf_map_update_elem(&go_tls_active_connection_args, &tgid_goid, &data_args, 0);
    return 0;
}

SEC("uretprobe/go_tls_write")
int go_tls_write_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    __u64 goid = get_goid(id);
    if (goid == 0) {
        return 0;
    }

    struct go_tls_args_symaddr_t* symaddrs = get_go_tls_args_symaddr(tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp = (const void*)PT_REGS_SP(ctx);
    __u64* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    int64_t retval0 = 0;
    assign_go_tls_arg(&retval0, sizeof(retval0), symaddrs->write_ret0_loc, sp, regs);
    struct go_interface retval1 = {};
    assign_go_tls_arg(&retval1, sizeof(retval1), symaddrs->write_ret1_loc, sp, regs);
    if (retval1.ptr != 0) {
        return 0;
    }

    struct go_tls_tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;
    tgid_goid.goid = goid;

    struct go_tls_connection_args_t *args = bpf_map_lookup_elem(&go_tls_active_connection_args, &tgid_goid);
    if (args) {
        struct sock_data_args_t data_args = {};
        data_args.fd = args->fd;
        data_args.buf = args->buffer_ptr;
        data_args.start_nacs = args->start_nacs;
        data_args.data_id = get_socket_data_id(6, id, args->fd);

        process_write_data(ctx, id, &data_args, retval0, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_GOTLS_WRITE, true);
    }
    bpf_map_delete_elem(&go_tls_active_connection_args, &tgid_goid);
    return 0;
}


SEC("uprobe/go_tls_read")
int go_tls_read(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    __u64 goid = get_goid(id);
    if (goid == 0) {
        return 0;
    }

    struct go_tls_args_symaddr_t* symaddrs = get_go_tls_args_symaddr(tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp = (const void*)PT_REGS_SP(ctx);
    __u64* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    struct go_tls_tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;
    tgid_goid.goid = goid;

    struct go_tls_connection_args_t data_args = {};
    assign_go_tls_arg(&data_args.connection_ptr, sizeof(data_args.connection_ptr), symaddrs->read_connection_loc, sp, regs);
    assign_go_tls_arg(&data_args.buffer_ptr, sizeof(data_args.buffer_ptr), symaddrs->read_buffer_loc, sp, regs);
    struct go_interface conn_intf = {};
    conn_intf.type = 1;
    conn_intf.ptr = data_args.connection_ptr;
    int fd = get_fd_from_go_tls_conn(conn_intf, symaddrs);
    set_conn_as_ssl(ctx, tgid, fd, SOCKET_OPTS_TYPE_GOTLS_READ);

    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.fd = fd;
    bpf_map_update_elem(&go_tls_active_connection_args, &tgid_goid, &data_args, 0);
    return 0;
}

SEC("uretprobe/go_tls_read")
int go_tls_read_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    __u64 goid = get_goid(id);
    if (goid == 0) {
        return 0;
    }

    struct go_tls_args_symaddr_t* symaddrs = get_go_tls_args_symaddr(tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp = (const void*)PT_REGS_SP(ctx);
    __u64* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    int64_t retval0 = 0;
    assign_go_tls_arg(&retval0, sizeof(retval0), symaddrs->read_ret0_loc, sp, regs);
    struct go_interface retval1 = {};
    assign_go_tls_arg(&retval1, sizeof(retval1), symaddrs->read_ret1_loc, sp, regs);
    if (retval1.ptr != 0) {
        return 0;
    }

    struct go_tls_tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;
    tgid_goid.goid = goid;

    struct go_tls_connection_args_t *args = bpf_map_lookup_elem(&go_tls_active_connection_args, &tgid_goid);
    if (args) {
        struct sock_data_args_t data_args = {};
        data_args.fd = args->fd;
        data_args.buf = args->buffer_ptr;
        data_args.start_nacs = args->start_nacs;
        data_args.data_id = get_socket_data_id(8, id, args->fd);

        process_write_data(ctx, id, &data_args, retval0, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_GOTLS_WRITE, true);
    }
    bpf_map_delete_elem(&go_tls_active_connection_args, &tgid_goid);
    return 0;
}