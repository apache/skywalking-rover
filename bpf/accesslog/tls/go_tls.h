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

struct go_tls_tgid_goid_t {
    __u64 tgid;
    __u64 goid;
};
struct go_tls_connection_args_t {
    void* connection_ptr;
    char* buffer_ptr;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct go_tls_tgid_goid_t);
	__type(value, struct go_tls_connection_args_t);
} go_tls_active_connection_args SEC(".maps");

static __always_inline int get_fd_from_go_tls_conn(struct go_interface conn, struct go_tls_args_symaddr_t* symaddr) {
    // read connection
    bpf_probe_read(&conn, sizeof(conn), conn.ptr + symaddr->tls_conn_offset);

    if (conn.type != symaddr->tcp_conn_offset) {
        return 0;
    }

    void* fd_ptr;
    bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn.ptr);
    __u64 sysfd;
    bpf_probe_read(&sysfd, sizeof(sysfd), fd_ptr + symaddr->fd_sys_offset);
    return sysfd;
}