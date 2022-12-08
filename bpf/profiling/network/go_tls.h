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

struct go_tls_arg_location_t {
    __u32 type;
    __u32 offset;
};

struct go_tls_args_symaddr_t {
    __u64 fd_sys_offset;
    __u64 tls_conn_offset;
    __u64 gid_offset;
    __u64 tcp_conn_offset;

    // casg
    struct go_tls_arg_location_t casg_status_gp_loc;
    struct go_tls_arg_location_t casg_status_new_val_loc;

    // read
    struct go_tls_arg_location_t read_connection_loc;
    struct go_tls_arg_location_t read_buffer_loc;
    struct go_tls_arg_location_t read_ret0_loc;
    struct go_tls_arg_location_t read_ret1_loc;

    // write
    struct go_tls_arg_location_t write_connection_loc;
    struct go_tls_arg_location_t write_buffer_loc;
    struct go_tls_arg_location_t write_ret0_loc;
    struct go_tls_arg_location_t write_ret1_loc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, struct go_tls_args_symaddr_t);
} go_tls_args_symaddr_map SEC(".maps");
static __always_inline struct go_tls_args_symaddr_t* get_go_tls_args_symaddr(__u32 tgid) {
    struct go_tls_args_symaddr_t *addr = bpf_map_lookup_elem(&go_tls_args_symaddr_map, &tgid);
    return addr;
}

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


struct go_regabi_regs_t {
    __u64 regs[9];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct go_regabi_regs_t);
    __uint(max_entries, 1);
} go_regabi_regs_map SEC(".maps");
// Copies the registers of the golang ABI, so that they can be
// easily accessed using an offset.
static __always_inline uint64_t* go_regabi_regs(const struct pt_regs* ctx) {
    __u32 zero = 0;
    struct go_regabi_regs_t* regs_heap_var = bpf_map_lookup_elem(&go_regabi_regs_map, &zero);
    if (regs_heap_var == NULL) {
        return NULL;
    }

    regs_heap_var->regs[0] = ctx->rax;
    regs_heap_var->regs[1] = ctx->rbx;
    regs_heap_var->regs[2] = ctx->rcx;
    regs_heap_var->regs[3] = ctx->rdi;
    regs_heap_var->regs[4] = ctx->rsi;
    regs_heap_var->regs[5] = ctx->r8;
    regs_heap_var->regs[6] = ctx->r9;
    regs_heap_var->regs[7] = ctx->r10;
    regs_heap_var->regs[8] = ctx->r11;

    return regs_heap_var->regs;
}

struct go_interface {
    int64_t type;
    void* ptr;
};

static __always_inline void assign_go_tls_arg(void* arg, size_t arg_size, struct go_tls_arg_location_t loc, const void* sp,
                                uint64_t* regs) {
    // stack type
    if (loc.type == 1) {
        bpf_probe_read(arg, arg_size, sp + loc.offset);
    } else if (loc.type == 2) {
        // register type
        if (loc.offset >= 0 && loc.offset <= 30) {
            bpf_probe_read(arg, arg_size, (char*)regs + loc.offset);
        }
    }
}

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} go_tgid_goid_map SEC(".maps");
static __inline __u64 get_goid(__u64 tgid) {
    __u64 *val;
    val = bpf_map_lookup_elem(&go_tgid_goid_map, &tgid);
    return !val ? 0 : *val;
}
static __inline void set_goid(__u64 tgid, __u64 goid) {
    bpf_map_update_elem(&go_tgid_goid_map, &tgid, &goid, 0);
}