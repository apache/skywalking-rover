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

// ------------------------------------------ openssl start -------------------------------------------------------
struct openssl_symaddr {
    // read the BIO offset from ssl
    __u32 bio_read_offset;
    __u32 bio_write_offset;
    // read the fd offset from BIO
    __u32 fd_offset;
    // read the SSL is server side or not
    __u32 server_offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, struct openssl_symaddr);
} openssl_symaddr_map SEC(".maps");
static __inline struct openssl_symaddr* get_openssl_symaddr(__u32 tgid) {
    struct openssl_symaddr *addr = bpf_map_lookup_elem(&openssl_symaddr_map, &tgid);
    return addr;
}
// ------------------------------------------ openssl end -------------------------------------------------------

// ------------------------------------------ go tls start -------------------------------------------------------
struct go_tls_arg_location_t {
    __u32 type;
    __u32 offset;
};

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
static __always_inline __u64* go_regabi_regs(const void* ctx) {
    __u32 zero = 0;
    struct go_regabi_regs_t* regs_heap_var = bpf_map_lookup_elem(&go_regabi_regs_map, &zero);
    if (regs_heap_var == NULL) {
        return NULL;
    }

#if defined(bpf_target_x86)
    const struct pt_regs* real = ctx;
    regs_heap_var->regs[0] = real->rax;
    regs_heap_var->regs[1] = real->rbx;
    regs_heap_var->regs[2] = real->rcx;
    regs_heap_var->regs[3] = real->rdi;
    regs_heap_var->regs[4] = real->rsi;
    regs_heap_var->regs[5] = real->r8;
    regs_heap_var->regs[6] = real->r9;
    regs_heap_var->regs[7] = real->r10;
    regs_heap_var->regs[8] = real->r11;
#else
    const struct user_pt_regs* real = ctx;
    regs_heap_var->regs[0] = real->regs[0];
    regs_heap_var->regs[1] = real->regs[1];
    regs_heap_var->regs[2] = real->regs[2];
    regs_heap_var->regs[3] = real->regs[3];
    regs_heap_var->regs[4] = real->regs[4];
    regs_heap_var->regs[5] = real->regs[5];
    regs_heap_var->regs[6] = real->regs[6];
    regs_heap_var->regs[7] = real->regs[7];
    regs_heap_var->regs[8] = real->regs[8];
#endif

    return regs_heap_var->regs;
}

struct go_tls_args_symaddr_t {
    __u64 fd_sys_offset;
    __u64 tls_conn_offset;
    __u64 gid_offset;
    __u64 tcp_conn_offset;
    __u64 is_client_offset;

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

static __always_inline void assign_go_tls_arg(void* arg, size_t arg_size, struct go_tls_arg_location_t loc, const void* sp,
                                __u64* regs) {
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

struct go_interface {
    int64_t type;
    void* ptr;
};
// ------------------------------------------ go tls end -------------------------------------------------------

// ------------------------------------------ envoy tls start -------------------------------------------------------
struct envoy_tls_args_symaddr_t {
    __u64 is_server_offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, struct envoy_tls_args_symaddr_t);
} envoy_tls_args_symaddr_map SEC(".maps");
static __always_inline struct envoy_tls_args_symaddr_t* get_envoy_tls_args_symaddr(__u32 tgid) {
    struct envoy_tls_args_symaddr_t *addr = bpf_map_lookup_elem(&envoy_tls_args_symaddr_map, &tgid);
    return addr;
}
// ------------------------------------------ envoy tls end -------------------------------------------------------