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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} go_tgid_goid_map SEC(".maps");
static __inline __u64 get_goid(__u64 id) {
    __u64 *val;
    val = bpf_map_lookup_elem(&go_tgid_goid_map, &id);
    return !val ? 0 : *val;
}
static __inline void set_goid(__u64 id, __u64 goid) {
    bpf_map_update_elem(&go_tgid_goid_map, &id, &goid, 0);
}

SEC("uprobe/casgstatus")
int go_casgstatus(struct pt_regs* ctx) {
    const void* sp = (const void*)PT_REGS_SP(ctx);
    __u64* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
       return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    struct go_tls_args_symaddr_t* symaddrs = get_go_tls_args_symaddr(tgid);
    if (symaddrs == NULL) {
       return 0;
    }

    // get runtime.g
    void* gptr = NULL;
    assign_go_tls_arg(&gptr, sizeof(gptr), symaddrs->casg_status_gp_loc, sp, regs);
    if (gptr == NULL) {
        return 0;
    }

    // get goid in runtime.g
    int64_t goid;
    bpf_probe_read(&goid, sizeof(goid), gptr + symaddrs->gid_offset);

    // newval in runtime.g
    __u32 status;
    assign_go_tls_arg(&status, sizeof(status), symaddrs->casg_status_new_val_loc, sp, regs);

    // check the status is running
    if (status == 2) {
        set_goid(id, goid);
    }
    return 0;
}