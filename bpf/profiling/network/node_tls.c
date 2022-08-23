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

#include "node_tls.h"

SEC("uprobe/node_tls_wrap")
int node_tls_wrap(struct pt_regs* ctx) {
    void* tls_wrap = (void*)PT_REGS_PARM1(ctx);
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&node_tls_wrap_construct_args_map, &id, &tls_wrap, 0);
    return 0;
}

SEC("uretprobe/node_tls_wrap")
int node_tls_wrap_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&node_tls_wrap_construct_args_map, &id);
    return 0;
}

SEC("uretprobe/ssl_new")
int node_tls_ret_ssl(struct pt_regs* ctx) {
    // get ssl data
    void* ssl = (void*)PT_REGS_RC(ctx);
    if (ssl == NULL) {
        return 0;
    }
    // get node tls_wrap
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_wrap **wrap = bpf_map_lookup_elem(&node_tls_wrap_construct_args_map, &id);
    if (wrap == NULL) {
        return 0;
    }
    bpf_map_update_elem(&node_tls_ssl_wrap_mapping, &ssl, wrap, 0);
    return 0;
}