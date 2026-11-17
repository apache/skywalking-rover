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

#include "../common/data_args.h"
#include "../common/sock.h"

// tcp_sendmsg notes the socket of a send call whose role is not known yet: the exit reads the role of the socket only
// when the call makes the connection (sock_data_args_t.role_sk)
static __always_inline int tcp_sendmsg_body(struct sock *sk) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = socket_data_args_get(&id);
    if (data_args != NULL) {

        // getting the socket role is client or server: at the exit, only when the call makes the connection
        // (sock_data_args_t.role_sk)
        if (data_args->sk_role == CONNECTION_ROLE_TYPE_UNKNOWN && data_args->role_sk == NULL) {
            data_args->role_sk = sk;
        }
    }
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs* ctx) {
    return tcp_sendmsg_body((void *)PT_REGS_PARM1(ctx));
};

// the fentry twin of the trampoline attach (common/sys_attach.h): tcp_sendmsg(sk, msg, size)
SEC("fentry/tcp_sendmsg")
int fentry_tcp_sendmsg(__u64 *ctx) {
    return tcp_sendmsg_body((struct sock *)ctx[0]);
}
