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
#include "api.h"
#include "socket.h"
#include "socket_opts.h"

static __always_inline __u8 get_sock_role(__u8 current_role, struct sock* sock) {
    if (current_role != CONNECTION_ROLE_TYPE_UNKNOWN) {
        return current_role;
    }
    // the max_ack_backlog holds the limit for the accept queue
    // if it is a server, it will not be 0
    int max_ack_backlog = 0;
    if (0 != bpf_core_read(&max_ack_backlog, sizeof(max_ack_backlog),
                &sock->sk_max_ack_backlog)) {
    return CONNECTION_ROLE_TYPE_UNKNOWN;
    }

    return max_ack_backlog == 0 ? CONNECTION_ROLE_TYPE_CLIENT : CONNECTION_ROLE_TYPE_SERVER;
}