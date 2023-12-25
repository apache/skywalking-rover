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

#include "../common/connection.h"
#include "socket_opts.h"

static __always_inline void set_conn_as_ssl(struct pt_regs* ctx, __u32 tgid, __u32 fd, __u32 func_name) {
    struct active_connection_t* conn = get_or_create_active_conn(ctx, tgid, fd, func_name, CONNECTION_ROLE_TYPE_UNKNOWN);
    if (conn == NULL) {
        return;
    }
    conn->ssl = true;
};
