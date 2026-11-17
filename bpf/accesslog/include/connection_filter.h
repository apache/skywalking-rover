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

// The filtering of the active connections of the access log: a filtered connection uploads no socket data and no
// close event, its state is only dropped on close. The access log includes it as <connection_filter.h> between struct
// socket_connect_event_t and struct active_connection_t. Which connections are filtered is the rule of
// <connection_filter_rule.h> (bpf/include/connection_filter_rule.h filters none; an agent puts its own copy in an
// include directory searched first). The filter state also keeps the ports of the connection, which
// transfer_detail.h puts in every socket data event.

#include <connection_filter_rule.h>

// in place of the last 5 bytes of the active connection: packed and 5 bytes long (common.ActiveConnection mirrors it)
struct connection_filter_state {
    __u8 filtered;
    __u16 local_port;
    __u16 remote_port;
} __attribute__((packed));

// the connect event tells the user space in __pad0 that the connection is filtered
// (pkg/accesslog/collector/connection.go)
static __always_inline bool connection_filter_on_connect(struct socket_connect_event_t *event, struct connection_filter_state *state) {
    bool filtered = connection_filter_rule(event);
    event->__pad0 = filtered ? 1 : 0;
    state->filtered = filtered ? 1 : 0;
    state->local_port = event->local_port;
    state->remote_port = event->remote_port;
    return filtered;
}

static __always_inline bool connection_filtered(struct connection_filter_state *state) {
    return state->filtered != 0;
}
