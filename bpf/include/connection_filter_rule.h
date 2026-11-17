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

// The rule of the connection filter of the access log (accesslog/include/connection_filter.h): whether a connection
// is filtered, decided from its connect event when its active connection is created. The access log includes it as
// <connection_filter_rule.h>: an agent that filters connections passes an include directory with its own copy,
// searched first (BPF_ACCESSLOG_CFLAGS, pkg/accesslog/bpf/loader.go). This copy filters none.
static __always_inline bool connection_filter_rule(struct socket_connect_event_t *event) {
    return false;
}
