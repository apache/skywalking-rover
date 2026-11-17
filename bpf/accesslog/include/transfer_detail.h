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

// How the details of a socket call reach the user space: they travel in the socket data event of the access log
// (socket_data_event.h), and no detail event is sent.

static __always_inline void fill_upload_data_args_ext(struct upload_data_args_ext *ext, struct active_connection_t *conn,
                                                      struct sock_data_args_t *args, __u8 func_name) {
    ext->l4_package_count = args->package_count;
    ext->l4_total_package_size = args->total_package_size;
    ext->func_name = func_name;
    ext->ssl = conn->ssl;
    ext->local_port = conn->filter.local_port;
    ext->remote_port = conn->filter.remote_port;
    ext->in_flight = args->in_flight;
    ext->pad = 0;
    // only a positional h2c upload carries summarised bytes, set after this (upload_data_args_ext_set_sum_before)
    ext->sum_before = 0;
    ext->sum_stream = 0;
    ext->sum_frames = 0;
    // nothing known of the frames of the call until the h2c follower says (upload_data_args_ext_set_h2c_frames)
    ext->h2c_frames = 0;
    ext->first_frame_off = 0xffff;
}
