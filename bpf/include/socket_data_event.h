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

// The socket data event of the network profiling. socket_data.h includes it as <socket_data_event.h> before struct
// upload_data_args, so the include path decides which copy is used: the access log object searches
// bpf/accesslog/include first, which has the event of the access log (it adds the details of a call, filled through
// struct upload_data_args_ext, and fill_socket_data_event_ext copies them into the event). The hooks below are the
// ones socket_data.h calls; this event adds nothing. Whatever field name the event of the access log shares with this
// one is set by socket_data.h, payload_skipped included.

struct socket_data_upload_event {
    __u8 protocol;
    __u8 have_reduce_after_chunk;
    __u8 direction;
    __u8 finished;
    __u16 sequence;
    __u16 data_len;
    __u64 start_time;
    __u64 end_time;
    __u64 conid;
    __u64 randomid;
    __u64 data_id;
    __u64 prev_data_id;
    __u64 total_size;
    // 1 when the call is uploaded without its content because it lies wholly inside the payload of an
    // h2c DATA frame (access_log.protocol_analyze.skip_h2c_data_payload): data_len is 0 and total_size
    // is the size of the call, which the user space counts without reading
    __u8 payload_skipped;
    char buffer[MAX_TRANSMIT_SOCKET_READ_LENGTH];
};

// the values of the fields an extension adds to the event, kept per socket call: none here
struct upload_data_args_ext {
};

static __always_inline void fill_socket_data_event_ext(struct socket_data_upload_event *event, struct upload_data_args_ext *ext) {
}

// socket_data_upload_without_content tells whether a socket call whose content is not uploaded (the
// protocol is unknown, or the connection skips the data upload) still sends an event without content,
// for the fields an extension adds: not here
static __always_inline bool socket_data_upload_without_content() {
    return false;
}

// socket_data_event_coalescable tells whether the event can stand for a run of skipped HTTP/1 body calls
// (coalesce_http1_body_payload, syscalls/h1.h): its extension fields have to sum up, and it has to carry
// the data ids of the run. Not here: the details of a call travel in their own event.
static __always_inline bool socket_data_event_coalescable() {
    return false;
}

// upload_data_args_ext_coalesce adds the extension fields of a call to those of a held run whose data ids
// would span data_id_span, or returns false when they cannot stand together (the run is uploaded first)
static __always_inline bool upload_data_args_ext_coalesce(struct upload_data_args_ext *run, struct upload_data_args_ext *call,
                                                          __u64 data_id_span) {
    return false;
}

// fill_socket_data_event_coalesced marks the event of a run of calls with the span of its data ids
static __always_inline void fill_socket_data_event_coalesced(struct socket_data_upload_event *event, __u64 data_id_span) {
}

// upload_data_args_ext_set_sum_before sets the bytes of h2c DATA payload summarised in front of a positional
// upload (summarize_h2c_payload, common/h2c_sum.h): only an event that carries them has the field, not here
static __always_inline void upload_data_args_ext_set_sum_before(struct upload_data_args_ext *ext, __u32 bytes) {
}

// upload_data_args_ext_set_sum_run sets the run of whole DATA frames those bytes are (common/h2c_sum.h): not here
static __always_inline void upload_data_args_ext_set_sum_run(struct upload_data_args_ext *ext, __u64 run) {
}

// upload_data_args_ext_set_h2c_frames sets what the h2c follower knows of the frames of a call: not here
static __always_inline void upload_data_args_ext_set_h2c_frames(struct upload_data_args_ext *ext, __u32 frames) {
}
