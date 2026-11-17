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

// SOCKET_DATA_ACCESS_LOG tells the shared socket upload code (bpf/include/socket_data.h) that it is compiled into the
// access log object, with this event: the network profiling objects, which keep their own event
// (bpf/include/socket_data_event.h), do not have the parts that only the access log uses.
#define SOCKET_DATA_ACCESS_LOG 1

// The socket data event of the access log. The access log object searches bpf/accesslog/include before bpf/include,
// so it takes this one instead of the event of the network profiling (bpf/include/socket_data_event.h). The socket
// data and the details of a socket call travel in one event, so the event also carries the L4 counters, the function
// name, the ssl flag and the ports (filled per call by transfer_detail.h), and a socket call whose content is not
// uploaded still sends one without content. pkg/accesslog/events/data.go reads it.

struct socket_data_upload_event {
    __u8 protocol;
    __u8 have_reduce_after_chunk;
    // the L4 packages of the call
    __u8 l4_package_count;
    __u8 finished;
    __u16 sequence;
    __u16 data_len;
    // the socket function of the call (SOCKET_OPTS_TYPE_*)
    __u32 func_name;
    // the connection is TLS
    __u8 ssl;
    // the frames of a followed h2c call (H2C_FRAMES_* in syscalls/h2c.h): bit 0, the follower knew where the frames
    // were at the start of the call; bit 1, no byte of the call belongs to a HEADERS, CONTINUATION or PUSH_PROMISE
    // frame (header or payload). 0 when not known.
    __u8 h2c_frames;
    // the socket calls of the fd in flight when the call returned, itself included, 0 when not known (see
    // socket_data_call_observe in common/data_args.h): with 1, every call of the fd with a smaller data id
    // has already uploaded whatever it uploads
    __u16 in_flight;
    __u64 start_time;
    __u64 end_time;
    __u64 conid;
    __u64 randomid;
    __u64 data_id;
    __u64 prev_data_id;
    __u64 total_size;
    // the size of the L4 packages of the call
    __u64 l4_total_package_size;
    __u8 direction;
    // 1 when the call is uploaded without its content because it lies wholly inside the payload of an
    // h2c DATA frame (access_log.protocol_analyze.skip_h2c_data_payload): data_len is 0 and total_size
    // is the size of the call (also the HTTP/1 body calls of syscalls/h1.h; 2 is the user space mark of an HTTP/1 body
    // call decoded without its bytes); 3 for a call shed under the memory pressure
    // and 4 for a receive made with MSG_PEEK (no bytes, no previous upload), see syscalls/transfer.h
    __u8 payload_skipped;
    // the ports of the connection, which bind TLS data reported by the Java agent to it
    __u16 local_port;
    __u16 remote_port;
    // an event of a run of skipped HTTP/1 body calls (coalesce_http1_body_payload, syscalls/h1.h) stands for
    // the calls with the data ids data_id - data_id_span to data_id; 0 for every other event
    __u16 data_id_span;
    // summarize_h2c_payload (common/h2c_sum.h): the bytes of DATA payload of the direction that BPF summarized
    // since the previous positional upload of the direction, which come in front of this call in the stream
    // of the direction: the parser counts them as skipped payload before it. Only set on the first chunk
    // event of a call (every chunk carries it, the user space reads it from sequence 0); 0 otherwise.
    // With sum_stream above 0 they are not payload of one frame but sum_frames whole DATA frames of the stream
    // sum_stream, headers included (a run, see h2c_sum_call in syscalls/h2c.h).
    __u32 sum_before;
    __u32 sum_stream;
    __u16 sum_frames;
    // with bit 0 of h2c_frames: where the first frame header that starts in the call starts, 0xffff when none
    // does (or it is not known)
    __u16 first_frame_off;
    char buffer[MAX_TRANSMIT_SOCKET_READ_LENGTH];
};

// the values of the fields this event adds, kept per socket call
struct upload_data_args_ext {
    __u64 l4_total_package_size;
    __u16 local_port;
    __u16 remote_port;
    __u8 l4_package_count;
    __u8 func_name;
    __u8 ssl;
    // see h2c_frames of the event
    __u8 h2c_frames;
    __u16 in_flight;
    // (the 2 bytes in front of sum_before, always 0: a batch record sends the extension as it is)
    __u16 pad;
    // see sum_before of the event; at offset 20
    __u32 sum_before;
    // see sum_stream, sum_frames and first_frame_off of the event
    __u32 sum_stream;
    __u16 sum_frames;
    __u16 first_frame_off;
};

// the user space reads both by offset (pkg/accesslog/events/data.go and batch.go)
_Static_assert(__builtin_offsetof(struct socket_data_upload_event, buffer) == 100, "the data of the event is at 100");
_Static_assert(__builtin_offsetof(struct socket_data_upload_event, sum_stream) == 92, "the run of the event is at 92");
_Static_assert(sizeof(struct upload_data_args_ext) == 32 && __builtin_offsetof(struct upload_data_args_ext, pad) == 18 &&
               __builtin_offsetof(struct upload_data_args_ext, sum_before) == 20 &&
               __builtin_offsetof(struct upload_data_args_ext, sum_stream) == 24,
               "the extension of a batch record is 32 bytes, its summarized bytes at 20, its run at 24");

static __always_inline void fill_socket_data_event_ext(struct socket_data_upload_event *event, struct upload_data_args_ext *ext) {
    event->l4_package_count = ext->l4_package_count;
    event->l4_total_package_size = ext->l4_total_package_size;
    event->func_name = ext->func_name;
    event->ssl = ext->ssl;
    event->in_flight = ext->in_flight;
    event->local_port = ext->local_port;
    event->remote_port = ext->remote_port;
    event->sum_before = ext->sum_before;
    event->sum_stream = ext->sum_stream;
    event->sum_frames = ext->sum_frames;
    event->h2c_frames = ext->h2c_frames;
    event->first_frame_off = ext->first_frame_off;
    // the scratch event is shared by every upload of the CPU
    event->data_id_span = 0;
}

// a socket call whose content is not uploaded still sends its details
static __always_inline bool socket_data_upload_without_content() {
    return true;
}

// socket_data_event_coalescable: the event carries the L4 counters and the data id span of a run of
// skipped HTTP/1 body calls (coalesce_http1_body_payload, syscalls/h1.h)
static __always_inline bool socket_data_event_coalescable() {
    return true;
}

// upload_data_args_ext_coalesce sums the L4 counters of a call into those of a held run. The run is one
// kernel log of the call function: what merging the kernel logs of the calls (access_log.flush.merge_kernel_logs,
// which coalescing goes with) makes of them in the user space, see CanMergeDetail in pkg/accesslog/events.
static __always_inline bool upload_data_args_ext_coalesce(struct upload_data_args_ext *run, struct upload_data_args_ext *call,
                                                          __u64 data_id_span) {
    if (run->func_name != call->func_name || (__u32)run->l4_package_count + call->l4_package_count > 0xff ||
        data_id_span > 0xffff) {
        return false;
    }
    run->l4_package_count += call->l4_package_count;
    run->l4_total_package_size += call->l4_total_package_size;
    return true;
}

static __always_inline void fill_socket_data_event_coalesced(struct socket_data_upload_event *event, __u64 data_id_span) {
    event->data_id_span = data_id_span;
}

// upload_data_args_ext_set_sum_before sets the summarized bytes in front of a positional upload
// (summarize_h2c_payload, common/h2c_sum.h)
static __always_inline void upload_data_args_ext_set_sum_before(struct upload_data_args_ext *ext, __u32 bytes) {
    ext->sum_before = bytes;
}

// upload_data_args_ext_set_sum_run sets the run the summarized bytes in front of a positional upload are, from
// what h2c_handle_call reports: the stream in the lower 32 bits, the frames above, 0 when they are payload of
// one frame
static __always_inline void upload_data_args_ext_set_sum_run(struct upload_data_args_ext *ext, __u64 run) {
    ext->sum_stream = (__u32)run;
    ext->sum_frames = (__u16)(run >> 32);
}

// upload_data_args_ext_set_h2c_frames sets what the follower knows of the frames of an h2c call: the flags in the
// low byte (h2c_frames), the offset of the first frame header above (first_frame_off); 0 when nothing is known
static __always_inline void upload_data_args_ext_set_h2c_frames(struct upload_data_args_ext *ext, __u32 frames) {
    ext->h2c_frames = (__u8)frames;
    ext->first_frame_off = (frames & 1) != 0 ? (__u16)(frames >> 8) : 0xffff;
}
