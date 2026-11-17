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
#include "socket_opts.h"

// drop_h2c_unused_frame is set by the user space before any program is attached
// (access_log.protocol_analyze.drop_h2c_unused_frame) and never changes afterwards. With it on, the socket
// calls of a cleartext HTTP/2 connection that carry only frames the user space reads nothing from are not
// uploaded, see syscalls/h2c.h.
volatile __u32 drop_h2c_unused_frame;
// skip_h2c_data_payload is set the same way (access_log.protocol_analyze.skip_h2c_data_payload). With it on,
// a socket call of a cleartext HTTP/2 connection that lies wholly inside the payload of a DATA frame is
// uploaded as an event without content that only carries its size, see syscalls/h2c.h. It follows the
// frames with the same cursor, so either switch makes the connections followed.
volatile __u32 skip_h2c_data_payload;
// skip_http1_body_payload is set the same way (access_log.protocol_analyze.skip_http1_body_payload_bpf). With
// it on, a socket call of a cleartext HTTP/1 connection that lies wholly inside a Content-Length body is
// uploaded as an event without content that only carries its size, see syscalls/h1.h. The connections are
// followed in the same map (h2c_stream_map), so this switch makes them followed as well.
volatile __u32 skip_http1_body_payload;
// coalesce_http1_body_payload is set with it when the kernel logs of a message are merged
// (access_log.flush.merge_kernel_logs): the consecutive skipped calls of one body are then uploaded as one
// event, see syscalls/h1.h. Only a build whose event can carry such a run coalesces
// (socket_data_event_coalescable in socket_data_event.h).
volatile __u32 coalesce_http1_body_payload;
// boot_time_unix_ns is the boot time of the host in unix nanoseconds as the user space computes it
// (host.BootTime): the coalesced calls never cross a wall clock minute, see syscalls/h1.h
volatile __u64 boot_time_unix_ns;

// h2c_following tells whether the cleartext HTTP/2 or HTTP/1 connections are followed
static __always_inline bool h2c_following() {
    return (drop_h2c_unused_frame | skip_h2c_data_payload | skip_http1_body_payload) != 0;
}

// h2c_direction_t follows the frame boundaries of one direction of a cleartext HTTP/2 connection, so a
// socket call is only ever judged when it starts on a frame boundary (see syscalls/h2c.h). While the
// direction is H2C_HELD it also keeps a socket call of exactly one frame header (9 bytes) that was not
// uploaded because it announced a frame the user space discards unread: a reader that reads the header
// and the payload of a frame separately (Go's x/net framer) turns every such frame into two socket calls.
// The next call of the direction shows whether it is exactly the payload. If it is, both are dropped; if
// not, the header is uploaded as the event its call would have produced, so the user space never sees a
// payload without its header.
// the bytes kept free between the parts of a followed connection (h2c_stream_t) that different CPUs write: two
// fields 64 bytes or more apart never share a cache line, wherever the hash map puts the value
#define H2C_LINE_GAP 64
struct h2c_direction_t {
    // payload bytes of the current frame that are still to come
    __u32 remaining;
    // the length, the type and the flags of the last frame header the cursor met: of the frame whose
    // payload is still to come when remaining is above 0, or of a header that continues in the next call
    // of the direction (head_len above 0), which keeps what it has of them
    __u8 head[5];
    // the bytes of that header already seen, 0 at a frame boundary and inside a payload
    __u8 head_len;
    // H2C_UNKNOWN, H2C_ALIGNED, H2C_HELD or H2C_LOST
    __u8 state;
    __u8 pad0;
    // the held socket call
    __u8 header[9];
    __u8 pad[3];
    __u64 data_id;
    __u64 prev_data_id;
    __u64 start_time;
    __u64 end_time;
    struct upload_data_args_ext ext;
    // summarize_h2c_payload (common/h2c_sum.h). stream is the stream id of the frame whose payload is still
    // to come (remaining above 0), valid when stream_known is set: the walk sets it when it reads the whole
    // header of that frame in the call (h2c_walk_reach), every other way to a payload leaves it unknown, and
    // such a payload is not summarized.
    __u32 stream;
    // the DATA payload bytes summarized since the last positional upload of the direction: the next one
    // carries them (sum_before), so the parser counts them in front of it
    __u32 sum_pending;
    // the minute of the last summarized call (h2c_sum_minute), what the close looks the summaries up by
    __u32 sum_minute;
    __u8 stream_known;
    // the function of the last call of the direction and a generation bumped whenever it changes: a summary
    // only holds calls of one generation, so no call of another function lies between its calls
    __u8 sum_func;
    __u8 sum_gen;
    // the upper 8 bits of sum_open (below)
    __u8 sum_open_hi;
    // a run (h2c_sum_call in syscalls/h2c.h): with sum_run_stream above 0, sum_pending is not payload of one frame
    // but the bytes of sum_run_frames whole DATA frames of that stream, each summarized as the call it came in (the
    // frame count in the lower 15 bits; H2C_SUM_RUN_HEAD when payload of the frame in front comes first, common/
    // h2c_sum.h)
    __u32 sum_run_stream;
    __u16 sum_run_frames;
    // the rest of the payload of the open last frame of the run at the start of the current call (0: no run, or its
    // last frame ended), set by h2c_handle_call before the follower moves the cursor over the call:
    // its lower 16 bits, sum_open_hi the upper 8 (a frame is at most 2^24 - 1 bytes)
    __u16 sum_open;
    // a cache line between the two directions of a connection, see h2c_stream_t
    __u8 line_gap[H2C_LINE_GAP];
};
// no call of the direction has been seen yet: the next one is the first byte of its stream
#define H2C_UNKNOWN 0
// the cursor knows where the next call of the direction starts relative to the frames
#define H2C_ALIGNED 1
// aligned, and the header of the current frame is held
#define H2C_HELD 2
// the cursor cannot tell anymore, the direction is never dropped from again
#define H2C_LOST 3

// h1_direction_t follows the message boundaries of one direction of a cleartext HTTP/1 connection, see
// syscalls/h1.h, and holds the skipped calls of a body that are uploaded as one event (coalesced)
struct h1_direction_t {
    // the first bytes of a message head that came in calls of their own (Go's server reads 1 byte in the
    // background while a keep-alive connection is idle), read in front of the next call of the direction
    __u8 carry[8];
    __u8 carry_len;
    // the skipped calls held for the coalesced event, 0 when none are
    __u8 pending;
    // 0, or H2C_LOST when the direction is not followed anymore. Nothing ever sets it back, so a call that
    // loses the direction while another one of it is still being followed (calls at once) cannot be undone.
    __u8 state;
    // H1_BOUNDARY, H1_BODY, H1_DEFERRED, H1_CHUNK_* or H1_CLOSE
    __u8 phase;
    // the requests whose head this direction sent and the responses whose head it received (counts that
    // wrap): the responses of the other direction answer the requests of this one in order
    __u8 requests;
    __u8 responses;
    // H1_DEFERRED: the response (counted by responses) whose request was not counted yet, and whether bytes
    // of the call came behind its head
    __u8 deferred_index;
    __u8 deferred_rest;
    // a chunked body: the bytes of the line break behind chunk data seen (0 or 1), the parse state of the
    // size line or of a trailer line (H1_LINE_*), the hex digits of the size, the bytes of the line and of
    // the trailers so far. The size is summed up in remaining.
    __u8 crlf;
    __u8 line;
    __u8 digits;
    __u8 line_len;
    __u16 trailers;
    // H1_CLOSE: the last call was too short to stand alone where the analyzer looks for a message start
    __u8 short_call;
    __u8 pad;
    // bit (n % 32) is set when request n of this direction (counted by requests) is a HEAD request,
    // whose response has no body
    __u32 head_requests;
    // the summed size of the held calls
    __u32 total_size;
    // body bytes still to come
    __u64 remaining;
    // the held calls: the data ids of the first and of the last, the previous data id of the first, the
    // start of the first and the end of the last, the fields an extension adds (summed)
    __u64 first_data_id;
    __u64 data_id;
    __u64 prev_data_id;
    __u64 start_time;
    __u64 end_time;
    struct upload_data_args_ext ext;
    // the gap of h2c_direction_t: both arrays of the union have the same stride
    __u8 line_gap[H2C_LINE_GAP];
};
// the state of either is at the same offset with the same H2C_LOST, so a direction is lost the same way
// whatever follows it
_Static_assert(__builtin_offsetof(struct h1_direction_t, state) == __builtin_offsetof(struct h2c_direction_t, state),
               "the state of an HTTP/1 direction is where the state of an HTTP/2 one is");

// the phase of an HTTP/1 direction: at the start of a message head, inside a Content-Length body, or behind
// the head of a response whose body depends on a request not counted yet (remaining is its body if the
// request is not a HEAD), see syscalls/h1.h
#define H1_BOUNDARY 0
#define H1_BODY 1
#define H1_DEFERRED 2
// a chunked body (RFC 9112 7.1): in the data of a chunk (remaining bytes to come), at the line break behind
// it, in a chunk size line, in the trailers
#define H1_CHUNK_DATA 3
#define H1_CHUNK_CRLF 4
#define H1_CHUNK_SIZE 5
#define H1_CHUNK_TRAILERS 6
// a response body delimited by the close of the connection
#define H1_CLOSE 7

// the parse state of a chunk size line or of a trailer line (h1_direction_t.line)
#define H1_LINE_TRAIL 1    // whitespace behind the digits
#define H1_LINE_EXT 2      // in a chunk extension
#define H1_LINE_CR 4       // a CR, the LF must follow
#define H1_LINE_NONEMPTY 8 // a trailer line with more than CRs

// how the directions of a followed connection are followed, decided by the first call followed
#define H2C_STREAM_UNDECIDED 0
#define H2C_STREAM_HTTP2 1
#define H2C_STREAM_HTTP1 2

// The reads and the writes of a connection run on two CPUs at once (a reader and a writer goroutine): the
// receives write dir[0] on every call, the sends dir[1], batching writes batch_cpu / batch_gen from either, and every call
// reads random_id, mode and request_direction. A header that shared its cache line with batch_cpu and the start of
// dir[0] would let the writes of one CPU take the line every call of the other CPU reads away, so the parts are apart
// by H2C_LINE_GAP bytes or more each (the read-mostly header, the batch markers, dir[0], dir[1]): no two of them share a
// line, whatever the alignment of the value in the hash element. The user space only deletes entries.
struct h2c_stream_t {
    // a connection that reuses the fd never takes the state of the one before
    __u64 random_id;
    // H2C_STREAM_*
    __u32 mode;
    // the direction the client connection preface came in (the requests), 0 while not seen: the
    // runs of whole DATA frames are only summarized in the other one (h2c_sum_call in syscalls/h2c.h)
    __u32 request_direction;
    __u8 header_gap[H2C_LINE_GAP];
    // batching (h2c_batch.h): per direction (indexed by the data direction - 1), the CPU and the batch generation
    // of the last record the direction of this connection added, so a full upload of the connection (either
    // direction) flushes the per-CPU buffer only while this connection's own records are still in it, keeping its
    // per-connection data id order. One mark per direction: the reads and the writes of a connection batch on two
    // CPUs at once, and a mark of both would only keep the CPU that marked last. batch_cpu is cpu + 1, so 0 means
    // "no record pending".
    __u32 batch_cpu[2];
    __u32 batch_gen[2];
    __u8 batch_gap[H2C_LINE_GAP];
    // indexed by the data direction - 1
    union {
        struct h2c_direction_t dir[2];
        struct h1_direction_t h1[2];
    };
};
_Static_assert(__builtin_offsetof(struct h2c_stream_t, batch_cpu) - __builtin_offsetof(struct h2c_stream_t, request_direction) >
                   H2C_LINE_GAP && __builtin_offsetof(struct h2c_stream_t, dir) - __builtin_offsetof(struct h2c_stream_t, batch_gen) >
                   H2C_LINE_GAP,
               "the header, the batch marker and the directions of a followed connection lie on cache lines of their own");
// The followed connections: an entry only exists for an active connection traced from its connect or
// accept, and goes with it. A plain hash, not an LRU: an entry must never be evicted while it holds a
// frame header (H2C_HELD), or its payload would be uploaded alone. As large as active_connection_map
// (when full, a new connection is not followed); preallocated, about 5.6MB (512 byte values, the gaps above).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct h2c_stream_t);
} h2c_stream_map SEC(".maps");
// the zeroed value a new entry is written from, too big for the stack of the programs it is inlined in
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct h2c_stream_t);
	__uint(max_entries, 1);
} h2c_stream_init_map SEC(".maps");

// h2c_forget_connection removes the entry of the connection id, if the frames are followed (otherwise there
// is none)
static __always_inline void h2c_forget_connection(__u64 conid) {
    if (h2c_following()) {
        bpf_map_delete_elem(&h2c_stream_map, &conid);
    }
}

// h2c_follow_new_connection starts following a new active connection when the frames are followed
// (h2c_following). The entry of a connection that had the fd before is removed first, and the new one is
// only inserted, never written over an entry a program may be using.
static __always_inline void h2c_follow_new_connection(__u64 conid, __u64 random_id, __u32 func_name) {
    if (!h2c_following()) {
        return;
    }
    bpf_map_delete_elem(&h2c_stream_map, &conid);
    if (func_name != SOCKET_OPTS_TYPE_CONNECT && func_name != SOCKET_OPTS_TYPE_ACCEPT) {
        return;
    }
    __u32 kZero = 0;
    struct h2c_stream_t *stream = bpf_map_lookup_elem(&h2c_stream_init_map, &kZero);
    if (stream != NULL) {
        // only the random id is ever written here: the mode stays undecided, every direction H2C_UNKNOWN
        stream->random_id = random_id;
        bpf_map_update_elem(&h2c_stream_map, &conid, stream, BPF_NOEXIST);
    }
}

// the held runs being uploaded: two calls may upload the same run at once (see h1_may_flush in
// syscalls/h1.h), the one that inserts the run here first does
struct h1_flush_claim_t {
    __u64 conid;
    __u64 random_id;
    __u64 first_data_id;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct h1_flush_claim_t);
	__type(value, __u8);
} h1_flush_claim_map SEC(".maps");

// h1_flush uploads the held calls of an HTTP/1 direction (syscalls/h1.h) as one event without content: the
// fields the event of each of them would carry, summed where they count (the size, the counters an
// extension adds), with the start of the first, the end of the last, the data id of the last and the
// previous data id of the first, and the data ids it stands for (fill_socket_data_event_coalesced). It
// moves socket_data_last_id_map forward to its data id, so the previous data id of the next upload names
// it. The calls are only held while nothing else of the connection uploads, so the event takes their place
// in the order of the uploads. It is a function of its own, also called from the close.
static __noinline int h1_flush(void *ctx, __u64 conid, __u64 random_id, struct h1_direction_t *d, __u32 direction) {
    struct h1_flush_claim_t claim = {};
    claim.conid = conid;
    claim.random_id = random_id;
    claim.first_data_id = d->first_data_id;
    // the value says nothing (the entry is the claim): its byte is read from the key, which saves the stack of
    // the programs this is called from deepest (h1_hold) a slot
    if (bpf_map_update_elem(&h1_flush_claim_map, &claim, &claim, BPF_NOEXIST) != 0) {
        // another call uploads the run
        return 0;
    }
    struct upload_data_args *upload = generate_socket_upload_args();
    struct socket_data_upload_event *event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*event));
    if (upload == NULL || event == NULL) {
        d->pending = 0;
        return 0;
    }
    // the per CPU arguments are reused: every field this upload does not set must read as zero
    __builtin_memset(upload, 0, sizeof(*upload));
    upload->start_time = d->start_time;
    upload->end_time = d->end_time;
    upload->con_id = conid;
    upload->random_id = random_id;
    upload->bytes_count = d->total_size;
    upload->socket_data_id = d->data_id;
    upload->data_direction = direction;
    upload->ext = d->ext;
    fill_socket_data_event(event, upload, CONNECTION_PROTOCOL_HTTP1);
    fill_socket_data_event_coalesced(event, d->data_id - d->first_data_id);
    event->prev_data_id = d->prev_data_id;
    event->sequence = 0;
    event->data_len = 0;
    event->finished = 1;
    event->have_reduce_after_chunk = 0;
    event->payload_skipped = 1;
    rover_submit_buf(ctx, &socket_data_upload_queue, event, __builtin_offsetof(struct socket_data_upload_event, buffer));
    d->pending = 0;

    // only forward, as for a held HTTP/2 frame header (a compare-and-exchange with the exchange chain)
    struct socket_data_last_id_t *latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    socket_data_store_last_forward(&conid, random_id, d->data_id, latest);
    return 1;
}

// h1_reserve_run moves socket_data_last_id_map forward to the last call of a held run that a call cannot
// upload before its own upload (another call of the direction of the run is in flight): the previous data
// id of that upload then names the run, which comes later with the smaller data ids, as it would name the
// last call of the run if the calls were uploaded each
static __noinline int h1_reserve_run(__u64 conid, __u64 random_id, struct h1_direction_t *d) {
    __u64 data_id = d->data_id;
    struct socket_data_last_id_t *latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    socket_data_store_last_forward(&conid, random_id, data_id, latest);
    return 0;
}

// h1_flush_connection uploads what the directions of a closing HTTP/1 connection still hold, before the
// close is notified
static __noinline int h1_flush_connection(void *ctx, __u64 conid, __u64 random_id) {
    if (skip_http1_body_payload == 0) {
        return 0;
    }
    struct h2c_stream_t *stream = bpf_map_lookup_elem(&h2c_stream_map, &conid);
    if (stream == NULL || stream->random_id != random_id || stream->mode != H2C_STREAM_HTTP1) {
        return 0;
    }
    if (stream->h1[0].pending != 0) {
        h1_flush(ctx, conid, random_id, &stream->h1[0], SOCK_DATA_DIRECTION_INGRESS);
    }
    if (stream->h1[1].pending != 0) {
        h1_flush(ctx, conid, random_id, &stream->h1[1], SOCK_DATA_DIRECTION_EGRESS);
    }
    return 0;
}

// the summary fields fit the space the HTTP/1 state of the union leaves, so the followed connection map
// keeps its value size; both arrays of the union have the same stride (h1_handle_call, h2c_fast_lost)
_Static_assert(sizeof(struct h2c_direction_t) <= sizeof(struct h1_direction_t),
               "the HTTP/2 direction state grew past the HTTP/1 one");
