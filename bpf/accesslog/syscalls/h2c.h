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
#include "socket_data.h"
#include "protocol_analyzer.h"
#include "../common/connection.h"
#include "../common/data_args.h"
#include "../common/h2c_state.h"
#include "../common/h2c_batch.h"
#include "../common/h2c_sum.h"

// Unused HTTP/2 frames on a cleartext connection (access_log.protocol_analyze.drop_h2c_unused_frame)
//
// The user space HTTP/2 parser reads nothing from WINDOW_UPDATE, PING, PRIORITY and SETTINGS ACK frames:
// it skips their payload, keeps no flow control state and does not report the socket calls that carry
// only such frames, because no stream slice ever covers them. Yet they are most of the socket calls
// of an HTTP/2 connection that receives a large body: the receiver returns flow control credit for
// every few KB it reads, and a reader that reads the header and the payload of a frame separately
// (Go's x/net framer) makes each of them two socket calls. Every upload costs the user space the same
// per event work whatever it carries, so with drop_h2c_unused_frame on these calls are not uploaded,
// which is where it is cheapest. A dropped call sends no event at all: the details of a call travel in its socket
// data event (transfer_detail.h), there is no separate detail event.
//
// Whether the bytes of a call parse as control frames says nothing unless the call starts on a frame
// boundary: the payload of a DATA, HEADERS or CONTINUATION frame often arrives in a call of its own,
// and its bytes are chosen by the peer. So every direction keeps a cursor (h2c_direction_t) that
// follows the frame boundaries through every call of the connection, and a call is only judged when
// the cursor knows that it starts on one. The cursor starts at the first byte of the stream, so it is
// only kept for a connection traced from its connect or accept (h2c_stream_map), from the first call of
// the direction; it walks the frame headers of a call within a fixed bound (H2C_WALK_MAX_FRAMES, far above
// what a buffered reader or writer puts into one call). Whenever it cannot tell where the frames are (an
// unknown frame type, more frames in a call than the walk covers, bytes it cannot read, a call it cannot
// follow) the direction is lost for good: it is never dropped from again.
// A missed drop costs a little CPU, a wrong one corrupts the access log, so there is no
// resynchronization.
//
// At a frame boundary a call is dropped when it consists of complete unused frames that fill
// it exactly, or when it is a lone 9 byte header of such a frame and the next call of the direction is
// exactly its payload (H2C_HELD). Removing whole frames keeps the stream of each direction frame
// aligned, and the previous data id of the next upload still names the last uploaded call, because
// socket_data_last_id_map is only written when a call is uploaded.
//
// DATA payloads (access_log.protocol_analyze.skip_h2c_data_payload)
//
// The user space reads nothing from the payload of a DATA frame either: it only counts its bytes into the
// size of the body. A receiver that reads the header and the payload of a frame separately reads every
// payload in calls that lie wholly inside it, and those carry nearly all the bytes of a large body. With
// skip_h2c_data_payload on, such a call is uploaded as one event without content that carries its size
// (total_size, data_len 0) and the payload_skipped mark, and the user space counts it without reading
// it. Unlike a dropped call the event is still sent: the call stays a socket call of the message, with
// its own times and counters, and it moves socket_data_last_id_map exactly like an upload, so the
// previous data id of the next upload names it. The cursor decides it: a call is skipped only when the
// direction is aligned, no frame header is cut by its start, the rest of the current payload covers the
// call, and the frame whose payload it is is a DATA frame without the PADDED flag (the user space reads
// the pad length). Every other call is uploaded as before, in whole: a call that holds any byte of a frame
// header, or of a HEADERS, CONTINUATION or SETTINGS payload, is read by the user space, and a wrong skip
// would desynchronize its HPACK decoder, while a missed skip costs a little CPU. The switch makes the
// connections followed by itself (h2c_following), with or without drop_h2c_unused_frame.
//
// A call that holds frame headers can still end inside a DATA payload: a writer that writes a frame with
// its header in one call (Go's framer, whenever its buffer is empty), or a buffered reader that fills its
// buffer with the next frame header and the start of its payload. Such a call is uploaded up to the first
// byte of that payload and marked as cut there (have_reduce_after_chunk on its last chunk, total_size the
// size of the call): the event of a call the upload limit truncated, which the user space parser already
// steps over inside a DATA payload (buffer.Buffer.SetFollowTruncation goes with skip_h2c_data_payload).
// The same rules decide it: a DATA frame without the PADDED flag whose header lies in the call, on a
// connection known as HTTP/2 before the call, and the payload runs to the end of the call or beyond.

#define H2C_FRAME_HEADER_LEN HTTP2_FRAME_HEADER_LEN
// the bytes of a call to upload when its end lies in a DATA payload, from what h2c_handle_call reports
// (*upload_size): it has the summarized bytes in front of the call in its upper half
#define H2C_UPLOAD_CUT(v) ((v) & 0xffffffff)
// the largest unused frame is a PING, 9 + 8 bytes; a buffered writer flushes a few of them at once
#define H2C_CONTROL_FRAMES_MAX_PER_CALL 4
#define H2C_CONTROL_FRAMES_MAX_CALL_SIZE (H2C_CONTROL_FRAMES_MAX_PER_CALL * 17)
// the frame headers the cursor walks in one call. Go's server and client put 33 to 44 frames into one
// call (the queued WINDOW_UPDATE frames flushed with the next HEADERS and DATA header), and a buffered
// reader of 4KB holds at most 455 frames (9 bytes each). A call with more frames loses the direction for
// good, which costs every drop and skip that would follow, but nothing is lost: the data is still uploaded
// and parsed. The walk is a loop that is not unrolled, in a function of its own that is verified once
// per program (h2c_cursor_walk): each header adds a few dozen processed instructions.
#define H2C_WALK_MAX_FRAMES 1024
// the user space parser does not know frame types above CONTINUATION either
#define H2C_MAX_FRAME_TYPE HTTP2_FRAME_TYPE_MAX
// the client connection preface (RFC 7540 3.5), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", as three little
// endian words
#define H2C_PREFACE_0 0x5448202a20495250ULL
#define H2C_PREFACE_1 0x0a0d302e322f5054ULL
#define H2C_PREFACE_2 0x0a0d0a0d4d530a0dULL

// what the follower knows of the frames of a call it uploads (the h2c_frames of the event): bit 0, where
// the frames are at the start of the call (and first_frame_off is where the first frame header that starts in it
// starts); bit 1, no byte of the call belongs to a frame that carries a header block (HEADERS, CONTINUATION,
// PUSH_PROMISE): no header of one, no payload of one, no rest of one from the call before; bit 2, the bytes in front
// of the first frame header that starts in the call (all of them when none does) belong to a frame that carries a
// header block (the rest of one from the call before, or may: its header cut before its type). The user space judges
// by them whether a call it has to drop may hold bytes its HPACK decoder needed.
// Behind the first frame header the follower does not tell the frames apart (a test per frame in the walk of the
// frame headers costs the verifier about 80K instructions on 6.12, see h2c_walk_frames): with bit 0 the user space
// walks the uploaded bytes of the call from first_frame_off itself (every byte up to where the upload cuts the call
// is uploaded, and what is cut is DATA payload). So bit 1 is set only for a call without a frame header (a call
// inside a payload, the rest of a frame that carries no header block) and for one header of a frame the user space
// discards, and then it is exact.
#define H2C_FRAMES_KNOWN 1
#define H2C_FRAMES_NO_HEADER_BLOCK 2
#define H2C_FRAMES_STARTS_IN_HEADER_BLOCK 4

// what h2c_follow_frames decides for a socket call
#define H2C_CALL_UPLOAD 0
#define H2C_CALL_DROP 1
#define H2C_CALL_SKIP_PAYLOAD 2
// uploaded, once h2c_cursor_walk moved the cursor over it (h2c_walk_t)
#define H2C_CALL_WALK 3

struct h2c_control_frame_buffer_t {
    // a call is at most 68 bytes; the rest is room for the verifier, which only knows that an offset
    // into it is below 128 (see h2c_judge_call) and that a frame header behind it is 9 bytes long
    __u8 data[128 + H2C_FRAME_HEADER_LEN];
    // the call whose bytes data holds when the h2c fast path read them and judged them as no call
    // of unused frames (h2c_judge_call -1) before it left the call to the generic path: h2c_follow_frames takes them
    // from here instead of reading and judging them again. tag_size is 0 when data holds no such call.
    __u64 tag_conid;
    __u64 tag_random_id;
    __u64 tag_data_id;
    __u64 tag_size;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct h2c_control_frame_buffer_t);
    __uint(max_entries, 1);
} h2c_control_frame_buffer_map SEC(".maps");

// h2c_control_frame_payload_len returns the payload length of a frame header the user space discards
// unread, or -1 for every other header. Each rule is what RFC 7540 requires of that frame type, and the
// length must be the exact one of the type: a header that is only plausible is never enough. It is a
// function of its own: inlined, the branches of every rule multiply with those of the next frame.
static __noinline int h2c_control_frame_payload_len(const __u8 *h) {
    // the length and the type, and the stream id with the reserved bit (4.1), as whole words: a few
    // comparisons of them keep the paths through this function few
    __u32 length_type = ((__u32)h[0] << 24) | ((__u32)h[1] << 16) | ((__u32)h[2] << 8) | h[3];
    __u32 stream = ((__u32)h[5] << 24) | ((__u32)h[6] << 16) | ((__u32)h[7] << 8) | h[8];
    __u8 flags = h[4];
    // the reserved bit must be unset when sending (4.1)
    if (stream > 0x7fffffff) {
        return -1;
    }
    // WINDOW_UPDATE (6.9): defines no flags, a 4 byte window size increment, any stream
    if (length_type == ((4 << 8) | HTTP2_FRAME_TYPE_WINDOW_UPDATE) && flags == 0) {
        return 4;
    }
    // PING (6.7): only the ACK flag, 8 bytes of opaque data, connection level only
    if (length_type == ((8 << 8) | HTTP2_FRAME_TYPE_PING) && (flags & ~HTTP2_FLAG_ACK & 0xff) == 0 && stream == 0) {
        return 8;
    }
    // PRIORITY (6.3): defines no flags, 5 bytes, never on stream 0
    if (length_type == ((5 << 8) | HTTP2_FRAME_TYPE_PRIORITY) && flags == 0 && stream != 0) {
        return 5;
    }
    // SETTINGS (6.5) only as the ACK, which must be empty and on stream 0. A SETTINGS frame that carries
    // settings is read by the user space (header table size, max frame size) and is never dropped.
    if (length_type == HTTP2_FRAME_TYPE_SETTINGS && flags == HTTP2_FLAG_ACK && stream == 0) {
        return 0;
    }
    return -1;
}

// h2c_upload_held_header uploads the held header of a direction as the event its socket call would have
// produced when it was made. The previous data id is the one of that time, so the user space never
// waits for a call it already parsed; socket_data_last_id_map only moves forward, the other direction
// may have uploaded a later call while the header was held.
static __always_inline void h2c_upload_held_header(void *ctx, struct active_connection_t *conn, __u64 conid,
                                                   __u32 data_direction, struct h2c_stream_t *stream, struct h2c_direction_t *held) {
    // a full event of this connection: its pending batch records go out first, so its data id order is kept
    if (h2c_batching()) {
        h2c_batch_flush_for(ctx, stream);
    }
    struct upload_data_args *args = generate_socket_upload_args();
    struct socket_data_upload_event *event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*event));
    if (args == NULL || event == NULL) {
        return;
    }
    // the per CPU arguments are reused: every field this upload does not set must read as zero
    __builtin_memset(args, 0, sizeof(*args));
    args->start_time = held->start_time;
    args->end_time = held->end_time;
    args->con_id = conid;
    args->random_id = conn->random_id;
    args->bytes_count = sizeof(held->header);
    args->socket_data_id = held->data_id;
    args->data_direction = data_direction;
    args->ext = held->ext;
    // the first positional upload of the direction since the summarized calls carries their bytes (only ever
    // above 0 with the summaries on)
    upload_data_args_ext_set_sum_before(&args->ext, held->sum_pending);
    upload_data_args_ext_set_sum_run(&args->ext, held->sum_run_stream | ((__u64)held->sum_run_frames << 32));
    // one header of a control frame the user space discards, on a frame boundary
    upload_data_args_ext_set_h2c_frames(&args->ext, H2C_FRAMES_KNOWN | H2C_FRAMES_NO_HEADER_BLOCK);
    held->sum_pending = 0;
    held->sum_run_stream = 0;
    held->sum_run_frames = 0;
    fill_socket_data_event(event, args, CONNECTION_PROTOCOL_HTTP2);
    event->prev_data_id = held->prev_data_id;
    event->sequence = 0;
    event->data_len = sizeof(held->header);
    event->finished = 1;
    event->have_reduce_after_chunk = 0;
    __builtin_memcpy(event->buffer, held->header, sizeof(held->header));
    rover_submit_buf(ctx, &socket_data_upload_queue, event,
                     __builtin_offsetof(struct socket_data_upload_event, buffer) + sizeof(held->header));

    // only forward: unlike in upload_socket_data, which uploads the newest call, the other direction may
    // have uploaded a later call while the header was held, and that one must stay the last
    struct socket_data_last_id_t *latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    socket_data_store_last_forward(&conid, conn->random_id, held->data_id, latest);
}

// h2c_lose stops following a direction; the entry goes when no direction is followed anymore
static __always_inline void h2c_lose(struct h2c_stream_t *stream, struct h2c_direction_t *c, __u64 conid) {
    c->state = H2C_LOST;
    if (stream->dir[0].state == H2C_LOST && stream->dir[1].state == H2C_LOST) {
        bpf_map_delete_elem(&h2c_stream_map, &conid);
    }
}

// h2c_judge_call judges a socket call that starts on a frame boundary, whose size bytes are in data: 0
// when it consists of complete unused frames that fill it exactly, the payload length (above 0)
// when it is a lone header of an unused frame that announces a payload, -1 otherwise. It is a
// function of its own so its paths, one per combination of frame types, end in these few results.
static __noinline int h2c_judge_call(const __u8 *data, __u64 size) {
    int len = h2c_control_frame_payload_len(data);
    if (len < 0) {
        return -1;
    }
    if (size == H2C_FRAME_HEADER_LEN) {
        return len;
    }
    // the offset is masked after every frame: the mask never changes it (it stays below 128), but the
    // verifier then sees one range instead of a constant per combination of frame types
    __u64 offset = H2C_FRAME_HEADER_LEN + len;
    asm volatile("%[v] &= 0x7f;\n" : [v] "+r"(offset));
#pragma unroll
    for (int i = 1; i < H2C_CONTROL_FRAMES_MAX_PER_CALL; i++) {
        if (offset == size) {
            return 0;
        }
        if (offset > H2C_CONTROL_FRAMES_MAX_CALL_SIZE - H2C_FRAME_HEADER_LEN || offset + H2C_FRAME_HEADER_LEN > size) {
            return -1;
        }
        int next = h2c_control_frame_payload_len(&data[offset]);
        if (next < 0) {
            return -1;
        }
        offset += H2C_FRAME_HEADER_LEN + next;
        asm volatile("%[v] &= 0x7f;\n" : [v] "+r"(offset));
    }
    return offset == size ? 0 : -1;
}

// h2c_walk_t is the rest of a socket call that h2c_cursor_walk moves the cursor over, kept per CPU between
// h2c_follow_frames, which sets it up, and the walk
struct h2c_walk_t {
    // readable bytes of the call can be read from src, the call is size bytes, the walk starts at pos
    __u64 src;
    __u64 readable;
    __u64 size;
    __u64 pos;
    // set by the walk: the bytes of the call to upload when its end lies in a DATA payload that may be
    // skipped (tail_skip), 0 to upload it in whole
    __u64 upload;
    // the end of the call may be skipped: skip_h2c_data_payload is on and the connection was known as
    // HTTP/2 before the call
    __u64 tail_skip;
    // summarize_h2c_payload (common/h2c_sum.h), read after the walk by h2c_sum_walked: sum_tail is
    // (1 << 32) | stream when the payload of a DATA frame with END_STREAM whose header came in an earlier call
    // ends in this call; reach_pos is where the payload the call ends in starts when the walk ended there
    // (h2c_walk_reach), 0 otherwise: the stream id of that frame is the 4 bytes in front of it when its header
    // is in the call. Nothing is done about the frames inside the loop of h2c_walk_frames, nor right behind
    // it: whatever the loop does is verified once per iteration, whatever follows it once per exit.
    __u64 sum_tail;
    __u64 reach_pos;
    // H2C_FRAMES_*: 1 when the bytes of the call in front of its first frame header (all of them when none starts in
    // it) belong to a frame that carries a header block; and where the first frame header that starts in the call
    // starts (0xffff: none)
    __u64 frames_hdr;
    __u64 frames_first;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct h2c_walk_t);
    __uint(max_entries, 1);
} h2c_walk_map SEC(".maps");

// h2c_header_block_type is 1 when a frame of the type carries a header block (HEADERS, PUSH_PROMISE, CONTINUATION),
// without a branch
static __always_inline __u64 h2c_header_block_type(__u8 type) {
    __u64 t = type;
    return h2c_z(t ^ HTTP2_FRAME_TYPE_HEADERS) | h2c_z(t ^ 5) | h2c_z(t ^ HTTP2_FRAME_TYPE_CONTINUATION);
}

// the results of the walk loop
#define H2C_WALK_LOST 0
#define H2C_WALK_BOUNDARY 1
#define H2C_WALK_CUT 2
#define H2C_WALK_REACH 3

// h2c_walk_reach ends a walk at a frame whose payload starts at pos and runs to the end of the call or
// beyond, with length bytes from there: the rest of it comes in the next calls, and the end of the call is
// skipped (w->upload) when it may be, see the comment on the top
static __always_inline int h2c_walk_reach(struct h2c_direction_t *c, struct h2c_walk_t *w, __u64 pos, __u64 length) {
    __u64 size = w->size;
    __u64 rest = size - pos;
    c->remaining = length - rest;
    c->head_len = 0;
    // the stream id of the frame is read by h2c_sum_walked (common/h2c_sum.h)
    w->reach_pos = pos;
    if (w->tail_skip != 0 && pos > 0 && rest > 0 && pos <= w->readable && c->head[3] == HTTP2_FRAME_TYPE_DATA &&
        (c->head[4] & HTTP2_FLAG_PADDED) == 0) {
        w->upload = pos;
    }
    return 0;
}

// h2c_walk_frames walks the frame headers of the call from w->pos, the first byte of a frame, see
// h2c_cursor_walk. It only takes the cursor and the walk, both in maps, and is only called as the last thing
// h2c_cursor_walk does: whichever way the walk got to its first frame, the verifier sees the same state
// when it enters this function, walks the loop once, and the loop counter is the only value that tells
// its iterations apart, so the exits of each kind merge behind it. It returns 1 when the cursor is lost.
static __noinline int h2c_walk_frames(struct h2c_direction_t *c, struct h2c_walk_t *w) {
    char *src = (char *)w->src;
    __u64 readable = w->readable;
    __u64 size = w->size;
    __u64 pos = w->pos;
    __u64 length = 0;
    __u32 result = H2C_WALK_LOST;
    // the first frame header that starts in the call starts here, unless an earlier one did (without a branch: the
    // loop below is walked once)
    __u64 first = w->frames_first;
    __u64 here = pos | (0xffff & (0 - (h2c_lt(pos, size) ^ 1)));
    __u64 earlier = h2c_lt(first, here);
    w->frames_first = here ^ ((first ^ here) & (0 - earlier));
    // Every exit of the loop is a state the verifier keeps until it has walked the loop to its end, for every
    // iteration: the loop has three, the tests of one exit are folded into one value without branches.
#pragma clang loop unroll(disable)
    for (int i = 0; i < H2C_WALK_MAX_FRAMES; i++) {
        // pos never passes size: the call ends on the boundary, or with a header it cuts (told apart behind
        // the loop)
        if (size - pos < H2C_FRAME_HEADER_LEN) {
            result = H2C_WALK_CUT;
            break;
        }
        // a whole header is in the call: its first 5 bytes are read, which must be readable, and the type must
        // be known. A read behind the readable bytes is harmless, its result is not used.
        long err = bpf_probe_read(c->head, sizeof(c->head), src + pos);
        __u64 bad = h2c_nz((__u64)err) | h2c_lt(readable, pos + sizeof(c->head)) | h2c_lt(H2C_MAX_FRAME_TYPE, c->head[3]);
        if (bad != 0) {
            break;
        }
        pos += H2C_FRAME_HEADER_LEN;
        length = http2_frame_length(c->head);
        if (length >= size - pos) {
            // the frame ends with the call, or behind it
            result = H2C_WALK_REACH;
            break;
        }
        pos += length;
    }
    if (result == H2C_WALK_REACH) {
        return h2c_walk_reach(c, w, pos, length);
    }
    if (result == H2C_WALK_CUT && pos >= size) {
        // the call ends on a frame boundary
        return 0;
    }
    if (result == H2C_WALK_CUT) {
        // a header cut by the end of the call: what the call has of its first 5 bytes is kept
        __u64 left = size - pos;
        if (pos + (left < sizeof(c->head) ? left : sizeof(c->head)) > readable) {
            return 1;
        }
        // the size of the read below has to be known to the verifier, which then tracks every value it
        // comes from exactly, the position the loop ended at among them, and would tell the exits of the
        // loop apart by it (newer kernels): it goes through the walk, where nothing tracks it
        w->pos = left;
        __u64 n = *(volatile __u64 *)&w->pos;
        if (n > sizeof(c->head)) {
            n = sizeof(c->head);
        }
        asm volatile("%[v] &= 0x7;\n" : [v] "+r"(n));
        if (bpf_probe_read(c->head, n, src + pos) != 0) {
            return 1;
        }
        c->head_len = left;
        return 0;
    }
    // lost, or more frames than the walk covers
    return 1;
}

// h2c_cursor_walk moves the cursor over the rest of a call that is uploaded (h2c_walk_t), from pos: through
// a frame header that began in the previous call, through the rest of the current payload, then from frame
// header to frame header (h2c_walk_frames). Only the length, the type and the flags (the first 5 bytes) of
// a header are kept; a header cut by the end of the call keeps what it has and is completed by the next
// call. When the call ends inside the payload of a DATA frame whose header lies in it, the bytes up to
// that payload are what is uploaded (w->upload), see the comment on the top. It returns 1 when the cursor
// is lost, 0 otherwise.
//
// It is called from h2c_handle_call, right behind h2c_follow_frames, so the verifier walks it once per
// program instead of once per path through the follower. Its result goes through the per CPU walk, it
// returns one of two constants.
static __noinline int h2c_cursor_walk(struct h2c_direction_t *c, struct h2c_walk_t *w) {
    char *src = (char *)w->src;
    __u64 readable = w->readable;
    __u64 size = w->size;
    __u64 pos = w->pos;
    w->upload = 0;
    w->sum_tail = 0;
    w->reach_pos = 0;
    // the call starts behind a header h2c_follow_frames read (at 0, pos 9: its frame is in head) or behind the
    // preface (pos 24), or at 0; without a branch
    __u64 judged = h2c_z(pos ^ H2C_FRAME_HEADER_LEN);
    w->frames_hdr = 0;
    w->frames_first = 0xffff & (0 - (judged ^ 1));

    __u32 seen = c->head_len;
    if (seen > 0 && seen < H2C_FRAME_HEADER_LEN) {
        // the rest of a header that began in the previous call
        __u64 need = H2C_FRAME_HEADER_LEN - seen;
        if (seen < sizeof(c->head)) {
            __u64 missing = sizeof(c->head) - seen;
            if (missing > size) {
                missing = size;
            }
            if (missing > readable) {
                return 1;
            }
            // seen is 1 to 4 and missing 1 to 4 here; the masks tell that to the verifier right before the
            // read, in 64 bit registers, which the 5.5 verifier needs (it does not track 32 bit bounds)
            __u64 at = seen;
            asm volatile("%[v] &= 0x7;\n" : [v] "+r"(at));
            asm volatile("%[v] &= 0x7;\n" : [v] "+r"(missing));
            if (bpf_probe_read(&c->head[at], missing, src) != 0) {
                return 1;
            }
        }
        if (size < need) {
            c->head_len = seen + size;
            w->frames_hdr |= h2c_lt(seen + size, 4) | h2c_header_block_type(c->head[3]);
            return 0;
        }
        pos = need;
        c->head_len = 0;
        if (c->head[3] > H2C_MAX_FRAME_TYPE) {
            return 1;
        }
        c->remaining = http2_frame_length(c->head);
        // the stream id of a header split over calls is not kept: its payload is not summarized
        c->stream_known = 0;
    }
    // the rest of a header from the call before, or the payload of the frame the call starts in (0 when neither)
    // (a payload of the frame whose header h2c_follow_frames read at 0 does not count: that frame starts in the call)
    w->frames_hdr |= h2c_nz(c->remaining | seen) & (judged ^ 1) & h2c_header_block_type(c->head[3]);
    if (c->remaining > 0) {
        if ((__u64)c->remaining >= size - pos) {
            // the payload runs to the end of the call: its header, in head, was read by this call when pos
            // is above 0
            return h2c_walk_reach(c, w, pos, c->remaining);
        }
        // the last bytes of a DATA frame with END_STREAM: the stream's summary goes after the walk (noted
        // without a branch, see h2c_walk_frames)
        __u64 m_tail = h2c_summarizing_mask() & h2c_nz(c->stream_known) & h2c_z(c->head[3] ^ HTTP2_FRAME_TYPE_DATA) &
                       (c->head[4] & H2C_FLAG_END_STREAM);
        w->sum_tail = ((1ULL << 32) | c->stream) & (0 - m_tail);
        pos += c->remaining;
        c->remaining = 0;
    }
    w->pos = pos;
    return h2c_walk_frames(c, w);
}

// h2c_call_t is the socket call h2c_follow_frames judges. It is a function of its own, verified apart
// from the upload that follows it, and a BPF call takes at most five arguments.
struct h2c_call_t {
    struct active_connection_t *conn;
    struct h2c_stream_t *stream;
    struct sock_data_args_t *args;
    __u64 conid;
    __u64 size;
    __u64 curr_nacs;
    __u8 data_direction;
    __u8 func_name;
    __u8 protocol_before_call;
    // h2c_sum_call: the call carries a DATA frame header offered to a run (h2c_sum_walked), not a call inside a
    // payload; once h2c_sum_handle decided the call is uploaded positionally: a run waits for the upload
    // (h2c_batch_cut), with bit 1 when its last frame is open (the upload is never a compact skipped record)
    __u8 run;
    // the summarized bytes in front of the call when it is uploaded positionally (common/h2c_sum.h); the run they
    // are waits per CPU for the upload (h2c_take_pos)
    __u32 sum_before;
};

// the call carries a run whose last frame is open (h2c_sum_handle)
#define H2C_CALL_OPEN_RUN(call) ((call).run & 2)

// h2c_follow_frames moves the cursor of the direction over the call and decides what becomes of it
// (H2C_CALL_*), see the comment above. It is called for every call with data of a connection that has an
// entry in h2c_stream_map, which only exists when the frames are followed (h2c_following). It is not
// inlined: the verifier then walks the upload that follows it once per result instead of once per path
// through it, and a static BPF to BPF call works on every supported kernel (a global function would need
// 5.6).
static __noinline int h2c_follow_frames(void *ctx, struct h2c_call_t *call) {
    struct active_connection_t *conn = call->conn;
    struct h2c_stream_t *stream = call->stream;
    struct sock_data_args_t *args = call->args;
    __u64 conid = call->conid;
    __u64 size = call->size;
    __u32 data_direction = call->data_direction;
    __u8 func_name = call->func_name;
    struct h2c_direction_t *c = data_direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
    // the call is uploaded with its content only when this holds, see upload_socket_data
    bool uploads_content = conn->protocol == CONNECTION_PROTOCOL_HTTP2 && conn->skip_data_upload == 0;
    // a receive with MSG_TRUNC discards its bytes unread: the bytes it reports are not the next bytes of the stream
    // it hands to the reader, so the cursor cannot follow it (a receive with MSG_PEEK never comes here: it leaves
    // its bytes in the socket and is uploaded without them, upload_socket_data_peek in transfer.h)
    bool consumed = args->recv_flags == 0;

    if (c->state == H2C_HELD) {
        // whatever this call is, it resolves the held header
        c->state = H2C_ALIGNED;
        // an mmsg call does not report the bytes it transferred (see below), so its size says nothing
        if (uploads_content && consumed && size == c->remaining && func_name != SOCKET_OPTS_TYPE_SENDMMSG &&
            func_name != SOCKET_OPTS_TYPE_RECVMMSG) {
            // exactly the payload: the frame is complete, the next call starts on a boundary
            c->remaining = 0;
            return H2C_CALL_DROP;
        }
        // not the payload: upload the header as it would have been, then follow this call as usual
        h2c_upload_held_header(ctx, conn, conid, data_direction, stream, c);
    }
    if (c->state == H2C_LOST) {
        return H2C_CALL_UPLOAD;
    }
    // a call the cursor cannot follow: the frames of the direction are not known from here on. The
    // mmsg calls do not report the bytes they transferred (see transfer.c).
    if (uploads_content == false || consumed == false || func_name == SOCKET_OPTS_TYPE_SENDMMSG ||
        func_name == SOCKET_OPTS_TYPE_RECVMMSG) {
        h2c_lose(stream, c, conid);
        return H2C_CALL_UPLOAD;
    }
    // most calls that are followed lie wholly inside the payload of a DATA frame. head is the header of
    // the frame whose payload it is: every path that leaves remaining above 0 with head_len 0 has just
    // read that header into it.
    if (c->state == H2C_ALIGNED && c->head_len == 0 && c->remaining >= size) {
        c->remaining -= size;
        if (skip_h2c_data_payload != 0 && size > 0 && call->protocol_before_call == CONNECTION_PROTOCOL_HTTP2 &&
            c->head[3] == HTTP2_FRAME_TYPE_DATA && (c->head[4] & HTTP2_FLAG_PADDED) == 0) {
            // inside the payload of a DATA frame: no frame header starts in it
            h2c_set_pos_frames(H2C_FRAMES_KNOWN | H2C_FRAMES_NO_HEADER_BLOCK | (0xffff << 8));
            return H2C_CALL_SKIP_PAYLOAD;
        }
        return H2C_CALL_UPLOAD;
    }

    // the bytes are read like the upload reads them: from the buffer, or from the first iov entry
    char *src = args->buf;
    __u64 readable = size;
    if (src == NULL && args->iovec != NULL) {
        struct iovec iov;
        bpf_probe_read(&iov, sizeof(iov), args->iovec);
        src = (char *)iov.iov_base;
        if (iov.iov_len < readable) {
            readable = iov.iov_len;
        }
    }
    if (src == NULL) {
        h2c_lose(stream, c, conid);
        return H2C_CALL_UPLOAD;
    }

    __u64 pos = 0;
    if (c->state == H2C_UNKNOWN) {
        // the first call of the direction: the client one starts with the connection preface
        // (RFC 7540 3.5, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), which is not a frame
        __u64 preface[3] = {};
        if (readable >= sizeof(preface) && bpf_probe_read(preface, sizeof(preface), src) == 0 &&
            preface[0] == H2C_PREFACE_0 && preface[1] == H2C_PREFACE_1 && preface[2] == H2C_PREFACE_2) {
            pos = sizeof(preface);
            // the requests come this way: the runs are only summarized the other way (h2c_sum_call)
            stream->request_direction = data_direction;
        } else if (size < sizeof(preface)) {
            // a preface split over calls is not followed
            char first = 0;
            if (bpf_probe_read(&first, 1, src) != 0 || first == 'P') {
                h2c_lose(stream, c, conid);
                return H2C_CALL_UPLOAD;
            }
        }
        c->state = H2C_ALIGNED;
    }

    // only a call that starts on a frame boundary of a connection already known to be HTTP/2 is judged,
    // and only when the unused frames are dropped
    if (drop_h2c_unused_frame != 0 && pos == 0 && c->remaining == 0 && c->head_len == 0 && call->protocol_before_call == CONNECTION_PROTOCOL_HTTP2 &&
        size >= H2C_FRAME_HEADER_LEN && size <= H2C_CONTROL_FRAMES_MAX_CALL_SIZE && size <= readable) {
        __u32 kZero = 0;
        struct h2c_control_frame_buffer_t *buf = bpf_map_lookup_elem(&h2c_control_frame_buffer_map, &kZero);
        if (buf == NULL) {
            h2c_lose(stream, c, conid);
            return H2C_CALL_UPLOAD;
        }
        // bound the size for the verifier right before the read, the mask never changes it
        __u64 read_size = size;
        asm volatile("%[size] &= 0x7f;\n" : [size] "+r"(read_size));
        // the bytes of this call the fast path already read and judged (-1) are taken as they are
        __u64 taken = buf->tag_size == size && buf->tag_conid == conid && buf->tag_random_id == conn->random_id &&
                      buf->tag_data_id == args->data_id;
        buf->tag_size = 0;
        if (taken || bpf_probe_read(buf->data, read_size, src) == 0) {
            // the first frame header of the call is the one the cursor met last, whatever the call turns
            // out to be (the walk, h2c_cursor_walk, starts behind it)
            __builtin_memcpy(c->head, buf->data, sizeof(c->head));
            int len = taken ? -1 : h2c_judge_call(buf->data, read_size);
            if (len == 0) {
                // complete unused frames that fill the call exactly
                return H2C_CALL_DROP;
            }
            if (len > 0) {
                // a lone frame header: hold it, the next call of the direction decides
                c->data_id = args->data_id;
                socket_data_last_upload(conid, conn->random_id, &c->prev_data_id);
                c->start_time = args->start_nacs;
                c->end_time = call->curr_nacs;
                fill_upload_data_args_ext(&c->ext, conn, args, func_name);
                __builtin_memcpy(c->header, buf->data, sizeof(c->header));
                c->remaining = len;
                c->stream_known = 0;
                c->state = H2C_HELD;
                return H2C_CALL_DROP;
            }
            // uploaded: the first frame header is already read
            if (buf->data[3] > H2C_MAX_FRAME_TYPE) {
                h2c_lose(stream, c, conid);
                return H2C_CALL_UPLOAD;
            }
            c->remaining = http2_frame_length(buf->data);
            pos = H2C_FRAME_HEADER_LEN;
        }
    }

    // the walk follows (h2c_handle_call)
    __u32 kZero = 0;
    struct h2c_walk_t *w = bpf_map_lookup_elem(&h2c_walk_map, &kZero);
    if (w == NULL) {
        h2c_lose(stream, c, conid);
        return H2C_CALL_UPLOAD;
    }
    w->src = (__u64)src;
    w->readable = readable;
    w->size = size;
    w->pos = pos;
    w->tail_skip = skip_h2c_data_payload != 0 && call->protocol_before_call == CONNECTION_PROTOCOL_HTTP2;
    return H2C_CALL_WALK;
}

// h2c_upload_skipped_payload uploads a socket call that lies wholly inside the payload of a DATA frame
// (or of an HTTP/1 body, see syscalls/h1.h) as the event without content that stands for it: the fields of
// the call are those an upload of it would carry, the protocol stays the one of the connection so it
// reaches its parser, data_len is 0 and total_size
// the size of the call, and payload_skipped tells the parser to count the bytes instead of reading them.
// socket_data_last_id_map moves exactly as an upload moves it, so the previous data id of the next upload
// names this call. It returns false when it could not, and the call is then uploaded as usual. It is a
// function of its own so its paths end in two results.
static __noinline bool h2c_upload_skipped_payload(void *ctx, struct h2c_call_t *call) {
    // a call that carries an open run (h2c_handle_call) goes as this event while the batch may hold records of its
    // connection: they go first, so its data id order is kept
    if (h2c_batching() && H2C_CALL_OPEN_RUN(*call) != 0) {
        h2c_batch_flush_for(ctx, call->stream);
    }
    struct active_connection_t *conn = call->conn;
    struct sock_data_args_t *args = call->args;
    struct upload_data_args *upload = generate_socket_upload_args();
    struct socket_data_upload_event *event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*event));
    if (upload == NULL || event == NULL) {
        return false;
    }
    // the per CPU arguments are reused: every field this upload does not set must read as zero
    __builtin_memset(upload, 0, sizeof(*upload));
    upload->start_time = args->start_nacs;
    upload->end_time = call->curr_nacs;
    upload->con_id = call->conid;
    upload->random_id = conn->random_id;
    upload->bytes_count = call->size;
    upload->socket_data_id = args->data_id;
    upload->data_direction = call->data_direction;
    fill_upload_data_args_ext(&upload->ext, conn, args, call->func_name);
    upload_data_args_ext_set_sum_before(&upload->ext, call->sum_before);
    h2c_take_pos(&upload->ext);
    fill_socket_data_event(event, upload, conn->protocol);

    __u64 prev_data_id;
    struct socket_data_last_id_t *latest = socket_data_chain_upload(call->conid, conn->random_id, args->data_id, &prev_data_id);
    event->prev_data_id = prev_data_id;
    event->sequence = 0;
    event->data_len = 0;
    event->finished = 1;
    event->have_reduce_after_chunk = 0;
    event->payload_skipped = 1;
    rover_submit_buf(ctx, &socket_data_upload_queue, event, __builtin_offsetof(struct socket_data_upload_event, buffer));

    socket_data_store_after_chain(&call->conid, conn->random_id, args->data_id, latest);
    return true;
}

// h2c_upload_cut uploads the first upload bytes of a call whose rest lies in a DATA payload (h2c_cursor_walk),
// as the upload limit cuts a call: the chunks of those bytes, each with have_reduce_after_chunk set, the
// last one finished, and total_size the size of the call. The bytes are read from where the walk read the
// frame headers (the buffer or the first iov entry, which holds them: upload is at most what was
// readable there). socket_data_last_id_map moves as an upload moves it. It returns false when the call
// would not be uploaded with its content, which upload_socket_data then decides as usual. It is a
// function of its own, apart from upload_socket_data, which stays the same for every other call.
static __noinline bool h2c_upload_cut(void *ctx, struct upload_data_args *args, __u64 upload) {
    if (args->connection_ssl != args->socket_data_ssl || args->connection_protocol == CONNECTION_PROTOCOL_UNKNOWN ||
        args->connection_skip_data_upload == 1) {
        return false;
    }
    char *src = args->socket_data_buf;
    if (src == NULL && args->socket_data_iovec != NULL) {
        struct iovec iov = {};
        bpf_probe_read(&iov, sizeof(iov), args->socket_data_iovec);
        src = (char *)iov.iov_base;
    }
    struct socket_data_upload_event *event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*event));
    if (src == NULL || event == NULL) {
        return false;
    }
    fill_socket_data_event(event, args, args->connection_protocol);
    __u64 prev_data_id;
    struct socket_data_last_id_t *latest = socket_data_chain_upload(args->con_id, args->random_id, args->socket_data_id, &prev_data_id);
    event->prev_data_id = prev_data_id;
    __u64 sent = 0;
#pragma unroll
    for (__u8 index = 0; index < SOCKET_UPLOAD_CHUNK_LIMIT; index++) {
        if (sent < upload) {
            __u64 need = upload - sent;
            if (need > SOCKET_UPLOAD_CHUNK_SIZE) {
                need = SOCKET_UPLOAD_CHUNK_SIZE;
            }
            __u32 finished = sent + need >= upload || index == SOCKET_UPLOAD_CHUNK_LIMIT - 1;
            __upload_socket_data_with_buffer(ctx, index, src + sent, need, finished, 1, event);
            sent += need;
            // never above the chunks the call can upload, the mask never changes it
            asm volatile("%[v] &= 0x1ffff;\n" : [v] "+r"(sent));
        }
    }
    socket_data_store_after_chain(&args->con_id, args->random_id, args->socket_data_id, latest);
    return true;
}

#include "h1.h"

// h2c_batch_advance_last_id moves socket_data_last_id_map forward to the data id of a call turned into a
// batch record, exactly as the event it replaces moves it (forward only), so the previous data id of the
// next upload names this call.
static __always_inline void h2c_batch_advance_last_id(__u64 conid, __u64 random_id, __u64 data_id) {
    // (the record took its place by the exchange already, include/socket_data.h)
    if (SOCKET_DATA_CHAIN_XCHG) {
        return;
    }
    struct socket_data_last_id_t *latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    // set to this call's id on any difference, exactly as the skipped/cut uploads it replaces do (not
    // forward only), so the previous data id of the next upload is byte-identical when a read and a write
    // of the fd run at once
    if (latest == NULL || latest->socket_data_id != data_id) {
        socket_data_store_last(&conid, random_id, data_id, latest);
    }
}

// h2c_batch_fill_common fills the fields a record shares with the event it replaces (the previous data id
// is the last uploaded call before this one, as the event carries it). It writes straight into the record
// slot of the per-CPU buffer, so no record is built on the stack.
static __always_inline void h2c_batch_fill_common(struct h2c_batch_record_t *rec, struct h2c_call_t *call) {
    struct active_connection_t *conn = call->conn;
    struct sock_data_args_t *args = call->args;
    rec->pad0 = 0;
    rec->pad1 = 0;
    fill_upload_data_args_ext(&rec->ext, conn, args, call->func_name);
    upload_data_args_ext_set_sum_before(&rec->ext, call->sum_before);
    h2c_take_pos(&rec->ext);
    rec->direction = call->data_direction;
    rec->start_time = args->start_nacs;
    rec->end_time = call->curr_nacs;
    rec->conid = call->conid;
    rec->random_id = conn->random_id;
    rec->data_id = args->data_id;
    rec->total_size = call->size;
    __u64 prev;
    socket_data_chain_upload(call->conid, conn->random_id, args->data_id, &prev);
    rec->prev_data_id = prev;
}

// h2c_batch_skipped turns a skipped DATA-payload call into a record (the batch replaces
// h2c_upload_skipped_payload). It returns true when the record was appended.
static __always_inline bool h2c_batch_skipped(void *ctx, struct h2c_call_t *call) {
    struct h2c_batch_record_t *rec = h2c_batch_reserve(ctx, call->curr_nacs);
    if (rec == NULL) {
        return false;
    }
    h2c_batch_fill_common(rec, call);
    rec->kind = H2C_BATCH_KIND_SKIPPED;
    rec->cut_len = 0;
    h2c_batch_advance_last_id(call->conid, call->conn->random_id, call->args->data_id);
    h2c_batch_mark(call->stream, call->data_direction);
    return true;
}

_Static_assert(H2C_BATCH_CUT_MAX == 16, "h2c_batch_cut bounds the cut bytes with a mask of 0xf");
// the cut bytes of a record that carries a run at most (h2c_batch_cut)
#define H2C_BATCH_CUT_RUN_MAX 10

// h2c_batch_cut turns a tail-cut call into a record when the bytes before the DATA payload fit a record
// (the batch replaces h2c_upload_cut). upload is the bytes of the call before the payload. It returns true
// when the record was appended, false when the call must be uploaded in whole instead.
static __always_inline bool h2c_batch_cut(void *ctx, struct h2c_call_t *call, __u64 upload) {
    // cut is upload in a register of its own: a copy (cut = upload) would share its id with upload, and the checks of
    // cut below would narrow upload too, in every state of the caller behind the call (6.12 links a copy and the
    // registers derived from it by a constant), which then no longer prunes against the states of the other calls
    __u64 cut;
    asm volatile("%[c] = %[u]\n%[c] |= 0\n" : [c] "=r"(cut) : [u] "r"(upload));
    if (cut == 0 || cut > H2C_BATCH_CUT_MAX) {
        return false;
    }
    // the user space keeps the run a record carries behind its cut bytes (buffer.CompactRecord): a longer cut
    // goes as an event
    if (cut > H2C_BATCH_CUT_RUN_MAX && call->run != 0) {
        return false;
    }
    struct sock_data_args_t *args = call->args;
    char *src = args->buf;
    __u64 readable = call->size;
    if (src == NULL && args->iovec != NULL) {
        struct iovec iov = {};
        bpf_probe_read(&iov, sizeof(iov), args->iovec);
        src = (char *)iov.iov_base;
        if (iov.iov_len < readable) {
            readable = iov.iov_len;
        }
    }
    if (src == NULL || upload > readable) {
        return false;
    }
    // read the cut bytes into a small stack buffer first, so a read failure does not leave a half-filled
    // record slot in the buffer
    __u8 tmp[H2C_BATCH_CUT_MAX] = {};
    // cut is 1..H2C_BATCH_CUT_MAX: ((cut - 1) & 0xf) + 1 is exactly it, and bounds it for the verifier in
    // the register the read takes (a clamp behind a mask can leave the bound on a copy, which 5.5 does not
    // carry over to the register it copied).
    __u64 n = cut - 1;
    asm volatile("%[v] &= 0xf;\n" : [v] "+r"(n));
    n += 1;
    if (bpf_probe_read(tmp, n, src) != 0) {
        return false;
    }
    struct h2c_batch_record_t *rec = h2c_batch_reserve(ctx, call->curr_nacs);
    if (rec == NULL) {
        return false;
    }
    h2c_batch_fill_common(rec, call);
    rec->kind = H2C_BATCH_KIND_CUT;
    rec->cut_len = cut;
    __builtin_memcpy(rec->cut_buf, tmp, H2C_BATCH_CUT_MAX);
    h2c_batch_advance_last_id(call->conid, call->conn->random_id, args->data_id);
    h2c_batch_mark(call->stream, call->data_direction);
    return true;
}

// h2c_sum_walked follows up the walk of a call (h2c_walk_t.sum_tail, reach_pos): it learns the stream of the
// DATA payload the call ends in from its header, and sends the summaries of a stream whose direction ends in
// the call: a DATA frame with END_STREAM whose payload ends in it, or ends with it. It runs behind the walk,
// where its exits have merged. The ends it does not see (a frame with END_STREAM inside the call followed by
// more frames, and RST_STREAM) the user space takes care of: its parser sees them and drains the summaries of
// such a stream from the map.
static __noinline int h2c_sum_walked(void *ctx, struct h2c_call_t *call, struct h2c_walk_t *w) {
    struct h2c_stream_t *stream = call->stream;
    struct h2c_direction_t *c = call->data_direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
    // what the walk found of the frames goes with the upload of the call, when it did not lose the cursor
    __u32 frames = 0;
    if (c->state != H2C_LOST) {
        __u64 first = w->frames_first;
        if (first > 0xffff) {
            first = 0xffff;
        }
        // what lies behind the first frame header the user space reads itself: every byte of the call up to where
        // the upload cuts it is uploaded, and what is cut is DATA payload
        __u32 before = w->frames_hdr != 0;
        __u32 none = first == 0xffff;
        frames = H2C_FRAMES_KNOWN | ((none & (before ^ 1)) << 1) | (before << 2) | (first << 8);
    }
    h2c_set_pos_frames(frames);
    if (!h2c_summarizing()) {
        return 0;
    }
    __u64 tail = w->sum_tail;
    __u64 at = w->reach_pos;
    w->sum_tail = 0;
    w->reach_pos = 0;
    __u64 random_id = call->conn->random_id;
    if (tail != 0) {
        h2c_sum_emit_stream(ctx, call->conid, random_id, (__u32)tail, call->data_direction | (H2C_SUM_REASON_END_STREAM << 8));
    }
    if (at == 0) {
        return 0;
    }
    // the header of the frame is in the call when its 9 bytes are in front of the payload
    __u32 sid = 0;
    c->stream_known = 0;
    if (at < H2C_FRAME_HEADER_LEN || at > w->readable || bpf_probe_read(&sid, sizeof(sid), (char *)w->src + at - sizeof(sid)) != 0) {
        return 0;
    }
    c->stream = bpf_ntohl(sid) & 0x7fffffff;
    c->stream_known = 1;
    // a call a run may take (h2c_sum_call, which tests the frame): its only frame header starts where the payload of
    // the open last frame of the run ends (at 0 when none is open), and its payload runs to the end of the call or
    // beyond. Without a branch.
    __u64 open = c->sum_open | ((__u32)c->sum_open_hi << 16);
    call->run = h2c_z(at ^ (open + H2C_FRAME_HEADER_LEN)) & h2c_nz(w->tail_skip);
    if (c->remaining == 0 && c->head[3] == HTTP2_FRAME_TYPE_DATA && (c->head[4] & H2C_FLAG_END_STREAM) != 0) {
        // a DATA frame with END_STREAM that ends with the call
        h2c_sum_emit_stream(ctx, call->conid, random_id, c->stream, call->data_direction | (H2C_SUM_REASON_END_STREAM << 8));
    }
    return 0;
}

// h2c_sum_call adds a call that lies wholly inside a DATA payload to the summary of its stream and direction
// (common/h2c_sum.h) instead of uploading it: H2C_SUM_TAKEN. It is H2C_SUM_LAST for the last payload call of
// a DATA frame with END_STREAM, which is uploaded positionally while its stream's summary is sent, and
// H2C_SUM_NONE when the call is uploaded as before (the stream is not known, the map is full, a summary that
// cannot join it cannot be sent). It is a function of its own so its paths end in these results.
//
// With call->run it is offered a call that is one whole DATA frame without END_STREAM and PADDED: its header
// and its payload, the payload ending with the call (a writer that writes each frame with one call, as Go's
// framer does whenever its buffer is empty: the server writes a large response body this way). Today such a
// call is uploaded cut behind its header (h2c_walk_reach), and the parser reads nothing of it but the length
// and the stream to count the payload into the body. It is summarized as a whole, header included, into a run
// of the direction: consecutive such calls of one stream, with nothing summarized in front of them otherwise
// (sum_pending counts the bytes of the run, sum_run_stream and sum_run_frames say what they are). The next
// positional upload of the direction carries the run, and the parser counts the frames of the stream in front
// of it (buffer.SummaryGap with a stream).
//
// The call is any call that carries one DATA frame header whose payload runs
// to the end of the call or beyond, the header at its start or behind the rest of the payload of the open last frame
// of the run of the stream (h2c_sum_walked), in either direction: a frame whose payload goes on behind the call stays
// open, the calls inside its payload join the run as payload calls. The parser splits a request body open for too long
// (validateIsStreamOpenTooLong) where it parses the run, behind its frames, instead of behind one of them.
static __noinline int h2c_sum_call(void *ctx, struct h2c_call_t *call) {
    struct h2c_stream_t *stream = call->stream;
    struct h2c_direction_t *c = call->data_direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
    struct active_connection_t *conn = call->conn;
    struct sock_data_args_t *args = call->args;
    if (c->stream_known == 0) {
        return H2C_SUM_NONE;
    }
    __u32 sid = c->stream;
    __u64 size = call->size;
    __u8 run = call->run;
    struct h2c_sum_scratch_t *scratch = h2c_sum_scratch();
    if (scratch == NULL) {
        return H2C_SUM_NONE;
    }
    if (run != 0) {
        // the walk read the header of the frame at the start of the call (or behind the rest of the open frame of the
        // run), and the payload ends with the call or behind it
        if (sid == 0 || c->state != H2C_ALIGNED || c->head_len != 0 || c->head[3] != HTTP2_FRAME_TYPE_DATA ||
            (c->head[4] & (H2C_FLAG_END_STREAM | HTTP2_FLAG_PADDED)) != 0 || stream->request_direction == 0) {
            return H2C_SUM_NONE;
        }
        // a run only follows a positional upload or a run of the same stream (a call that starts with the rest of
        // the open frame of a run only follows that run: sum_open is 0 without one), or the summarized payload of a
        // frame whose header was uploaded positionally (the head of the run, which ends where the call starts)
        if ((c->sum_run_stream != sid && c->sum_run_stream != 0) ||
            c->sum_pending + size > H2C_SUM_RUN_MAX_BYTES || (c->sum_run_frames & H2C_SUM_RUN_MAX_FRAMES) >= H2C_SUM_RUN_MAX_FRAMES) {
            return H2C_SUM_NONE;
        }
    } else {
        if (c->remaining == 0 && (c->head[4] & H2C_FLAG_END_STREAM) != 0) {
            h2c_sum_emit_stream(ctx, call->conid, conn->random_id, sid,
                                call->data_direction | (H2C_SUM_REASON_END_STREAM << 8));
            return H2C_SUM_LAST;
        }
        // a payload call only follows a run inside the open last frame of the run, within the bytes a run carries
        if (c->sum_run_stream != 0 &&
            (c->sum_run_stream != sid || c->sum_pending + size > H2C_SUM_RUN_MAX_BYTES)) {
            return H2C_SUM_NONE;
        }
    }
    struct h2c_sum_key_t *key = &scratch->call_key;
    key->conid = call->conid;
    key->random_id = conn->random_id;
    key->stream = sid;
    key->direction = call->data_direction;
    key->epoch = h2c_sum_epoch();
    key->pad = 0;
    __u32 minute = h2c_sum_minute(args->start_nacs);
    __u8 gen = c->sum_gen;
    __u8 func_name = call->func_name;
    struct h2c_sum_value_t *v = bpf_map_lookup_elem(&h2c_sum_map, key);
    if (v != NULL && (v->minute != minute || v->gen != gen || v->func_name != func_name || v->calls >= H2C_SUM_MAX_CALLS ||
                      v->l4_package_count >= H2C_SUM_MAX_L4_COUNT)) {
        // the call cannot join the summary: it goes, the call starts the next one
        h2c_sum_emit(ctx, key, H2C_SUM_REASON_REKEY);
        v = bpf_map_lookup_elem(&h2c_sum_map, key);
        if (v != NULL) {
            return H2C_SUM_NONE;
        }
    }
    if (v != NULL) {
        // the latest end, as the merge of the details of the calls keeps it: calls of a direction made at once (the
        // writes of several goroutines) may return out of the order of their data ids
        if (call->curr_nacs > v->end_time) {
            v->end_time = call->curr_nacs;
        }
        v->last_data_id = args->data_id;
        v->bytes += size;
        v->l4_total_package_size += args->total_package_size;
        v->l4_package_count += args->package_count;
        v->calls += 1;
    } else {
        struct h2c_sum_value_t *init = &scratch->init;
        init->start_time = args->start_nacs;
        init->end_time = call->curr_nacs;
        init->first_data_id = args->data_id;
        init->last_data_id = args->data_id;
        init->bytes = size;
        // the fields fill_upload_data_args_ext gives the event of the call (transfer_detail.h)
        init->l4_total_package_size = args->total_package_size;
        init->l4_package_count = args->package_count;
        init->calls = 1;
        init->minute = minute;
        init->local_port = conn->filter.local_port;
        init->remote_port = conn->filter.remote_port;
        init->func_name = func_name;
        init->ssl = conn->ssl;
        init->gen = gen;
        init->pad0 = 0;
        init->pad1 = 0;
        if (bpf_map_update_elem(&h2c_sum_map, key, init, BPF_NOEXIST) != 0) {
            // full (or made at once by another call): the call is uploaded as before
            return H2C_SUM_NONE;
        }
    }
    if (run != 0 && c->sum_run_stream == 0 && c->sum_pending != 0) {
        // the run starts behind the head (see above)
        c->sum_run_frames = H2C_SUM_RUN_HEAD;
    }
    c->sum_pending += size;
    c->sum_minute = minute;
    if (run != 0) {
        c->sum_run_stream = sid;
        c->sum_run_frames += 1;
    }
    return H2C_SUM_TAKEN;
}

// h2c_sum_handle is what the summaries make of a followed call (result, H2C_CALL_*): H2C_SUM_TAKEN when it was
// summarized (a call inside a DATA payload, or a whole DATA frame of a run: call->run), and the call is not
// uploaded. Otherwise a positional upload follows unless the call is dropped: it carries the bytes summarized in
// front of it (call->sum_before) and the run they are, which waits per CPU for whichever upload of the call
// follows (every one takes it: h2c_take_pos). A function of its own: the program that inlines the
// follower has no stack to spare for it.
static __noinline int h2c_sum_handle(void *ctx, struct h2c_call_t *call, int result) {
    if (result == H2C_CALL_DROP) {
        return H2C_SUM_NONE;
    }
    if ((result == H2C_CALL_SKIP_PAYLOAD || call->run != 0) && h2c_sum_call(ctx, call) == H2C_SUM_TAKEN) {
        // no upload: what was left for one goes
        h2c_clear_pos();
        return H2C_SUM_TAKEN;
    }
    struct h2c_stream_t *stream = call->stream;
    struct h2c_direction_t *c = call->data_direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
    call->sum_before = c->sum_pending;
    __u64 run = c->sum_run_stream;
    // the last frame of the run is open (sum_open is only above 0 with a run): the rest of its payload
    // from the start of the call goes with the call, its lower 16 bits as the first frame offset of the call, whatever
    // the walk made of it (common/h2c_sum.h). Without a branch.
    __u64 open = c->sum_open | ((__u32)c->sum_open_hi << 16);
    __u64 m = 0 - h2c_nz(open);
    call->run = h2c_nz(run) | (m & 2);
    // (the upper 8 bits of the rest go in the upper byte of the summarized bytes, common/h2c_sum.h)
    call->sum_before |= (__u32)(open >> 16) << 24;
    struct h2c_sum_scratch_t *scratch = h2c_sum_scratch();
    if (scratch != NULL) {
        __u64 frames = H2C_FRAMES_KNOWN | (h2c_lt(open, call->size) ^ 1) << 1 | ((open & 0xffff) << 8);
        scratch->pos_frames = (frames & m) | (scratch->pos_frames & ~m);
        scratch->pos_run = run | (H2C_SUM_RUN_OPEN & m) | ((__u64)c->sum_run_frames << 32);
    }
    c->sum_pending = 0;
    c->sum_run_stream = 0;
    c->sum_run_frames = 0;
    return H2C_SUM_NONE;
}

// The fast path. Most followed calls of a busy h2c connection only continue what the follower
// already knows, and the generic path makes them pay for everything it may do with a call: the calls in flight
// (socket_data_call_observe), the mode decision, h2c_follow_frames and its walk, the summary decision. process_write_data
// (syscalls/transfer.h) calls h2c_fast_call where it calls h2c_handle_call, with the entry h2c_handle_call would
// look up; h2c_fast_call does exactly what h2c_handle_call would do with three kinds of calls, with nothing else, and
// the generic path takes every other call (the caller goes on with it when this returns 0):
//
// A (summarized payload): a call inside the payload of a DATA frame without PADDED (the cursor is aligned, no header
//   is cut, the rest of the payload covers the call), whose stream is known and whose summary exists and takes it
//   (same minute, function generation and function, below its limits), that does not end a frame with END_STREAM
//   and may follow the run in front of it: what h2c_follow_frames (H2C_CALL_SKIP_PAYLOAD) and h2c_sum_handle /
//   h2c_sum_call (H2C_SUM_TAKEN) make of it.
// B (dropped): a call at a frame boundary that consists of complete unused frames that fill it exactly (h2c_judge_call
//   0, drop_h2c_unused_frame): H2C_CALL_DROP.
// C (run): a call at a frame boundary that starts with the header of a DATA frame without END_STREAM and PADDED
//   whose payload (not empty) runs to the end of the call or beyond, with the summaries on: the walk (h2c_cursor_walk,
//   h2c_walk_reach) and h2c_sum_walked offer it to the run of its stream, and h2c_sum_call takes it into the summary
//   that exists for it (H2C_SUM_TAKEN).
//
// Everything the generic path changes for such a call is changed here the same way, in the same order where the order
// shows: the package size fallback of the arguments (process_write_data made it already: a no-op that keeps this
// independent of it), the summary prelude of
// h2c_handle_call (function generation, the rest of the open frame of the run), the cursor (remaining, head, the
// stream of the payload), the summary and the run of the direction, and
// the per CPU positional state (cleared, as a taken call leaves it). What it does not do changes nothing a later call
// or the user space sees: the calls in flight of the arguments (only an upload reads them), the per CPU upload
// arguments (every upload sets them again), the per CPU walk (only read behind the walk of the same call). Every test
// that sends a call elsewhere is made before anything is changed; a call that finds the entry taken by another
// connection once it changed the cursor is left to the generic path with the state the follower would have left
// (h2c_handle_call then uploads it in whole, as it did).

#define H2C_FAST_SUM 1
#define H2C_FAST_DROP 2
#define H2C_FAST_RUN 3

// h2c_fast_summary finds the summary that takes a call of the stream (h2c_sum_call: same minute, function generation and
// function, below its limits); NULL when there is none or it cannot take the call (h2c_sum_call then emits it or makes
// one, which the generic path does)
static __always_inline struct h2c_sum_value_t *h2c_fast_summary(struct h2c_call_t *call, __u32 sid, __u8 gen, __u32 *minute) {
    struct h2c_sum_scratch_t *scratch = h2c_sum_scratch();
    if (scratch == NULL) {
        return NULL;
    }
    struct h2c_sum_key_t *key = &scratch->call_key;
    key->conid = call->conid;
    key->random_id = call->conn->random_id;
    key->stream = sid;
    key->direction = call->data_direction;
    key->epoch = h2c_sum_epoch();
    key->pad = 0;
    __u32 m = h2c_sum_minute(call->args->start_nacs);
    *minute = m;
    struct h2c_sum_value_t *v = bpf_map_lookup_elem(&h2c_sum_map, key);
    if (v == NULL || v->minute != m || v->gen != gen || v->func_name != call->func_name || v->calls >= H2C_SUM_MAX_CALLS ||
        v->l4_package_count >= H2C_SUM_MAX_L4_COUNT) {
        return NULL;
    }
    return v;
}

// h2c_fast_join adds the call to the summary that takes it, as h2c_sum_call does
static __always_inline void h2c_fast_join(struct h2c_call_t *call, struct h2c_sum_value_t *v) {
    struct sock_data_args_t *args = call->args;
    if (call->curr_nacs > v->end_time) {
        v->end_time = call->curr_nacs;
    }
    v->last_data_id = args->data_id;
    v->bytes += call->size;
    v->l4_total_package_size += args->total_package_size;
    v->l4_package_count += args->package_count;
    v->calls += 1;
}

// h2c_fast_begin is what process_write_data and h2c_handle_call change for a followed call before the follower: the
// package size fallback of the arguments and the summary prelude (the function generation, the
// rest of the payload of the open last frame of the run: the cursor is aligned without a cut header here)
static __always_inline void h2c_fast_begin(void *ctx, struct h2c_call_t *call, struct h2c_direction_t *c, __u8 gen) {
    struct sock_data_args_t *args = call->args;
    if (args->total_package_size == 0 && args->package_count == 0) {
        args->total_package_size = call->size;
        args->package_count = 1;
    }
    if (h2c_summarizing()) {
        c->sum_gen = gen;
        c->sum_func = call->func_name;
        __u64 rest = c->remaining & (0 - h2c_nz(c->sum_run_stream));
        c->sum_open = rest;
        c->sum_open_hi = rest >> 16;
    }
}

// h2c_fast_lost is the end of a call that finds the entry taken by another connection once it moved the cursor: what
// h2c_handle_call does then (both directions lost; the call is uploaded in whole by the generic path, which finds the
// entry of another connection and takes the positional state left here, frames)
static __always_inline int h2c_fast_lost(struct h2c_stream_t *stream, __u32 frames) {
    h2c_set_pos_frames(frames);
    stream->dir[0].state = H2C_LOST;
    stream->dir[1].state = H2C_LOST;
    return 0;
}

// h2c_fast_now is the end of the call (sock_data_args_t.exit_nacs): read once, by the kinds of calls that keep it
// (h2c_fast_join, the held header) and in front of the paths that may leave the call to the generic path; the dropped
// calls never read it, and a call left to the generic path before it was read here reads it there (process_write_data)
static __always_inline __u64 h2c_fast_now(struct h2c_call_t *call) {
    struct sock_data_args_t *args = call->args;
    if (*(volatile __u64 *)&args->exit_nacs == 0) {
        args->exit_nacs = bpf_ktime_get_ns();
    }
    call->curr_nacs = *(volatile __u64 *)&args->exit_nacs;
    return call->curr_nacs;
}

// h2c_fast_control_type is 1 when a frame of the type may be one h2c_control_frame_payload_len accepts (WINDOW_UPDATE,
// PING, PRIORITY, SETTINGS): h2c_judge_call returns -1 for a call whose first frame is of any other type
static __always_inline int h2c_fast_control_type(__u8 type) {
    return type == HTTP2_FRAME_TYPE_WINDOW_UPDATE || type == HTTP2_FRAME_TYPE_PING || type == HTTP2_FRAME_TYPE_PRIORITY ||
           type == HTTP2_FRAME_TYPE_SETTINGS;
}

// h2c_fast_held: D, the call that follows a held lone header of a frame the user space discards (h2c_follow_frames
// holds a WINDOW_UPDATE, PING or PRIORITY header read alone, as Go's framer reads every frame header of a connection: a
// read of the header, a read of the payload). When the call is exactly the payload, the generic path drops it and the
// cursor is at the next frame boundary: the same here, with the prelude of h2c_handle_call as it is for a held header
// (the open rest of the run is 0: the cursor is not aligned while a header is held). Every other call goes generic.
static __always_inline int h2c_fast_held(void *ctx, struct h2c_call_t *call, struct h2c_direction_t *c, __u8 gen) {
    struct active_connection_t *conn = call->conn;
    struct h2c_stream_t *stream = call->stream;
    struct sock_data_args_t *args = call->args;
    if ((drop_h2c_unused_frame | skip_h2c_data_payload) == 0 || call->size != c->remaining) {
        return 0;
    }
    if (args->total_package_size == 0 && args->package_count == 0) {
        args->total_package_size = call->size;
        args->package_count = 1;
    }
    if (h2c_summarizing()) {
        c->sum_gen = gen;
        c->sum_func = call->func_name;
        c->sum_open = 0;
        c->sum_open_hi = 0;
    }
    c->state = H2C_ALIGNED;
    c->remaining = 0;
    if (stream->random_id != conn->random_id) {
        return h2c_fast_lost(stream, 0);
    }
    return 1;
}

// h2c_fast_call does what the generic path would do with a call of the kinds A, B and C above, and returns 1; 0 when
// the call is not one of them, before it changed anything (or once it found the entry of another connection). call is
// the call as h2c_follow_frames gets it, of a cleartext connection with an entry in h2c_stream_map (call->stream). A
// function of its own: its paths end in two results.
static __noinline int h2c_fast_call(void *ctx, struct h2c_call_t *call) {
    struct active_connection_t *conn = call->conn;
    struct h2c_stream_t *stream = call->stream;
    struct sock_data_args_t *args = call->args;
    __u64 size = call->size;
    __u32 data_direction = call->data_direction;
    __u8 func_name = call->func_name;
    if (data_direction != SOCK_DATA_DIRECTION_INGRESS && data_direction != SOCK_DATA_DIRECTION_EGRESS) {
        return 0;
    }
    // a connection known as HTTP/2 before the call and still, cleartext and uploaded, a receive that hands its bytes to
    // the reader, not an mmsg call: h2c_follow_frames follows it (and skips, drops and cuts in it). The entry is the
    // connection's, followed as HTTP/2.
    if (conn->protocol != CONNECTION_PROTOCOL_HTTP2 || call->protocol_before_call != CONNECTION_PROTOCOL_HTTP2 || conn->ssl != 0 ||
        conn->skip_data_upload != 0 || args->recv_flags != 0 || func_name == SOCKET_OPTS_TYPE_SENDMMSG ||
        func_name == SOCKET_OPTS_TYPE_RECVMMSG || stream->random_id != conn->random_id || stream->mode != H2C_STREAM_HTTP2) {
        return 0;
    }
    struct h2c_direction_t *c = data_direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
    // the function generation of the call (h2c_handle_call bumps it before the follower)
    __u8 gen = c->sum_gen + (__u8)h2c_nz(c->sum_func ^ func_name);
    if (c->state == H2C_HELD) {
        return h2c_fast_held(ctx, call, c, gen);
    }
    if (c->state != H2C_ALIGNED || c->head_len != 0) {
        return 0;
    }
    __u64 remaining = c->remaining;
    __u32 minute = 0;
    if (remaining >= size) {
        // A: inside the payload of the current frame
        h2c_fast_now(call);
        if (skip_h2c_data_payload == 0 || !h2c_summarizing() || c->head[3] != HTTP2_FRAME_TYPE_DATA ||
            (c->head[4] & HTTP2_FLAG_PADDED) != 0 || c->stream_known == 0) {
            return 0;
        }
        __u64 rest = remaining - size;
        __u32 sid = c->stream;
        // the last payload call of a frame with END_STREAM (H2C_SUM_LAST), or a payload call the run in front of it
        // cannot take (h2c_sum_call)
        if ((rest == 0 && (c->head[4] & H2C_FLAG_END_STREAM) != 0) ||
            (c->sum_run_stream != 0 &&
             (c->sum_run_stream != sid || c->sum_pending + size > H2C_SUM_RUN_MAX_BYTES))) {
            return 0;
        }
        struct h2c_sum_value_t *v = h2c_fast_summary(call, sid, gen, &minute);
        if (v == NULL) {
            return 0;
        }
        h2c_fast_begin(ctx, call, c, gen);
        c->remaining = rest;
        if (stream->random_id != conn->random_id) {
            return h2c_fast_lost(stream, H2C_FRAMES_KNOWN | H2C_FRAMES_NO_HEADER_BLOCK | (0xffff << 8));
        }
        h2c_fast_join(call, v);
        c->sum_pending += size;
        c->sum_minute = minute;
        h2c_clear_pos();
        return 1;
    }
    if (remaining != 0 || size < H2C_FRAME_HEADER_LEN) {
        return 0;
    }
    // at a frame boundary: the bytes are read like the follower reads them, from the buffer or the first iov entry
    char *src = args->buf;
    __u64 readable = size;
    if (src == NULL && args->iovec != NULL) {
        struct iovec iov;
        bpf_probe_read(&iov, sizeof(iov), args->iovec);
        src = (char *)iov.iov_base;
        if (iov.iov_len < readable) {
            readable = iov.iov_len;
        }
    }
    if (src == NULL) {
        return 0;
    }
    // the first frame header of the call, from the bytes B reads or read on its own for C
    __u8 h[H2C_FRAME_HEADER_LEN] = {};
    int have_header = 0;
    if (drop_h2c_unused_frame != 0 && size <= H2C_CONTROL_FRAMES_MAX_CALL_SIZE && size <= readable) {
        // B: judged as h2c_follow_frames judges it; any other result is the generic path's
        __u32 kZero = 0;
        struct h2c_control_frame_buffer_t *buf = bpf_map_lookup_elem(&h2c_control_frame_buffer_map, &kZero);
        if (buf == NULL) {
            return 0;
        }
        buf->tag_size = 0;
        __u64 read_size = size;
        asm volatile("%[size] &= 0x7f;\n" : [size] "+r"(read_size));
        int judged = -1;
        if (bpf_probe_read(buf->data, read_size, src) == 0) {
            // a call whose first frame is of no type an unused frame has is judged -1 without the judge
            if (h2c_fast_control_type(buf->data[3])) {
                judged = h2c_judge_call(buf->data, read_size);
            }
            if (judged < 0) {
                // the bytes go on to C and, when it leaves the call, to h2c_follow_frames (which reads and judges
                // them the same way)
                __builtin_memcpy(h, buf->data, sizeof(h));
                have_header = 1;
                buf->tag_conid = call->conid;
                buf->tag_random_id = conn->random_id;
                buf->tag_data_id = args->data_id;
                buf->tag_size = size;
            }
        }
        if (judged > 0) {
            // D: a lone header of a frame the user space discards, held as h2c_follow_frames holds it (with the
            // calls in flight that the generic path takes before the follower, which the held event carries)
            h2c_fast_begin(ctx, call, c, gen);
            __builtin_memcpy(c->head, buf->data, sizeof(c->head));
            socket_data_call_observe(bpf_get_current_pid_tgid(), args);
            c->data_id = args->data_id;
            socket_data_last_upload(call->conid, conn->random_id, &c->prev_data_id);
            c->start_time = args->start_nacs;
            c->end_time = h2c_fast_now(call);
            fill_upload_data_args_ext(&c->ext, conn, args, func_name);
            __builtin_memcpy(c->header, buf->data, sizeof(c->header));
            c->remaining = judged;
            c->stream_known = 0;
            c->state = H2C_HELD;
            if (stream->random_id != conn->random_id) {
                return h2c_fast_lost(stream, 0);
            }
            return 1;
        }
        if (judged == 0) {
            h2c_fast_begin(ctx, call, c, gen);
            __builtin_memcpy(c->head, buf->data, sizeof(c->head));
            if (stream->random_id != conn->random_id) {
                return h2c_fast_lost(stream, 0);
            }
            return 1;
        }
        // (a call of a DATA frame header goes on to C: the follower walks from that header as from the start of the
        // call, see below)
    }
    // C: one DATA frame header at the start of the call whose payload reaches the end of the call. The follower walks
    // it from its start (or, a call h2c_judge_call read, from behind the header it read: the same cursor, the same
    // walk results); h2c_sum_walked learns the stream from the header (9 bytes of it must be readable) and offers the
    // call to a run; h2c_sum_call takes it.
    h2c_fast_now(call);
    if (skip_h2c_data_payload == 0 || !h2c_summarizing() || readable < H2C_FRAME_HEADER_LEN) {
        return 0;
    }
    if (have_header == 0 && bpf_probe_read(h, sizeof(h), src) != 0) {
        return 0;
    }
    __u64 length = ((__u64)h[0] << 16) | ((__u64)h[1] << 8) | h[2];
    __u32 sid = (((__u32)h[5] << 24) | ((__u32)h[6] << 16) | ((__u32)h[7] << 8) | h[8]) & 0x7fffffff;
    __u32 request_direction = stream->request_direction;
    __u64 body = size - H2C_FRAME_HEADER_LEN;
    // the walk cuts the upload behind the header when the payload has bytes in the call (h2c_walk_reach); the run
    // takes the call (h2c_sum_walked, h2c_handle_call, h2c_sum_call)
    if (h[3] != HTTP2_FRAME_TYPE_DATA || (h[4] & (H2C_FLAG_END_STREAM | HTTP2_FLAG_PADDED)) != 0 || length == 0 ||
        length < body || sid == 0 || request_direction == 0) {
        return 0;
    }
    // the run of the direction takes it (h2c_sum_call)
    if ((c->sum_run_stream != sid && c->sum_run_stream != 0) ||
        c->sum_pending + size > H2C_SUM_RUN_MAX_BYTES || (c->sum_run_frames & H2C_SUM_RUN_MAX_FRAMES) >= H2C_SUM_RUN_MAX_FRAMES) {
        return 0;
    }
    struct h2c_sum_value_t *v = h2c_fast_summary(call, sid, gen, &minute);
    if (v == NULL) {
        return 0;
    }
    h2c_fast_begin(ctx, call, c, gen);
    // the cursor behind the walk: in the payload of this frame, its header in head, its stream known
    __builtin_memcpy(c->head, h, sizeof(c->head));
    c->head_len = 0;
    c->remaining = length - body;
    c->stream = sid;
    c->stream_known = 1;
    if (stream->random_id != conn->random_id) {
        // what h2c_sum_walked left for the upload: the frames are known, the first header at 0
        return h2c_fast_lost(stream, H2C_FRAMES_KNOWN);
    }
    h2c_fast_join(call, v);
    if (c->sum_run_stream == 0 && c->sum_pending != 0) {
        // the run starts behind the head (see h2c_sum_call)
        c->sum_run_frames = H2C_SUM_RUN_HEAD;
    }
    c->sum_pending += size;
    c->sum_minute = minute;
    c->sum_run_stream = sid;
    c->sum_run_frames += 1;
    h2c_clear_pos();
    return 1;
}

// The h2c upgrade (RFC 7540 3.2): a cleartext HTTP/1.1 connection whose request asks for "Upgrade: h2c" is
// answered with "HTTP/1.1 101 Switching Protocols" and "Upgrade: h2c", and is HTTP/2 from the next byte behind that
// response on, both ways (the client sends the connection preface next). The connection is known as HTTP/2 from
// the call that carries the 101 (written by the server, read by the client) on: its event and every later one say
// CONNECTION_PROTOCOL_HTTP2 (pkg/accesslog/collector/protocols/http2_upgrade.go). The call itself was not known as
// HTTP/2 before it (protocol_before_call in syscalls/transfer.h is HTTP/1), so it is followed but never dropped,
// skipped or cut: it is uploaded whole, the head and whatever frames the server wrote behind it. The follower of
// the connection starts over as for a new HTTP/2 connection: the client preface is the first thing it sees in the
// direction of the requests. The response is told by its first
// bytes, "HTTP/1.1 101", and by "h2c" followed by a CR within its first H2C_UPGRADE_SCAN bytes (the value of its
// Upgrade header: a WebSocket upgrade says "websocket").
#define H2C_UPGRADE_SCAN 128
struct h2c_upgrade_buffer_t {
    __u8 data[H2C_UPGRADE_SCAN + 8];
    // what the scan found, kept here and not in registers: the verifier then sees the same state on every iteration
    // and at every exit of the scan
    __u32 found;
    __u32 head;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct h2c_upgrade_buffer_t);
    __uint(max_entries, 1);
} h2c_upgrade_buffer_map SEC(".maps");

// "HTTP/1.1" and " 101" as little endian words, and "h2c\r"
#define H2C_UPGRADE_HTTP11 0x312e312f50545448ULL
#define H2C_UPGRADE_101 0x31303120U
#define H2C_UPGRADE_H2C 0x0d633268U
// "\r\n\r\n"
#define H2C_UPGRADE_END 0x0a0d0a0dU

static __noinline int h2c_upgrade(void *ctx, struct active_connection_t *conn, struct sock_data_args_t *args, __u64 conid,
                                  __u64 size_direction) {
    __u64 size = size_direction & 0xffffffffffffULL;
    __u32 direction = size_direction >> 56;
    char *src = args->buf;
    __u64 readable = size;
    if (src == NULL && args->iovec != NULL) {
        struct iovec iov = {};
        bpf_probe_read(&iov, sizeof(iov), args->iovec);
        src = (char *)iov.iov_base;
        if (iov.iov_len < readable) {
            readable = iov.iov_len;
        }
    }
    if (src == NULL || readable < 16) {
        return 0;
    }
    __u32 kZero = 0;
    struct h2c_upgrade_buffer_t *b = bpf_map_lookup_elem(&h2c_upgrade_buffer_map, &kZero);
    if (b == NULL || bpf_probe_read(b->data, 12, src) != 0) {
        return 0;
    }
    if (*(__u64 *)b->data != H2C_UPGRADE_HTTP11 || *(__u32 *)&b->data[8] != H2C_UPGRADE_101) {
        return 0;
    }
    __u64 n = readable < H2C_UPGRADE_SCAN ? readable : H2C_UPGRADE_SCAN;
    asm volatile("%[v] &= 0xff;\n" : [v] "+r"(n));
    if (n > H2C_UPGRADE_SCAN || bpf_probe_read(b->data, n, src) != 0) {
        return 0;
    }
    // the value h2c of an Upgrade header in the head, and the end of the head
    b->found = 0;
    b->head = 0;
#pragma clang loop unroll(disable)
    for (int i = 12; i < H2C_UPGRADE_SCAN - 4; i++) {
        if (i + 4 > n) {
            break;
        }
        __u32 word = *(__u32 *)&b->data[i];
        __u32 ended = *(volatile __u32 *)&b->head;
        if (ended == 0 && word == H2C_UPGRADE_H2C) {
            b->found = 1;
        }
        if (ended == 0 && word == H2C_UPGRADE_END) {
            b->head = i + 4;
        }
    }
    __u64 found = *(volatile __u32 *)&b->found;
    __u64 head = *(volatile __u32 *)&b->head;
    if (found == 0) {
        return 0;
    }
    // HTTP/2 from this call on
    conn->protocol = CONNECTION_PROTOCOL_HTTP2;
    struct h2c_stream_t *stream = bpf_map_lookup_elem(&h2c_stream_map, &conid);
    if (stream == NULL || stream->random_id != conn->random_id) {
        return 1;
    }
    // the follower starts over, undecided: this call decides HTTP/2, the first call of the other direction is the
    // first byte of its HTTP/2 stream (the client preface). Unless the HTTP/1 follower holds skipped calls of a body
    // (it does not by the 101: the request was read whole, the 101 has no body): it then follows nothing more, and
    // its held calls go as they would (before the next call, or at the close)
    if (stream->mode == H2C_STREAM_HTTP1 && (stream->h1[0].pending | stream->h1[1].pending) != 0) {
        stream->h1[0].state = H2C_LOST;
        stream->h1[1].state = H2C_LOST;
        return 1;
    }
    __builtin_memset(&stream->dir, 0, sizeof(stream->dir));
    stream->mode = H2C_STREAM_UNDECIDED;
    stream->request_direction = 0;
    // this direction: the head of the 101 is taken for the payload of a frame the user space discards (type
    // WINDOW_UPDATE), so the frames behind it are followed from where it ends; a head that does not end within the
    // bytes looked at loses the direction
    struct h2c_direction_t *c = direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
    if (head == 0 || head > size) {
        c->state = H2C_LOST;
    } else {
        c->state = H2C_ALIGNED;
        c->remaining = head;
        c->head[3] = HTTP2_FRAME_TYPE_WINDOW_UPDATE;
    }
    return 1;
}

// h2c_handle_call follows a socket call with data of a followed connection (h2c_stream_map) and reports
// whether its socket data must not be uploaded as usual: when it is dropped, when it was uploaded without
// its content here because it lies inside a DATA payload or an HTTP/1 body, and when it is held for a
// coalesced event (syscalls/h1.h). The first call followed decides how the connection is followed: as
// HTTP/1 when it is known as HTTP/1 by then and skip_http1_body_payload is on, otherwise as HTTP/2. Only a
// cleartext call of a connection followed from its start is ever dropped (with drop_h2c_unused_frame on)
// or skipped (with skip_h2c_data_payload or skip_http1_body_payload on). A call that is uploaded as usual
// may be uploaded only up to the lower 32 bits of *upload_size bytes, when that is above 0: the rest lies in a
// DATA payload. The upper 32 bits are the summarized payload bytes in front of the call (common/h2c_sum.h); the
// run they are waits per CPU for whichever upload of the call follows (h2c_take_pos), with what the follower
// knows of its frames (H2C_FRAMES_*).
//
// stream is the entry of the connection in h2c_stream_map (NULL: none), which the caller looked up.
static __always_inline bool h2c_handle_call(void *ctx, struct active_connection_t *conn, struct h2c_stream_t *stream,
                                          struct sock_data_args_t *args, __u64 conid, ssize_t bytes_count, __u64 curr_nacs,
                                          __u32 data_direction, __u8 func_name, __u8 protocol_before_call, bool ssl, bool pressure,
                                          __u64 *upload_size) {
    // a call of a TLS library (ssl) is never of a connection followed in plain text: a constant, so the TLS
    // probes do not carry the follower
    if (!h2c_following() || ssl != false ||
        (data_direction != SOCK_DATA_DIRECTION_INGRESS && data_direction != SOCK_DATA_DIRECTION_EGRESS)) {
        return false;
    }
    if (stream == NULL || stream->random_id != conn->random_id) {
        return false;
    }
    // the protocol analysis before the call can leave a different known value of the protocol on each of
    // its paths; masked (which never changes it), they cannot make the verifier walk the follower once per
    // path
    __u64 protocol = protocol_before_call;
    asm volatile("%[v] &= 0xff;\n" : [v] "+r"(protocol));
    struct h2c_call_t call = {
        .conn = conn, .stream = stream, .args = args, .conid = conid, .size = bytes_count,
        .curr_nacs = curr_nacs, .data_direction = data_direction, .func_name = func_name,
        .protocol_before_call = protocol,
    };
    // an undecided mode is decided without a branch: a branch would make the verifier walk the follower
    // once more, for the path that decided
    __u64 mode = *(volatile __u32 *)&stream->mode;
    __u64 http1 = h1_z(conn->protocol ^ CONNECTION_PROTOCOL_HTTP1) & h1_nz(skip_http1_body_payload);
    mode |= (0 - h1_z(mode)) & (H2C_STREAM_HTTP2 + http1);
    stream->mode = mode;
    if (mode == H2C_STREAM_HTTP1) {
        // whatever the call is: a held run of the connection is uploaded before any other call
        bool h1_taken = h1_handle_call(ctx, &call) != 0;
        return h1_taken;
    }
    if (conn->ssl != 0) {
        return false;
    }
    if (h2c_summarizing()) {
        // a summary only holds calls of one function generation (common/h2c_sum.h)
        struct h2c_direction_t *g = data_direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
        g->sum_gen += h2c_nz(g->sum_func ^ func_name);
        g->sum_func = func_name;
        // the rest of the payload of the open last frame of the run of the direction at the start of the call (common/
        // h2c_sum.h), before the follower moves the cursor over it; without a branch
        __u64 open = h2c_nz(g->sum_run_stream) & h2c_z(g->head_len) & h2c_z(g->state ^ H2C_ALIGNED);
        __u64 rest = g->remaining & (0 - open);
        g->sum_open = rest;
        g->sum_open_hi = rest >> 16;
    }
    if ((drop_h2c_unused_frame | skip_h2c_data_payload) == 0) {
        // only the HTTP/1 bodies are skipped, and the connection was not known as HTTP/1 at its first call
        stream->dir[0].state = H2C_LOST;
        h2c_lose(stream, &stream->dir[1], conid);
        return false;
    }
    int result = h2c_follow_frames(ctx, &call);
    if (result == H2C_CALL_WALK) {
        __u32 kZero = 0;
        struct h2c_walk_t *w = bpf_map_lookup_elem(&h2c_walk_map, &kZero);
        struct h2c_direction_t *c = data_direction == SOCK_DATA_DIRECTION_INGRESS ? &stream->dir[0] : &stream->dir[1];
        if (w == NULL || h2c_cursor_walk(c, w) != 0) {
            h2c_lose(stream, c, conid);
        } else {
            *upload_size = w->upload;
        }
        // what the walk found of the frames, and the summaries
        if (w != NULL) {
            h2c_sum_walked(ctx, &call, w);
        }
        result = H2C_CALL_UPLOAD;
    }
    // the entry was removed and its element taken by another connection of the fd while the call was
    // followed: what was written may be this call's state in the other connection's entry, so the other
    // connection is never dropped from, and this call is uploaded
    if (stream->random_id != conn->random_id) {
        stream->dir[0].state = H2C_LOST;
        stream->dir[1].state = H2C_LOST;
        *upload_size = 0;
        return false;
    }
    if (h2c_summarizing()) {
        // the walk offered the call to a run (h2c_sum_walked): a call that carries the header of the DATA frame whose
        // payload it ends in, which a run may take (h2c_sum_call); noted without a branch
        __u64 request_direction = stream->request_direction;
        call.run = call.run & h2c_z(result ^ H2C_CALL_UPLOAD) & h2c_nz(request_direction);
        int sum = h2c_sum_handle(ctx, &call, result);
        if (sum == H2C_SUM_TAKEN) {
            *upload_size = 0;
            return true;
        }
        // a positional upload follows: the bytes summarized in front of it in the upper half of *upload_size
        *upload_size |= (__u64)call.sum_before << 32;
    }
    if (result == H2C_CALL_SKIP_PAYLOAD) {
        // batch the skipped call as a compact record, or upload it as an event without content
        // (one that carries an open run goes as an event: a record has no room for the rest of the open frame)
        if (h2c_batching() && H2C_CALL_OPEN_RUN(call) == 0) {
            bool batched = h2c_batch_skipped(ctx, &call);
            if (batched) {
                return true;
            }
        }
        bool skipped = h2c_upload_skipped_payload(ctx, &call);
        return skipped;
    }
    // a tail-cut call (the rest of the call lies in a DATA payload) is batched as a record when its cut
    // prefix fits one; otherwise it is uploaded in whole by the caller (h2c_upload_cut), which flushes the
    // batch first so the data id order of this CPU is kept
    if (result == H2C_CALL_UPLOAD && H2C_UPLOAD_CUT(*upload_size) != 0 && h2c_batching() && !pressure) {
        bool batched = h2c_batch_cut(ctx, &call, H2C_UPLOAD_CUT(*upload_size));
        if (batched) {
            *upload_size = 0;
            return true;
        }
    }
    // a full upload of this connection follows (transfer.h): flush its own pending records first, so its
    // data id order is kept. Only this connection's records force a flush (correction: same-connection only)
    if (result == H2C_CALL_UPLOAD && h2c_batching()) {
        h2c_batch_flush_for(ctx, stream);
    }
    return result == H2C_CALL_DROP;
}
