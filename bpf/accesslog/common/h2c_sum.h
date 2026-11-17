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

// Per-stream summaries of the skipped HTTP/2 DATA payload (access_log.protocol_analyze.summarize_h2c_payload,
// set with skip_h2c_data_payload, batch_h2c_records and merge_kernel_logs).
//
// A socket call that lies wholly inside the payload of a DATA frame (H2C_CALL_SKIP_PAYLOAD, syscalls/h2c.h)
// is not uploaded at all: its size, its times and its L4 counters are added to the summary of its stream and
// direction in h2c_sum_map. Every other call (anything with a frame header, a tail-cut call, a call whose
// stream is not known) is uploaded as before, and the bytes summarized since the previous positional upload
// of the direction travel with the next positional upload of the direction (sum_before), so the user-space
// parser counts them as skipped payload in front of it and the frames stay where they are. The calls the
// summaries take never move socket_data_last_id_map: the previous data id of a positional upload names the
// previous positional upload.
//
// A summary goes to the user space as a record of the per-CPU batch (H2C_BATCH_KIND_SUMMARY) and its entry is
// deleted, in the program that sees:
// - the end of the stream's direction: the last payload call of a DATA frame with END_STREAM (that call
//   itself is uploaded positionally, as a skipped call, carrying the summarized bytes in front of it, so the
//   parser can finish the stream at once), a positional call in which such a payload ends, or one that ends
//   with such a frame (h2c_sum_walked in syscalls/h2c.h);
// - a call that cannot join it: another wall clock minute (the kernel log merge never crosses one), another
//   function generation (h2c_direction_t.sum_gen), or a counter at its limit; the call then starts a new one;
// - the close of the connection (the current stream of each direction).
// The ends BPF does not look for, because the frame walk has no room for them in the verifier (a frame with
// END_STREAM inside a call followed by more frames, RST_STREAM), the user space parser sees: it drains the
// entries of such a stream itself (pkg/accesslog/collectors/protocols/h2csum.go DrainStream).
// The user space flushes the rest once a second by the epoch: every key carries the epoch bit current when
// the entry was made; the user space flips h2c_sum_epoch_map, waits for the programs of the old epoch to end,
// and drains (looks up and deletes) every entry of the old epoch and every entry of a connection that is
// closed. Exactly one side deletes an entry, and only the side whose delete succeeded hands it on (a BPF
// emission that loses the race takes its record back), so an entry is never counted twice.
//
// When an entry cannot be made (the map is full) the call is uploaded as before, as a skipped call: nothing
// is lost. The map is a plain hash on purpose, not an LRU: an evicted entry would lose its calls silently.
//
// Runs (syscalls/h2c.h h2c_sum_call). A call that carries one DATA frame header, without END_STREAM or PADDED, of a
// stream whose payload runs to the end of the call or beyond is summarized as a whole, header included, into a run of
// the direction: the next positional upload carries the run (the stream and the frame headers in the summarized bytes
// in front of it), and the parser takes it where it expects a frame header, as that many frames of the stream.
// A run also takes:
// - a frame whose payload continues in the next calls of the direction (a reader that reads the header and the start
//   of the payload in one call and the rest in others, as Go's HTTP/2 client does, or a lone 9 byte header read, as
//   Go's server reads a request body): the calls of the rest of its payload are summarized as any payload call, and the
//   last frame of the run is open while its payload has not ended;
// - a call that starts with the rest of the payload of the open last frame of the run, followed by the header of the
//   next frame of the stream (the bytes in front of its header are the lead, the run's open frame ends there);
// - the frames of both directions;
// - a frame at a frame boundary behind the summarized payload calls of a frame whose header was uploaded positionally
//   (the first DATA frame behind a HEADERS frame read in the same call, as Go's client reads a response): the run
//   starts behind that payload, its head, and its frames carry H2C_SUM_RUN_HEAD. The parser, which discards the
//   payload of that frame when it gets to the run, takes the head as the end of the frame (the rest of the bytes it
//   still wants) and the run behind it.
// A positional upload that follows an open run (a call whose first bytes are the rest of the payload of the last frame
// of the run) carries H2C_SUM_RUN_OPEN with the stream of the run, and the rest of that payload from the start of the
// call (24 bits): its lower 16 bits as the first frame offset of the call (h2c_frames with H2C_FRAMES_KNOWN, set
// however the walk of the call went), its upper 8 bits in the upper byte of sum_before (the summarized bytes in front
// of an upload never exceed 24 bits, H2C_SUM_RUN_MAX_BYTES). The parser counts that many bytes behind the run into the
// payload of its last frame (HTTP2 handleSummaryRun), which then ends where the frame ends. Such an upload is never a
// compact record of a skipped call (whose first frame offset does not fit): it goes as an event.

volatile __u32 summarize_h2c_payload;
#define h2c_summarizing() (summarize_h2c_payload != 0)

// branch-free tests, written so the compiler keeps them branch-free: a branch on a value the verifier does
// not know is a state it explores, and the frame walk (syscalls/h2c.h) has none to spare
static __always_inline __u64 h2c_nz(__u64 x) {
    __u64 n = x;
    asm volatile("%[v] = -%[v];\n" : [v] "+r"(n));
    n |= x;
    asm volatile("%[v] >>= 63;\n" : [v] "+r"(n));
    return n;
}
static __always_inline __u64 h2c_z(__u64 x) {
    return h2c_nz(x) ^ 1;
}
// 1 when a < b, both below 2^63
static __always_inline __u64 h2c_lt(__u64 a, __u64 b) {
    __u64 d = a - b;
    asm volatile("%[v] >>= 63;\n" : [v] "+r"(d));
    return d;
}

// 1 when the summaries are on, without a branch
#define h2c_summarizing_mask() h2c_nz(summarize_h2c_payload)

#define H2C_FRAME_TYPE_RST_STREAM 0x3
#define H2C_FLAG_END_STREAM 0x1

// what h2c_sum_call made of a call
#define H2C_SUM_NONE 0
#define H2C_SUM_TAKEN 1
// the last payload call of a stream's direction: uploaded positionally, its summary was emitted
#define H2C_SUM_LAST 2

// why a summary was sent (h2c_sum_record_t.reason); the user space adds its own (flush, close, stale)
#define H2C_SUM_REASON_END_STREAM 1
// (not sent by BPF: the user space drains the entries of a reset stream)
#define H2C_SUM_REASON_RST 2
#define H2C_SUM_REASON_CLOSE 3
#define H2C_SUM_REASON_REKEY 4

// a summary holds at most this many calls, so its counters never wrap in the user space
#define H2C_SUM_MAX_CALLS 0xffff
#define H2C_SUM_MAX_L4_COUNT 0xffff0000
// a run of whole DATA frames in front of a positional upload at most: the user space keeps the summarized bytes
// in front of a record in 24 bits (buffer.CompactRecord), and the frames in 15 (the mask of the frame count)
#define H2C_SUM_RUN_MAX_BYTES 0xffffff
#define H2C_SUM_RUN_MAX_FRAMES 0x7fff
// the frames of a run that starts behind summarized payload of the frame in front of its first frame (the head):
// the parser takes the head as the end of that frame (buffer.Buffer.DiscardBytes)
#define H2C_SUM_RUN_HEAD 0x8000
// the stream of a run whose last frame is open behind it: the rest of its payload from the start of the
// call that carries the run is the first frame offset of that call (its lower 16 bits; the upper 8 go in the upper
// byte of the summarized bytes, h2c_take_pos in syscalls/h2c.h)
#define H2C_SUM_RUN_OPEN 0x80000000U

struct h2c_sum_key_t {
    __u64 conid;
    __u64 random_id;
    __u32 stream;
    __u8 direction;
    __u8 epoch;
    __u16 pad;
};

// the calls of a summary: the start of the first, the end of the last, the data ids of the first and of the
// last, the bytes, the L4 counters summed, and what every call of it shares (function, ssl, ports, minute and
// function generation)
struct h2c_sum_value_t {
    __u64 start_time;
    __u64 end_time;
    __u64 first_data_id;
    __u64 last_data_id;
    __u64 bytes;
    __u64 l4_total_package_size;
    __u32 l4_package_count;
    __u32 calls;
    __u32 minute;
    __u16 local_port;
    __u16 remote_port;
    __u8 func_name;
    __u8 ssl;
    __u8 gen;
    __u8 pad0;
    __u32 pad1;
};

// a summary in the per-CPU batch, in the place of a call record (h2c_batch_record_t)
struct h2c_sum_record_t {
    __u8 kind;
    __u8 direction;
    __u8 reason;
    __u8 epoch;
    __u32 stream;
    __u64 conid;
    __u64 random_id;
    struct h2c_sum_value_t value;
    __u64 pad[2];
};

#define H2C_BATCH_KIND_SUMMARY 3


_Static_assert(sizeof(struct h2c_sum_record_t) == sizeof(struct h2c_batch_record_t), "a summary is a batch record");
_Static_assert(sizeof(struct h2c_sum_key_t) == 24 && sizeof(struct h2c_sum_value_t) == 72,
               "the user space reads the summaries by this layout (pkg/accesslog/events/summary.go)");

// 400 connections x 8 streams x 2 directions at once, with the entries of the old epoch until they are
// drained, fit with room; preallocated, about 2.3MB
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct h2c_sum_key_t);
    __type(value, struct h2c_sum_value_t);
} h2c_sum_map SEC(".maps");

// the epoch the new entries are made in (bit 0), flipped by the user space
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} h2c_sum_epoch_map SEC(".maps");

// the keys and the value a new entry is written from, per CPU: the programs they are used in have no stack
// to spare
struct h2c_sum_scratch_t {
    struct h2c_sum_key_t call_key;
    struct h2c_sum_key_t emit_key;
    struct h2c_sum_value_t init;
    // the run in front of a positional upload (syscalls/h2c.h h2c_handle_call), from where it is decided to the
    // upload (in h2c.h, or by the caller in transfer.h): every upload that may follow takes it (and clears it),
    // so it is never left for another call
    __u64 pos_run;
    // in the same way, what the follower knows of the frames of the call (upload_data_args_ext_set_h2c_frames),
    // set for a call inside a DATA payload and for a call it walked, 0 for any other
    __u32 pos_frames;
    __u32 pos_pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct h2c_sum_scratch_t);
    __uint(max_entries, 1);
} h2c_sum_scratch_map SEC(".maps");

static __always_inline struct h2c_sum_scratch_t *h2c_sum_scratch() {
    __u32 kZero = 0;
    return bpf_map_lookup_elem(&h2c_sum_scratch_map, &kZero);
}

static __always_inline void h2c_set_pos_frames(__u32 frames) {
    struct h2c_sum_scratch_t *scratch = h2c_sum_scratch();
    if (scratch != NULL) {
        scratch->pos_frames = frames;
    }
}

// h2c_clear_pos forgets what was left for an upload that does not come (the call was summarized)
static __always_inline void h2c_clear_pos() {
    struct h2c_sum_scratch_t *scratch = h2c_sum_scratch();
    if (scratch != NULL) {
        scratch->pos_run = 0;
        scratch->pos_frames = 0;
    }
}

// h2c_take_pos sets the run and the frames h2c_handle_call left for the positional upload into its extension
// (nothing: no run, frames not known), and clears them
static __always_inline void h2c_take_pos(struct upload_data_args_ext *ext) {
    struct h2c_sum_scratch_t *scratch = h2c_sum_scratch();
    if (scratch == NULL) {
        return;
    }
    upload_data_args_ext_set_sum_run(ext, scratch->pos_run);
    upload_data_args_ext_set_h2c_frames(ext, scratch->pos_frames);
    scratch->pos_run = 0;
    scratch->pos_frames = 0;
}



static __always_inline __u8 h2c_sum_epoch() {
    __u32 kZero = 0;
    __u32 *epoch = bpf_map_lookup_elem(&h2c_sum_epoch_map, &kZero);
    return epoch != NULL ? (*epoch & 1) : 0;
}

// h2c_sum_minute is the wall clock minute of a BPF time, as host.SameMinute computes it
static __always_inline __u32 h2c_sum_minute(__u64 t) {
    return (boot_time_unix_ns + t) / 60000000000ULL;
}

// h2c_sum_emit sends the summary of the key as a record of the per-CPU batch and deletes its entry. The
// record is filled before the delete: when the delete fails, the user space drained the entry in between and
// has it, so the record is taken back. It returns 1 when the summary was sent. An entry that gets no record
// (a CPU that does not batch) stays for the flush.
static __noinline int h2c_sum_emit(void *ctx, struct h2c_sum_key_t *key, __u32 reason) {
    struct h2c_sum_value_t *v = bpf_map_lookup_elem(&h2c_sum_map, key);
    if (v == NULL) {
        return 0;
    }
    struct h2c_batch_record_t *slot = h2c_batch_reserve(ctx, bpf_ktime_get_ns());
    if (slot == NULL) {
        return 0;
    }
    struct h2c_sum_record_t *rec = (struct h2c_sum_record_t *)slot;
    rec->kind = H2C_BATCH_KIND_SUMMARY;
    rec->direction = key->direction;
    rec->reason = reason;
    rec->epoch = key->epoch;
    rec->stream = key->stream;
    rec->conid = key->conid;
    rec->random_id = key->random_id;
    __builtin_memcpy(&rec->value, v, sizeof(rec->value));
    rec->pad[0] = 0;
    rec->pad[1] = 0;
    if (bpf_map_delete_elem(&h2c_sum_map, key) != 0) {
        struct h2c_batch_t *b = h2c_batch_get();
        if (b != NULL && b->count > 0) {
            b->count--;
        }
        return 0;
    }
    return 1;
}

// h2c_sum_emit_stream sends the summaries of a stream's direction of both epochs (the old one may not be
// drained yet). direction_reason is the direction | the reason << 8.
static __noinline int h2c_sum_emit_stream(void *ctx, __u64 conid, __u64 random_id, __u32 stream, __u32 direction_reason) {
    struct h2c_sum_scratch_t *scratch = h2c_sum_scratch();
    if (scratch == NULL) {
        return 0;
    }
    struct h2c_sum_key_t *key = &scratch->emit_key;
    key->conid = conid;
    key->random_id = random_id;
    key->stream = stream;
    key->direction = direction_reason & 0xff;
    key->pad = 0;
    __u32 reason = (direction_reason >> 8) & 0xff;
    key->epoch = 0;
    h2c_sum_emit(ctx, key, reason);
    key->epoch = 1;
    h2c_sum_emit(ctx, key, reason);
    return 0;
}

// h2c_sum_close sends what the closing connection's directions summarize of their current stream, before the
// close is notified. The entries it cannot reach (other streams, other minutes) are drained by the user space
// for the closed connection.
static __noinline int h2c_sum_close(void *ctx, __u64 conid, __u64 random_id) {
    if (!h2c_summarizing()) {
        return 0;
    }
    struct h2c_stream_t *stream = bpf_map_lookup_elem(&h2c_stream_map, &conid);
    if (stream == NULL || stream->random_id != random_id || stream->mode != H2C_STREAM_HTTP2) {
        return 0;
    }
    if (stream->dir[0].stream_known != 0) {
        h2c_sum_emit_stream(ctx, conid, random_id, stream->dir[0].stream,
                            SOCK_DATA_DIRECTION_INGRESS | (H2C_SUM_REASON_CLOSE << 8));
    }
    if (stream->dir[1].stream_known != 0) {
        h2c_sum_emit_stream(ctx, conid, random_id, stream->dir[1].stream,
                            SOCK_DATA_DIRECTION_EGRESS | (H2C_SUM_REASON_CLOSE << 8));
    }
    return 0;
}

