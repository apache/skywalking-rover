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

// Per-CPU batching of the compact records of skipped and tail-cut HTTP/2 DATA calls
// (access_log.protocol_analyze.batch_h2c_records, set with skip_h2c_data_payload and merge_kernel_logs).
//
// Nothing is merged here: every skipped or tail-cut call of a followed HTTP/2 connection still becomes its
// own record, carrying exactly the fields the event it replaces would carry, so the user space feeds each
// record into the connection as that event and its existing kernel-log merge does all merging. Records are
// appended to a per-CPU buffer and sent as ONE perf event (h2c_batch_flush) when the buffer is full, before
// any full upload on the same CPU (so the per-connection data id order of one CPU is kept), on the close of
// a connection with records pending, and on a kick from the user space for idle flushing. A lost batch gaps
// every connection it carried through the lost-samples path, like a lost socket event.
//
// The switch is off by default: with it off not a single record is produced and the socket calls take the
// path they take today.

// access_log.protocol_analyze.batch_h2c_records, set by the user space before any program is attached
volatile __u32 batch_h2c_records;
#define h2c_batching() (batch_h2c_records != 0)

// The idle kick: the user space writes one byte to a dedicated pipe from a goroutine pinned to each CPU, so
// the write runs on that CPU; a write probe recognises the agent's own tgid and that fd and flushes that
// CPU's buffer instead of recording the write as traffic (h2c_batch_kick). batch_kick_fd 0 disables it.
volatile __u32 batch_kick_tgid;
volatile __u32 batch_kick_fd;

#define H2C_BATCH_MAX_RECORDS 64
// a tail-cut call carries the bytes before the DATA payload (the frame header, 9 bytes, sometimes a
// preceding complete frame): a call whose cut prefix is larger is uploaded in whole instead of batched
#define H2C_BATCH_CUT_MAX 16

// the kind of a record
#define H2C_BATCH_KIND_SKIPPED 1
#define H2C_BATCH_KIND_CUT 2

// one socket call: the fields the event it replaces carries (see h2c_upload_skipped_payload and
// h2c_upload_cut in syscalls/h2c.h), plus for a tail-cut call the content bytes before the DATA payload.
// The extension fields (function, L4 counters, ssl, ports, in flight) are kept as the whole
// upload_data_args_ext, exactly as the event carries them, so the user space reads them the same way.
struct h2c_batch_record_t {
    __u8 kind;
    __u8 direction;
    __u8 cut_len;
    __u8 pad0;
    __u32 pad1;
    __u64 start_time;
    __u64 end_time;
    __u64 conid;
    __u64 random_id;
    __u64 data_id;
    __u64 prev_data_id;
    __u64 total_size;
    struct upload_data_args_ext ext;
    __u8 cut_buf[H2C_BATCH_CUT_MAX];
};

// The per-CPU buffer is also the wire event: a flush sends its first bytes (marker, count, then count
// records) straight from the map, with no copy. The user space tells a batch from a socket data upload
// event by the first byte (H2C_BATCH_MARKER, which a real event's protocol is never). pending_since sits
// after the records so it is not part of the sent bytes; it is the BPF time the first record of the current
// buffer was appended (0 when empty), so the idle kick only touches CPUs with records waiting.
#define H2C_BATCH_MARKER 0xBA
struct h2c_batch_t {
    __u8 marker;
    __u8 pad[3];
    __u32 count;
    struct h2c_batch_record_t records[H2C_BATCH_MAX_RECORDS];
    __u64 pending_since;
    // bumped on every flush: a connection direction remembers (cpu, generation) when it adds a record, so a
    // full upload of that connection flushes the buffer only while its own records are still in it
    // (h2c_batch_flush_for). pending_since and generation are after the records, outside the sent bytes.
    __u32 generation;
    __u32 pad2;
    // never used: the bound the verifier puts on the bytes h2c_batch_flush sends lies here (the multiplication by
    // the record size, 112, is two shifts for the compiler, records of 128 bytes for the verifier)
    __u8 slack[1024];
};
_Static_assert(__builtin_offsetof(struct h2c_batch_t, records) + H2C_BATCH_MAX_RECORDS * 128 <= sizeof(struct h2c_batch_t),
               "the slack of a batch covers what the verifier bounds its sent bytes by");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct h2c_batch_t);
    __uint(max_entries, 1);
} h2c_batch_map SEC(".maps");

// A CPU only batches once its idle kick is known to work: the kick (the agent's write, h2c_batch_kick) sets
// this per-CPU flag, and a CPU whose flag is unset uploads its calls as usual instead of batching. So a CPU
// the user space cannot pin and kick (outside the agent's cpuset, or one that comes online after the kicker
// started) never leaves records waiting without a kick to flush them.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} h2c_batch_kickable_map SEC(".maps");

static __always_inline void h2c_batch_set_kickable() {
    __u32 kZero = 0;
    __u32 *flag = bpf_map_lookup_elem(&h2c_batch_kickable_map, &kZero);
    if (flag != NULL) {
        *flag = 1;
    }
}

static __always_inline bool h2c_batch_is_kickable() {
    __u32 kZero = 0;
    __u32 *flag = bpf_map_lookup_elem(&h2c_batch_kickable_map, &kZero);
    return flag != NULL && *flag != 0;
}

// h2c_batch_kick tells whether a write is the agent's own idle-flush kick (its tgid and the dedicated fd);
// the caller then flushes this CPU's buffer and does not record the write as traffic.
static __always_inline bool h2c_batch_kick(__u64 id, __u32 fd) {
    return h2c_batching() && batch_kick_fd != 0 && (__u32)(id >> 32) == batch_kick_tgid && fd == batch_kick_fd;
}

static __always_inline struct h2c_batch_t *h2c_batch_get() {
    __u32 kZero = 0;
    return bpf_map_lookup_elem(&h2c_batch_map, &kZero);
}

// h2c_batch_flush sends the per-CPU buffer as one perf event and empties it. It is a no-op when the buffer
// is empty. Called before a full upload on the CPU, on a full buffer, on close and on a kick.
static __always_inline int h2c_batch_flush(void *ctx) {
    struct h2c_batch_t *b = h2c_batch_get();
    if (b == NULL || b->count == 0) {
        return 0;
    }
    // count is 1..H2C_BATCH_MAX_RECORDS: the verifier then bounds the submit size below by one record and
    // above by all of them (offsetof(records) + MAX * record size, which is value_size - sizeof(pending),
    // so it is always within the map value and needs no mask)
    __u64 count = b->count;
    if (count > H2C_BATCH_MAX_RECORDS) {
        count = H2C_BATCH_MAX_RECORDS;
    }
    b->marker = H2C_BATCH_MARKER;
    b->pad[0] = 0;
    b->pad[1] = 0;
    b->pad[2] = 0;
    // (the compiler multiplies by the record size with shifts, which the verifier bounds above the records:
    // slack holds the difference)
    __u64 submit = __builtin_offsetof(struct h2c_batch_t, records) + count * sizeof(struct h2c_batch_record_t);
    rover_submit_buf(ctx, &socket_data_upload_queue, b, submit);
    // (count is not used behind the submit: keeping it live across it makes the compiler spill it, and the 5.5
    // verifier loses its bounds)
    b->count = 0;
    b->pending_since = 0;
    b->generation++;
    return 1;
}

// h2c_batch_reserve returns the next record slot of the per-CPU buffer to fill, flushing the buffer first
// when it is full. The caller fills the returned record. NULL when the buffer map is missing. A function of its own:
// its caller gets the slot as a pointer (inlined, the compiler may keep the offset of the slot apart, spill it, and
// the 5.5 verifier forgets the bounds of a spilled offset).
static __noinline struct h2c_batch_record_t *h2c_batch_reserve(void *ctx, __u64 now) {
    // do not batch on a CPU whose idle kick is not known to work: its records could wait without a flush
    if (!h2c_batch_is_kickable()) {
        return NULL;
    }
    struct h2c_batch_t *b = h2c_batch_get();
    if (b == NULL) {
        return NULL;
    }
    if (b->count >= H2C_BATCH_MAX_RECORDS) {
        h2c_batch_flush(ctx);
        b = h2c_batch_get();
        if (b == NULL) {
            return NULL;
        }
    }
    __u32 idx = b->count;
    idx &= (H2C_BATCH_MAX_RECORDS - 1);
    if (b->count == 0) {
        b->pending_since = now;
    }
    b->count = idx + 1;
    return &b->records[idx];
}

// h2c_batch_mark records on the direction of the connection that it just added a record to the current per-CPU
// buffer, as (cpu + 1, generation): a later full upload of this connection flushes the buffer only while this is
// still the current buffer (h2c_batch_flush_for).
static __always_inline void h2c_batch_mark(struct h2c_stream_t *stream, __u32 data_direction) {
    struct h2c_batch_t *b = h2c_batch_get();
    if (b != NULL) {
        __u32 d = (data_direction - 1) & 1;
        stream->batch_cpu[d] = bpf_get_smp_processor_id() + 1;
        stream->batch_gen[d] = b->generation;
    }
}

// h2c_batch_flush_for flushes the per-CPU buffer before a full upload of this connection, but only when the records
// of a direction of it are still in the current buffer of this CPU (same cpu and generation). Records on another
// CPU, or from an older generation, are covered by the idle kick and the user-space gap wait (the ordering argument,
// case 2), so they do not force a flush here. The marks of this CPU are then cleared; a mark of another CPU stays,
// for the uploads of the connection on that CPU.
static __always_inline void h2c_batch_flush_for(void *ctx, struct h2c_stream_t *stream) {
    __u32 c0 = stream->batch_cpu[0];
    __u32 c1 = stream->batch_cpu[1];
    if ((c0 | c1) == 0) {
        return;
    }
    __u32 cpu = bpf_get_smp_processor_id() + 1;
    if (c0 != cpu && c1 != cpu) {
        return;
    }
    struct h2c_batch_t *b = h2c_batch_get();
    if (b != NULL && ((c0 == cpu && stream->batch_gen[0] == b->generation) ||
                      (c1 == cpu && stream->batch_gen[1] == b->generation))) {
        h2c_batch_flush(ctx);
    }
    if (c0 == cpu) {
        stream->batch_cpu[0] = 0;
    }
    if (c1 == cpu) {
        stream->batch_cpu[1] = 0;
    }
}
