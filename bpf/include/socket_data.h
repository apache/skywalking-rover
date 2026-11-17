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

#include "socket_opts.h"
#include "protocol_analyzer.h"
#include "queue.h"

// per socket call at most SOCKET_UPLOAD_CHUNK_LIMIT x SOCKET_UPLOAD_CHUNK_SIZE (6 x 20480B = 120KB)
// bytes are uploaded; a larger call is truncated (have_reduce_after_chunk) and its real length stays in
// total_size. The chunk body is unrolled into every syscall exit, every TLS uretprobe and the network
// profiling probes, so the limit is bounded by what the verifier accepts. Measured on 6.1 (worst
// program, of the 1M processed instruction budget): 6 chunks 203K, 7 chunks 440K, 8 chunks 753K; 9 and
// above are rejected for exceeding the 512 byte stack depth of the inlined call chain, and then no
// upload program loads at all. 6 keeps the margin for other kernels and architectures.
#define SOCKET_UPLOAD_CHUNK_LIMIT 6

// SOCKET_UPLOAD_CHUNK_SIZE is the number of bytes a single chunk uploads
#define SOCKET_UPLOAD_CHUNK_SIZE MAX_TRANSMIT_SOCKET_READ_LENGTH

// the verifier hint on the offset inside an iov entry (see UPLOAD_PER_SOCKET_DATA_IOV) must never
// truncate a real offset
_Static_assert(SOCKET_UPLOAD_CHUNK_LIMIT * SOCKET_UPLOAD_CHUNK_SIZE <= 0x1ffff,
               "the iov offset hint 0x1ffff is smaller than the bytes a socket call can upload");

// the event layout, see socket_data_event.h
#include <socket_data_event.h>

// A perf record is framed by an 8 byte perf_event_header whose size field is a __u16, plus a 4 byte
// raw length, and the whole record is padded to 8 bytes: it can never reach 65536. Measured on 6.1,
// a payload of 65508 bytes is delivered and 65520 is dropped without a trace, which is the arithmetic
// above. The bound is the perf ABI, so it is the same on every supported kernel.
_Static_assert(sizeof(struct socket_data_upload_event) + 12 <= 65500,
               "the socket data event does not fit in a perf record");
DATA_QUEUE(socket_data_upload_queue);

struct socket_data_sequence_t {
    __u64 data_id;
    __u16 sequence;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1000);
	__type(key, __u64);
	__type(value, struct socket_data_sequence_t);
} socket_data_sequence_generator SEC(".maps");
static __inline __u16 generate_socket_sequence(__u64 conid, __u64 data_id) {
    struct socket_data_sequence_t *seq = bpf_map_lookup_elem(&socket_data_sequence_generator, &conid);
    if (seq == NULL) {
        struct socket_data_sequence_t data = {};
        data.data_id = data_id;
        data.sequence = 0;
        bpf_map_update_elem(&socket_data_sequence_generator, &conid, &data, BPF_NOEXIST);
        return 0;
    }
    if (seq->data_id != data_id) {
        seq->data_id = data_id;
        seq->sequence = 0;
    } else {
        seq->sequence++;
    }
    return seq->sequence;
}

struct upload_data_args {
    __u64 start_time;
    __u64 end_time;
    __u64 con_id;
    __u64 random_id;

    __u64 socket_data_id;
    __u64 prev_socket_data_id;
    struct iovec *socket_data_iovec;
    size_t socket_data_iovlen;
    ssize_t bytes_count;
    char* socket_data_buf;

    __u32 data_direction;
    __u8 connection_protocol;
    __u8 connection_ssl;
    __u8 socket_ssl_buffer_force_unfinished;
    // skip data upload when the protocol break(such as HTTP2)
    __u8 connection_skip_data_upload;
    bool socket_data_ssl;
    // the values of the event fields an extension adds, see socket_data_event.h
    struct upload_data_args_ext ext;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct upload_data_args);
    __uint(max_entries, 1);
} socket_data_upload_args_per_cpu_map SEC(".maps");
static __always_inline struct upload_data_args* generate_socket_upload_args() {
    __u32 kZero = 0;
    return bpf_map_lookup_elem(&socket_data_upload_args_per_cpu_map, &kZero);
}

// fill_socket_data_event sets the fields every socket data event takes from its socket call; the chunks
// of the call only set the chunk fields and the buffer
static __always_inline void fill_socket_data_event(struct socket_data_upload_event *event, struct upload_data_args *args,
                                                   __u8 protocol) {
    event->protocol = protocol;
    event->start_time = args->start_time;
    event->end_time = args->end_time;
    event->direction = args->data_direction;
    event->conid = args->con_id;
    event->randomid = args->random_id;
    event->total_size = args->bytes_count;
    event->data_id = args->socket_data_id;
    // only an h2c call inside a DATA payload is uploaded without its content (syscalls/h2c.h), and the
    // scratch event is shared by every upload of the CPU
    event->payload_skipped = 0;
    fill_socket_data_event_ext(event, &args->ext);
}

static __always_inline void __upload_socket_data_with_buffer(void *ctx, __u8 index, char* buf, size_t size, __u32 is_finished, __u8 have_reduce_after_chunk, struct socket_data_upload_event *event) {
    if (size > sizeof(event->buffer)) {
        size = sizeof(event->buffer);
    }
    if (size <= 0) {
        return;
    }

    event->sequence = index;
    event->data_len = size;
    event->finished = is_finished;
    event->have_reduce_after_chunk = have_reduce_after_chunk;
    // The read and the perf record take their size back from data_len, through a load of its own, and
    // bound that copy for the verifier. A helper's size has to be known exactly to the verifier, and
    // through size that would reach back into the chunk arithmetic of every unrolled chunk (need,
    // already_send) and keep the verifier from ever merging their paths, which lifts the biggest
    // upload programs over the 1M instruction limit on 6.12. The clamp is exact: data_len is the
    // chunk size, at most 20480. It also has to be there: 5.5 cannot derive that bound by itself.
    __u64 len = *(volatile __u16 *)&event->data_len;
    if (len > MAX_TRANSMIT_SOCKET_READ_LENGTH) {
        len = MAX_TRANSMIT_SOCKET_READ_LENGTH;
    }
    bpf_probe_read(&event->buffer, len, buf);
    // only the bytes that were read are sent: the event is fixed size in the scratch map, but a perf
    // record that always carries the whole buffer costs 20568 bytes for a 100 byte message, which is
    // what the per CPU ring buffer fills up with. The reader takes data_len bytes, see the Go side.
    rover_submit_buf(ctx, &socket_data_upload_queue, event,
                     __builtin_offsetof(struct socket_data_upload_event, buffer) + len);
}

static __noinline void upload_socket_data_buf(void *ctx, char* buf, ssize_t size, struct socket_data_upload_event *event, __u8 force_unfinished) {
    ssize_t already_send = 0;
#pragma unroll
    for (__u8 index = 0; index < SOCKET_UPLOAD_CHUNK_LIMIT; index++) {
        // calculate bytes need to send
        ssize_t remaining = size - already_send;
        size_t need_send_in_chunk = 0;
        __u8 have_reduce_after_chunk = 0;
        if (remaining > SOCKET_UPLOAD_CHUNK_SIZE) {
            need_send_in_chunk = SOCKET_UPLOAD_CHUNK_SIZE;
            have_reduce_after_chunk = 1;
        } else {
            need_send_in_chunk = remaining;
        }

        __u32 is_finished = (need_send_in_chunk + already_send) >= size || index == (SOCKET_UPLOAD_CHUNK_LIMIT - 1) ? true : false;
        __u8 sequence = index;
        if (force_unfinished == 1 && need_send_in_chunk > 0) {
            is_finished = 0;
            sequence = generate_socket_sequence(event->conid, event->data_id);
        }
        __upload_socket_data_with_buffer(ctx, sequence, buf + already_send, need_send_in_chunk, is_finished, have_reduce_after_chunk, event);
        already_send += need_send_in_chunk;
    }
}

#define UPLOAD_PER_SOCKET_DATA_IOV() \
if (iov_index < iovlen) {                                                   \
    struct iovec cur_iov;                                                   \
    bpf_probe_read(&cur_iov, sizeof(cur_iov), &iov[iov_index]);             \
    size_t need_send_in_chunk = size - already_send;                        \
    size_t avail_in_iov = cur_iov.iov_len - cur_iov_sended;                 \
    if (need_send_in_chunk > avail_in_iov) {                                \
        need_send_in_chunk = avail_in_iov;                                  \
    }                                                                       \
    if (need_send_in_chunk > SOCKET_UPLOAD_CHUNK_SIZE) {                    \
        need_send_in_chunk = SOCKET_UPLOAD_CHUNK_SIZE;                      \
    }                                                                       \
    char *chunk_base = (char *)cur_iov.iov_base + cur_iov_sended;           \
    already_send += need_send_in_chunk;                                     \
    /* keep the offset inside the entry when the chunk only covers a part of it, otherwise every   \
       following chunk re-reads the entry from its beginning and the entries behind it are never   \
       uploaded, while the byte count still adds up to the size of the syscall */                  \
    cur_iov_sended += need_send_in_chunk;                                   \
    /* neither counter can grow past SOCKET_UPLOAD_CHUNK_LIMIT x SOCKET_UPLOAD_CHUNK_SIZE, so the   \
       masks never change a real value; telling the bound to the verifier keeps it from exploring   \
       every chunk body with an unbounded offset, which otherwise lifts the biggest upload programs \
       over the 1M processed instruction limit */                                                   \
    asm volatile("%[v] &= 0x1ffff;\n" ::[v] "+r"(already_send) :);          \
    asm volatile("%[v] &= 0x1ffff;\n" ::[v] "+r"(cur_iov_sended) :);        \
    if (cur_iov_sended >= cur_iov.iov_len) {                                \
        iov_index++;                                                        \
        cur_iov_sended = 0;                                                 \
    }                                                                       \
    /* the data that does not fit into the remaining chunks is only signaled by the flag on the     \
       finished chunk, so it must be derived from what is really left, not from one entry */        \
    __u8 have_reduce_after_chunk = already_send < size ? 1 : 0;             \
    __u32 is_finished = already_send >= size || loop_count == (SOCKET_UPLOAD_CHUNK_LIMIT - 1) ? true : false;  \
    __upload_socket_data_with_buffer(ctx, loop_count, chunk_base, need_send_in_chunk, is_finished, have_reduce_after_chunk, event);      \
    loop_count++;                                                                                                                    \
}

#ifdef SOCKET_DATA_ACCESS_LOG
// (access log) The chunks of a call made with an iov are filled across its entries: one chunk takes as many entries as
// fit into it, so the bytes of a call up to SOCKET_UPLOAD_CHUNK_LIMIT chunks are uploaded whatever the number of its
// entries (a writer of many small buffers, Netty's or Envoy's writev, puts frame headers into the entries far behind the
// sixth). The walk goes through the entries in steps of at most SOCKET_UPLOAD_IOV_PIECE bytes, at most
// SOCKET_UPLOAD_IOV_STEPS of them: a call with more entries than the steps reach is uploaded up to there, cut as one
// that passes the limit. Its state is kept in a per CPU map, where the verifier does not track it, so the loop is
// verified once, and the copy into the chunk is bounded below the scratch event (rover_data_heap) for the verifier: a
// piece is at most half a chunk.
#define SOCKET_UPLOAD_IOV_STEPS 32
#define SOCKET_UPLOAD_IOV_PIECE (SOCKET_UPLOAD_CHUNK_SIZE / 2)
struct socket_upload_iov_t {
    __u64 sent;
    __u64 fill;
    __u64 seq;
    __u64 index;
    __u64 offset;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_upload_iov_t);
    __uint(max_entries, 1);
} socket_upload_iov_map SEC(".maps");
_Static_assert(__builtin_offsetof(struct socket_data_upload_event, buffer) + SOCKET_UPLOAD_CHUNK_SIZE + SOCKET_UPLOAD_IOV_PIECE <= 30960,
               "a piece copied behind a part of a chunk stays in the scratch event");

// branch-free tests of the walk (values below 2^63): a branch on a value the verifier does not know is a state it
// explores, and the walk body is verified once per step
static __always_inline __u64 socket_iov_lt(__u64 a, __u64 b) {
    __u64 d = a - b;
    asm volatile("%[v] >>= 63;\n" : [v] "+r"(d));
    return d;
}
static __always_inline __u64 socket_iov_min(__u64 a, __u64 b) {
    return b ^ ((a ^ b) & (0 - socket_iov_lt(a, b)));
}

static __noinline void upload_socket_data_iov(void *ctx, struct iovec* iov, const size_t iovlen, ssize_t size, struct socket_data_upload_event *event) {
    __u32 kZero = 0;
    struct socket_upload_iov_t *w = bpf_map_lookup_elem(&socket_upload_iov_map, &kZero);
    if (w == NULL) {
        return;
    }
    w->sent = 0;
    w->fill = 0;
    w->seq = 0;
    w->index = 0;
    w->offset = 0;
    __u64 total = size;
    __u64 entries = iovlen;
#pragma clang loop unroll(disable)
    for (int i = 0; i < SOCKET_UPLOAD_IOV_STEPS; i++) {
        __u64 sent = *(volatile __u64 *)&w->sent;
        __u64 fill = *(volatile __u64 *)&w->fill;
        __u64 seq = *(volatile __u64 *)&w->seq;
        __u64 index = *(volatile __u64 *)&w->index;
        __u64 offset = *(volatile __u64 *)&w->offset;
        // done: every chunk sent, every byte, every entry
        if ((socket_iov_lt(seq, SOCKET_UPLOAD_CHUNK_LIMIT) & socket_iov_lt(sent, total) & socket_iov_lt(index, entries)) == 0) {
            break;
        }
        struct iovec cur = {};
        bpf_probe_read(&cur, sizeof(cur), &iov[index & 0xffff]);
        __u64 len = cur.iov_len;
        // what is left of the entry, of the chunk, of the call, without a branch
        __u64 n = (len - offset) & (0 - socket_iov_lt(offset, len));
        n = socket_iov_min(n, SOCKET_UPLOAD_CHUNK_SIZE - fill);
        n = socket_iov_min(n, total - sent);
        // the bounds of the copy for the verifier (exact: fill never passes the chunk, a piece is at most half one),
        // each in the register it is then used from (5.5 keeps a bound only there)
        asm volatile("if %[v] < %[max] goto +1\n%[v] = %[last]\n"
                     : [v] "+r"(fill) : [max] "i"(SOCKET_UPLOAD_CHUNK_SIZE + 1), [last] "i"(SOCKET_UPLOAD_CHUNK_SIZE));
        asm volatile("if %[v] < %[max] goto +1\n%[v] = %[last]\n"
                     : [v] "+r"(n) : [max] "i"(SOCKET_UPLOAD_IOV_PIECE + 1), [last] "i"(SOCKET_UPLOAD_IOV_PIECE));
        bpf_probe_read(&event->buffer[fill], n, (char *)cur.iov_base + offset);
        fill += n;
        sent += n;
        offset += n;
        // the entry is done: the next one
        __u64 next = 1 - socket_iov_lt(offset, len);
        index += next;
        offset &= next - 1;
        __u64 more = socket_iov_lt(fill, SOCKET_UPLOAD_CHUNK_SIZE) & socket_iov_lt(sent, total) & socket_iov_lt(index, entries) &
                     socket_iov_lt(i, SOCKET_UPLOAD_IOV_STEPS - 1);
        if (more == 0) {
            // the chunk is full, or the last of the call: it goes
            __u64 reduce = socket_iov_lt(sent, total);
            event->sequence = seq;
            event->data_len = fill;
            event->finished = (reduce ^ 1) | (1 - socket_iov_lt(seq, SOCKET_UPLOAD_CHUNK_LIMIT - 1)) |
                              (1 - socket_iov_lt(index, entries)) | (1 - socket_iov_lt(i, SOCKET_UPLOAD_IOV_STEPS - 1));
            event->have_reduce_after_chunk = reduce;
            // the size of the record is taken back from data_len, as in __upload_socket_data_with_buffer
            __u64 bytes = *(volatile __u16 *)&event->data_len;
            if (bytes > SOCKET_UPLOAD_CHUNK_SIZE) {
                bytes = SOCKET_UPLOAD_CHUNK_SIZE;
            }
            rover_submit_buf(ctx, &socket_data_upload_queue, event, __builtin_offsetof(struct socket_data_upload_event, buffer) + bytes);
            seq++;
            fill = 0;
        }
        w->sent = sent;
        w->fill = fill;
        w->seq = seq;
        w->index = index;
        w->offset = offset;
    }
}
#else
static __noinline void upload_socket_data_iov(void *ctx, struct iovec* iov, const size_t iovlen, ssize_t size, struct socket_data_upload_event *event) {
    ssize_t already_send = 0;
    size_t cur_iov_sended = 0;
    __u8 iov_index = 0;
    __u8 loop_count = 0;

    // each count is same with SOCKET_UPLOAD_CHUNK_LIMIT
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
}
#endif

struct socket_data_last_id_t {
    __u64 random_id;
    __u64 socket_data_id;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct socket_data_last_id_t);
} socket_data_last_id_map SEC(".maps");

// socket_data_store_last makes the call data_id the last upload of the connection: in the entry the caller looked up
// (latest) when it is the connection's, otherwise by an update. An update of an LRU entry that exists replaces it
// with a new element and frees the old one (under the lock of the global LRU list for a map shared by the CPUs), and
// the freed element can be taken by another key at once, under a reader that still holds it; a store in place
// does neither. The value is one word, stored whole.
static __always_inline void socket_data_store_last(__u64 *conid, __u64 random_id, __u64 data_id, struct socket_data_last_id_t *latest) {
    if (latest != NULL && latest->random_id == random_id) {
        *(volatile __u64 *)&latest->socket_data_id = data_id;
        return;
    }
    struct socket_data_last_id_t data = {};
    data.random_id = random_id;
    data.socket_data_id = data_id;
    bpf_map_update_elem(&socket_data_last_id_map, conid, &data, BPF_ANY);
}

// socket_data_last_upload returns the last uploaded call of the connection, and in prev its data id when
// it belongs to this connection (0 otherwise): the previous data id of the next upload
static __always_inline struct socket_data_last_id_t *socket_data_last_upload(__u64 conid, __u64 random_id, __u64 *prev) {
    struct socket_data_last_id_t *latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    *prev = 0;
    if (latest != NULL && latest->random_id == random_id) {
        *prev = latest->socket_data_id;
    }
    return latest;
}

#ifdef SOCKET_DATA_ACCESS_LOG
// The chain of the uploads of a connection (access log). An upload names the upload before it (prev_data_id), which
// the user space links by: an event whose previous one has arrived is linked, and the parser goes on through it.
// socket_data_last_id_map alone does not make a chain of the uploads of calls made at once on two CPUs (a read and a
// write of the connection): both read the last upload P before either writes itself there, both name P, and only
// one of them is named by the next upload. The other one is in the chain of nothing behind it, and when it comes
// later than the call that follows it in its direction, the parser has gone past it and skips it (late), which can
// desynchronize the HPACK decoder of the direction for good.
// So an upload claims the place behind its previous one: socket_data_link_map holds, for an upload P of the
// connection, the data id of the upload that named it. The insert that does not find P taken makes the upload P's
// successor; one that finds P taken follows the chain to its end (the claim of P, then the claim of that one, ...)
// and claims the place there. The hash map serializes the inserts of one key, which the kernels the access log
// supports have no other way to (no atomic exchange before 5.12, no spin lock in tracing programs). Every upload is
// then named by at most one, and every one but the last by exactly one, whatever order the calls end and write
// socket_data_last_id_map in, which stays where an upload starts looking (it is almost always the end of the chain).
// The chain does not follow the data ids then: an upload may name one with a larger data id, which the user space
// links the same way. Calls summarised or dropped take no place, as they upload nothing.
struct socket_data_link_t {
    __u64 conid;
    __u64 random_id;
    __u64 prev;
};
// A claim is only needed while the calls of a connection race (microseconds), and nothing deletes one: the map
// stays full and every insert evicts. The LRU lists are per CPU (BPF_F_NO_COMMON_LRU, 4.10+), so an insert evicts
// from its own CPU's list without the lock of a global one; each CPU holds max_entries / the possible CPUs of the
// claims, 4096 of them with 32, which at 20 thousand uploads a second on a CPU keep a claim about 200ms.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
	__type(key, struct socket_data_link_t);
	__type(value, __u64);
} socket_data_link_map SEC(".maps");
// the claims an upload follows at most (one per upload made at once with it)
#define SOCKET_DATA_LINK_FOLLOW 16

// The chain by atomic exchange (kernels with BPF_XCHG, 5.12+): an upload swaps its data id into the last upload
// of the connection and names what it took out. The exchanges of one word are ordered, so every upload is named by at
// most one and every one but the last by exactly one, as the claims make it, in the order of the exchanges instead of
// the claims, and without an insert into socket_data_link_map (an LRU map kept full, every insert evicts: about 2 us an
// upload measured on 6.12). The place is taken at once, so the store of the last upload behind the upload is not made
// (socket_data_store_after_chain). Without an entry of the connection the upload inserts one (BPF_NOEXIST: one first
// upload names 0, another one exchanges into it); the entry of an earlier connection of the conid (a reused fd whose
// close was not seen) is replaced by the one upload that claims the place behind 0 in socket_data_link_map, as the
// claims elect it, while the others wait for its entry and exchange into it. A run without races names exactly what
// the claims name; the only other difference: an upload after its connection's entry was evicted from the map (10000
// connections) names 0 instead of the end of the claims behind 0, which the claims only still hold for some 200 ms.
// upload_xchg_on is set by the loader where the kernel has the instruction (a probe); it is a constant of the load:
// the kernels before 5.12, which refuse the instruction, never verify it (the branch is dead and removed).
volatile const __u32 upload_xchg_on;
#define SOCKET_DATA_CHAIN_XCHG (upload_xchg_on != 0)
// the uploads that wait for the entry of the upload that replaced the entry of an earlier connection look it up at most
// that many times (the winner is a few instructions from its insert, on a CPU that runs it without preemption)
#define SOCKET_DATA_CHAIN_WAIT 256

// socket_data_store_after_chain is the store of an upload into socket_data_last_id_map once it is uploaded (only for the
// claims: the exchange took the place already)
static __always_inline void socket_data_store_after_chain(__u64 *conid, __u64 random_id, __u64 data_id, struct socket_data_last_id_t *latest) {
    if (SOCKET_DATA_CHAIN_XCHG) {
        return;
    }
    if (latest == NULL || latest->socket_data_id != data_id) {
        socket_data_store_last(conid, random_id, data_id, latest);
    }
}

// the compare-and-exchanges socket_data_store_last_forward tries at most (each failed one saw another upload's
// exchange; a few in a row are already a burst of concurrent uploads that moved the entry past data_id anyway)
#define SOCKET_DATA_FORWARD_RETRIES 4

// socket_data_store_last_forward moves the last upload of the connection forward to data_id, never back: for an
// event that takes the place of a call made earlier (a held frame header, a held HTTP/1 run), while the other
// direction may have uploaded a later call since. With the exchange (5.12+) the uploads of the connection swap
// their data ids into the entry at any time, so a plain check-then-store could overwrite the id of an upload
// that exchanged in between, which no upload would name then (the parser would take it for late): the move is a
// compare-and-exchange that only replaces a smaller id. Without the exchange the uploads store after the fact
// (socket_data_store_after_chain) and the store stays plain.
static __always_inline void socket_data_store_last_forward(__u64 *conid, __u64 random_id, __u64 data_id,
                                                           struct socket_data_last_id_t *latest) {
    if (SOCKET_DATA_CHAIN_XCHG && latest != NULL && latest->random_id == random_id) {
        __u64 cur = *(volatile __u64 *)&latest->socket_data_id;
#pragma clang loop unroll(disable)
        for (int i = 0; i < SOCKET_DATA_FORWARD_RETRIES; i++) {
            if (cur >= data_id) {
                break;
            }
            __u64 seen = __sync_val_compare_and_swap(&latest->socket_data_id, cur, data_id);
            if (seen == cur) {
                break;
            }
            cur = seen;
        }
        return;
    }
    if (latest == NULL || latest->random_id != random_id || latest->socket_data_id < data_id) {
        socket_data_store_last(conid, random_id, data_id, latest);
    }
}

static __always_inline struct socket_data_last_id_t *socket_data_chain_xchg(__u64 conid, __u64 random_id, __u64 data_id, __u64 *prev) {
    *prev = 0;
    struct socket_data_last_id_t *latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    if (latest == NULL) {
        struct socket_data_last_id_t data = {};
        data.random_id = random_id;
        data.socket_data_id = data_id;
        if (bpf_map_update_elem(&socket_data_last_id_map, &conid, &data, BPF_NOEXIST) == 0) {
            // the first upload (or the first since the entry was evicted)
            return bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
        }
        latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    }
    if (latest != NULL && latest->random_id == random_id) {
        *prev = __sync_lock_test_and_set(&latest->socket_data_id, data_id);
        return latest;
    }
    // the entry of an earlier connection of the conid: the upload that claims the place behind 0 replaces it
    struct socket_data_link_t link = {};
    link.conid = conid;
    link.random_id = random_id;
    link.prev = 0;
    if (bpf_map_update_elem(&socket_data_link_map, &link, &data_id, BPF_NOEXIST) == 0) {
        struct socket_data_last_id_t data = {};
        data.random_id = random_id;
        data.socket_data_id = data_id;
        bpf_map_update_elem(&socket_data_last_id_map, &conid, &data, BPF_ANY);
        return bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
    }
#pragma clang loop unroll(disable)
    for (int i = 0; i < SOCKET_DATA_CHAIN_WAIT; i++) {
        latest = bpf_map_lookup_elem(&socket_data_last_id_map, &conid);
        if (latest != NULL && latest->random_id == random_id) {
            *prev = __sync_lock_test_and_set(&latest->socket_data_id, data_id);
            return latest;
        }
    }
    // (never seen: the winner's entry did not come) named behind the winner, as the claims would
    __u64 *winner = bpf_map_lookup_elem(&socket_data_link_map, &link);
    if (winner != NULL) {
        *prev = *winner;
    }
    return NULL;
}

// socket_data_chain_upload is socket_data_last_upload for an upload of the call data_id that names its previous
// upload: prev is the place in the chain it claimed
static __noinline struct socket_data_last_id_t *socket_data_chain_upload(__u64 conid, __u64 random_id, __u64 data_id, __u64 *prev) {
    if (SOCKET_DATA_CHAIN_XCHG) {
        return socket_data_chain_xchg(conid, random_id, data_id, prev);
    }
    struct socket_data_last_id_t *latest = socket_data_last_upload(conid, random_id, prev);
    struct socket_data_link_t link = {};
    link.conid = conid;
    link.random_id = random_id;
    __u64 at = *prev;
#pragma clang loop unroll(disable)
    for (int i = 0; i < SOCKET_DATA_LINK_FOLLOW; i++) {
        link.prev = at;
        if (bpf_map_update_elem(&socket_data_link_map, &link, &data_id, BPF_NOEXIST) == 0) {
            break;
        }
        __u64 *next = bpf_map_lookup_elem(&socket_data_link_map, &link);
        if (next == NULL) {
            // the claim went (evicted) in between: claim again
            continue;
        }
        __u64 behind = *next;
        if (behind == data_id) {
            break;
        }
        at = behind;
    }
    *prev = at;
    return latest;
}
#else
#define socket_data_chain_upload(conid, random_id, data_id, prev) socket_data_last_upload(conid, random_id, prev)
static __always_inline void socket_data_store_after_chain(__u64 *conid, __u64 random_id, __u64 data_id, struct socket_data_last_id_t *latest) {
    if (latest == NULL || latest->socket_data_id != data_id) {
        socket_data_store_last(conid, random_id, data_id, latest);
    }
}
#endif

static __inline void upload_socket_data(void *ctx, struct upload_data_args *args) {
    // must have protocol and ssl must same(plain)
    if (args->connection_ssl != args->socket_data_ssl) {
        return;
    }
    // if the connection data is needs to skip upload, then the content is not uploaded
    bool upload_content = args->connection_protocol != CONNECTION_PROTOCOL_UNKNOWN && args->connection_skip_data_upload != 1;
    if (upload_content == false && socket_data_upload_without_content() == false) {
        return;
    }
    // one event for every chunk of the call: the fields of the call are filled once, each chunk sets its own.
    // This relies on rover_reserve_buf handing out a scratch buffer that each submit copies into the perf
    // buffer (queue.h): a ring buffer reservation could be submitted only once.
    struct socket_data_upload_event *socket_data_event;
    socket_data_event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*socket_data_event));
    if (socket_data_event == NULL) {
        return;
    }
    if (upload_content == false) {
        // an event without content for the fields an extension adds, with the protocol unknown to tell that
        // there is no content. The scratch element is shared by every event of this CPU and is not zeroed,
        // so the fields the chunks would have written must be set here.
        fill_socket_data_event(socket_data_event, args, CONNECTION_PROTOCOL_UNKNOWN);
        socket_data_event->sequence = 0;
        socket_data_event->data_len = 0;
        socket_data_event->finished = 1;
        socket_data_event->have_reduce_after_chunk = 0;
        socket_data_event->prev_data_id = 0;
        rover_submit_buf(ctx, &socket_data_upload_queue, socket_data_event,
                         __builtin_offsetof(struct socket_data_upload_event, buffer));
        return;
    }
    fill_socket_data_event(socket_data_event, args, args->connection_protocol);

    __u64 prev_data_id;
    struct socket_data_last_id_t *latest = socket_data_chain_upload(args->con_id, args->random_id, args->socket_data_id, &prev_data_id);
    socket_data_event->prev_data_id = prev_data_id;
    if (args->socket_data_buf != NULL) {
        upload_socket_data_buf(ctx, args->socket_data_buf, args->bytes_count, socket_data_event, args->socket_ssl_buffer_force_unfinished);
    } else if (args->socket_data_iovec != NULL) {
        upload_socket_data_iov(ctx, args->socket_data_iovec, args->socket_data_iovlen, args->bytes_count, socket_data_event);
    }

    socket_data_store_after_chain(&args->con_id, args->random_id, args->socket_data_id, latest);
}