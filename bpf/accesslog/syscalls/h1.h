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

// HTTP/1 bodies (access_log.protocol_analyze.skip_http1_body_payload_bpf)
//
// The user space HTTP/1 analyzer reads nothing from the data of a body: it counts the bytes of a body
// framed by Content-Length (buffer.BodyConsumer), and of a chunked one it parses the framing (the size
// lines, the line breaks, the trailers) but only counts the data of the chunks; the calls behind the head
// of a response delimited by the close it does not read as a body at all (it reads the rest of the call
// of the head, and takes each later call for a message start it does not recognize). Yet bodies carry
// nearly all the bytes of the connections that move data, and every byte uploaded costs a copy into the
// perf buffer, a copy out of it and a pooled buffer while the message is analyzed. With
// skip_http1_body_payload on, a socket call that lies wholly inside a Content-Length body or inside the
// data of one chunk, or that comes behind the head of a response delimited by the close where the analyzer
// would not find a message start in it, is uploaded as the event without content the HTTP/2 DATA payloads
// use (h2c_upload_skipped_payload: data_len 0, total_size the size of the call, payload_skipped), and the
// analyzer counts it without reading it. Every other call is uploaded as before, in whole, the calls that
// hold any framing byte of a chunked body included: the analyzer parses the framing from the bytes as it
// always did, so it never depends on what BPF made of them.
//
// Like the HTTP/2 frames, the bodies are told apart by a cursor that follows the message boundaries of
// each direction from the first byte of the connection (h1_direction_t in h2c_stream_map, which only
// exists for a connection traced from its connect or accept). At a boundary the call starts with a message
// head: its first H1_HEAD_MAX bytes are read and the head is scanned for its end and for the headers that
// frame the body (h1_scan_head), then the cursor follows the body through the following calls: it counts
// the bytes of a Content-Length body down, walks the framing of a chunked body (h1_chunks, a bounded number
// of chunk boundaries per call), and takes every later call of a response delimited by the close as body.
// The cursor frames the messages exactly as the analyzer does (RFC 9112 6.3, reader.Response.HasBody,
// buffer.BodyConsumer): a request has the body its Content-Length or Transfer-Encoding announces (none
// without either); a response to a HEAD request and a 1xx, 204 or 304 response has none whatever it
// announces (an interim 1xx answers no request), any other response the one its Content-Length or
// Transfer-Encoding announces, or one delimited by the close without either. Which request a response
// answers is kept per direction: the requests one direction sent (h1_direction_t.requests, with a bit per
// HEAD request) and the responses the other received, which answer them in order. A response can come
// before the request is counted (the write of the request returned, the peer answered before the exit of
// the write ran): with the request still in flight, its body is decided by the next call of the direction
// (H1_DEFERRED). Whenever the cursor cannot tell where the next message starts the direction is lost for
// good, as an HTTP/2 one: a head it cannot read whole (longer than H1_HEAD_MAX, cut by the end of the
// call, bytes it cannot read), a Transfer-Encoding other than exactly "chunked" (or with a Content-Length),
// a chunk size line it does not follow (not 1 to 15 hex digits with optional whitespace and extension, or
// longer than H1_CHUNK_LINE_MAX), trailers longer than H1_CHUNK_TRAILERS_MAX, more chunk boundaries in a
// call than h1_chunks follows, a chunked call larger than the upload limit, an Upgrade, a CONNECT, a 101,
// more than one Content-Length or one that is not plain digits, a response without the request it
// answers, a message that starts inside the call that ends another one (pipelining), a call that does not
// hand over the bytes it reports (MSG_PEEK, MSG_TRUNC, the mmsg calls), and a call that overlaps another
// one of its direction (in_flight_direction, see common/data_args.h), whose bytes may come first. A
// missed skip costs a little CPU, a wrong one corrupts the access log, so there is no resynchronization.
//
// The order of the uploads: the analyzer reads the calls of a connection in data id order, and a call
// takes its data id when it enters but uploads when it returns. A call that overlaps another one of its
// fd can return after a call with a larger data id and be read in front of calls that were skipped: so a
// call is only skipped when no other call of the fd was in flight as it returned (in_flight 1), which also
// proves that every call before it has uploaded already. A call that overlaps another one is still
// followed, and uploaded in whole. A read that uploads after a call with a larger data id did (it
// overlapped that one) is read in front of it, which may put the analyzer out of step: the connection is
// not followed anymore.
//
// Coalescing (coalesce_http1_body_payload, with access_log.flush.merge_kernel_logs): each skipped call is
// still one event, one per socket call. With the kernel logs merged, the calls of one body that the user
// space would merge anyway (the same function, the same wall clock minute) are held in the direction
// instead (h1_direction_t.pending) and uploaded as one event that sums them (h1_flush), with the span of
// their data ids. The run is uploaded as soon as the body is complete, before any other call of the
// connection uploads, and before the close is notified (h1_flush_connection), so it takes the place of
// its calls in the order of the uploads. Only a call alone on its fd adds to a run; any call uploads a run
// first when no other call of the direction of the run is in flight (h1_may_flush_own, h1_may_flush_other),
// so no call can be adding to it. A call that uploads while it may not upload a run names the run as its
// previous data id (h1_reserve_run), as it would name the last call of the run uploaded on its own, so the
// analyzer waits for the run (buffer.BodyConsumer); and a call joins a run only while nothing else of the
// connection uploaded since the run started, so a run never stands for the data id of another upload.

#include "../common/h2c_state.h"

// the bytes of a head the cursor reads at most: one that is longer loses the direction
#define H1_HEAD_MAX 1024
// one step either moves 8 bytes or over one line end
#define H1_SCAN_STEPS (H1_HEAD_MAX / 8 + 64)
// the offsets stay below H1_HEAD_MAX; the verifier only learns that they are below 2 * H1_HEAD_MAX
#define H1_OFF_MASK (2 * H1_HEAD_MAX - 1)
// the scanned bytes start behind 8 zero bytes, so the byte before an offset is never a subtraction
#define H1_PAD 8
// the requests of a direction whose response has not come yet that the cursor keeps (the bits of
// h1_direction_t.head_requests)
#define H1_MAX_OUTSTANDING 32

struct h1_head_buffer_t {
    __u8 data[H1_PAD + 2 * H1_HEAD_MAX + 32];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct h1_head_buffer_t);
    __uint(max_entries, 1);
} h1_head_buffer_map SEC(".maps");

// the findings of h1_scan_head (h1_scan_t.flags)
#define H1_FL_BAD 1
#define H1_FL_UPGRADE 4

// The scan state lives in map memory: the verifier does not track its values, so the branches that write
// it do not multiply the states it explores.
struct h1_scan_t {
    __u64 n;      // in: the bytes in the window, the 16 behind them are zero
    __u64 end;    // out: the offset behind the blank line, 0 when it was not found
    __u64 flags;  // out: H1_FL_*
    __u64 clc;    // out: the Content-Length headers
    __u64 cl_pos; // out: the offset behind "content-length:"
    __u64 cl;     // parse: the value
    __u64 digits; // parse
    __u64 trail;  // parse: whitespace behind the digits seen
    __u64 off;    // scan: the cursor
    __u64 rest;   // follow: the bytes of the call from the start of the window
    __u64 status; // follow: the status code of a response
    __u64 tec;    // out: the Transfer-Encoding headers
    __u64 te_pos; // out: the offset behind "transfer-encodin"
    // h1_chunks: where the call is read from, how much of it can be read, its size, the offset reached
    __u64 w_src;
    __u64 w_readable;
    __u64 w_size;
    __u64 w_pos;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct h1_scan_t);
    __uint(max_entries, 1);
} h1_scan_map SEC(".maps");

// the start of a header line as little endian words, the letters folded with 0x20
#define H1_P_CONTENT 0x2d746e65746e6f63ULL  // "content-"
#define H1_F_CONTENT 0x0020202020202020ULL
#define H1_P_LENGTH 0x003a6874676e656cULL   // "length:" (7 bytes)
#define H1_F_LENGTH 0x0000202020202020ULL
#define H1_P_TRANSFER 0x726566736e617274ULL // "transfer"
#define H1_F_TRANSFER 0x2020202020202020ULL
#define H1_P_ENCODIN 0x6e69646f636e652dULL  // "-encodin"
#define H1_F_ENCODIN 0x2020202020202000ULL
#define H1_P_UPGRADE 0x3a65646172677075ULL  // "upgrade:"
#define H1_F_UPGRADE 0x0020202020202020ULL
// the start of a message as little endian words, exact: the methods the analyzer knows (reader.Reader),
// with the space behind them, and the status line of a response
#define H1_GET 0x20544547ULL               // "GET " (4 bytes)
#define H1_PUT 0x20545550ULL               // "PUT " (4 bytes)
#define H1_POST 0x2054534f50ULL            // "POST " (5 bytes)
#define H1_HEAD 0x2044414548ULL            // "HEAD " (5 bytes)
#define H1_PATCH 0x204843544150ULL         // "PATCH " (6 bytes)
#define H1_TRACE 0x204543415254ULL         // "TRACE " (6 bytes)
#define H1_DELETE 0x204554454c4544ULL      // "DELETE " (7 bytes)
#define H1_OPTIONS 0x20534e4f4954504fULL   // "OPTIONS "
#define H1_CONNECT 0x205443454e4e4f43ULL   // "CONNECT "
#define H1_HTTP10 0x302e312f50545448ULL    // "HTTP/1.0"
#define H1_HTTP11 0x312e312f50545448ULL    // "HTTP/1.1"

// what a message head is (h1_message_kind)
#define H1_KIND_UNKNOWN 0
#define H1_KIND_REQUEST 1
#define H1_KIND_HEAD 2
#define H1_KIND_CONNECT 3
#define H1_KIND_RESPONSE 4

#define H1_V(f) (*(volatile __u64 *)&res->f)
#define H1_MASK_OFF(v) asm volatile("%[x] &= %[m];\n" : [x] "+r"(v) : [m] "i"(H1_OFF_MASK))

// h1_load64 loads 8 bytes at any offset of map memory (the x86 and arm64 verifiers accept an unaligned
// map value access); clang splits a load it cannot prove aligned into 8 byte loads
static __always_inline __u64 h1_load64(const __u8 *p) {
    __u64 v;
    asm volatile("%[v] = *(u64 *)(%[p] + 0);\n" : [v] "=r"(v) : [p] "r"(p));
    return v;
}

// 0/1 tests without branches: the asm keeps clang from turning them back into compares, which the BPF
// backend lowers into a branch each (a path per test and step for the verifier)
static __always_inline __u64 h1_nz(__u64 x) {
    __u64 n = x;
    asm volatile("%[v] = -%[v];\n" : [v] "+r"(n));
    n |= x;
    asm volatile("%[v] >>= 63;\n" : [v] "+r"(n));
    return n;
}
static __always_inline __u64 h1_z(__u64 x) {
    return h1_nz(x) ^ 1;
}

// h1_scan_head walks the head in the res->n bytes of buf one 8 byte word at a time: a word without a LF
// moves 8 bytes; otherwise the first LF in it is a line end, which must follow a CR, and the 16 bytes
// behind it are the start of the next line, compared as two words with the folded header names, or the
// CRLF of the blank line that ends the head. A step is straight line code but for its two exits.
static __noinline int h1_scan_head(struct h1_head_buffer_t *buf, struct h1_scan_t *res) {
    res->off = 0;
    res->end = 0;
    res->flags = 0;
    res->clc = 0;
    res->cl_pos = 0;
    res->tec = 0;
    res->te_pos = 0;
    // off and n go through map memory every step: loaded back they are unknown values in one fixed range,
    // so the steps end in equal states
#pragma clang loop unroll(disable)
    for (int i = 0; i < H1_SCAN_STEPS; i++) {
        __u64 off = H1_V(off);
        H1_MASK_OFF(off);
        if (off >= H1_V(n)) {
            return 0;
        }
        __u64 w = h1_load64(&buf->data[H1_PAD + off]);
        __u64 x = w ^ 0x0a0a0a0a0a0a0a0aULL;
        // 0x80 in every byte of w that is a LF, exact (no carry between the bytes)
        __u64 z = ~(((x & 0x7f7f7f7f7f7f7f7fULL) + 0x7f7f7f7f7f7f7f7fULL) | x | 0x7f7f7f7f7f7f7f7fULL);
        __u64 has = h1_nz(z);
        // the index of the lowest LF byte (0 without one): 1 << (8 * index) times 0x0001020304050607 has
        // the index in its top byte
        __u64 idx = (((z & -z) >> 7) * 0x0001020304050607ULL) >> 56;
        asm volatile("%[v] &= 7;\n" : [v] "+r"(idx));
        __u64 lf = off + idx;
        H1_MASK_OFF(lf);
        __u64 prev = buf->data[H1_PAD - 1 + lf];
        __u64 a = h1_load64(&buf->data[H1_PAD + 1 + lf]);
        __u64 b = h1_load64(&buf->data[H1_PAD + 9 + lf]);
        __u64 bad = has & h1_nz(prev ^ 0x0d);
        __u64 end = has & h1_z((a & 0xffff) ^ 0x0a0d);
        __u64 m_cl = has & h1_z(((a | H1_F_CONTENT) ^ H1_P_CONTENT) |
                                (((b & 0x00ffffffffffffffULL) | H1_F_LENGTH) ^ H1_P_LENGTH));
        __u64 m_te = has & h1_z(((a | H1_F_TRANSFER) ^ H1_P_TRANSFER) | ((b | H1_F_ENCODIN) ^ H1_P_ENCODIN));
        __u64 m_up = has & h1_z((a | H1_F_UPGRADE) ^ H1_P_UPGRADE);
        res->clc += m_cl;
        __u64 pos = res->cl_pos;
        res->cl_pos = pos ^ ((pos ^ (lf + 16)) & (0 - m_cl));
        res->tec += m_te;
        pos = res->te_pos;
        res->te_pos = pos ^ ((pos ^ (lf + 17)) & (0 - m_te));
        res->flags |= bad | (m_up << 2);
        // a LF moves behind it, a word without one 8 bytes
        H1_V(off) = off + 8 - has * (7 - idx);
        if ((bad | end) != 0) {
            if (end != 0) {
                res->end = lf + 3;
            }
            return 0;
        }
    }
    return 0;
}

// h1_parse_cl parses the Content-Length value at res->cl_pos into res->cl: optional whitespace, 1 to 15
// digits, optional whitespace, CRLF. 0, or -1 for anything else.
static __noinline int h1_parse_cl(struct h1_head_buffer_t *buf, struct h1_scan_t *res) {
    __u64 p = res->cl_pos;
    H1_MASK_OFF(p);
    // the parse state is volatile map memory: in registers clang keeps it as known constants per path,
    // which the verifier walks apart
    H1_V(cl) = 0;
    H1_V(digits) = 0;
    H1_V(trail) = 0;
#pragma clang loop unroll(disable)
    for (int i = 0; i < 24; i++) {
        __u8 ch = buf->data[H1_PAD + p + i];
        if (ch == '\r') {
            __u64 d = H1_V(digits);
            if (buf->data[H1_PAD + 1 + p + i] != '\n' || d == 0 || d > 15) {
                return -1;
            }
            return 0;
        }
        if (ch == ' ' || ch == '\t') {
            if (H1_V(digits) != 0) {
                H1_V(trail) = 1;
            }
            continue;
        }
        if (ch < '0' || ch > '9' || H1_V(trail) != 0) {
            return -1;
        }
        H1_V(cl) = H1_V(cl) * 10 + (ch - '0');
        H1_V(digits) = H1_V(digits) + 1;
    }
    return -1;
}

#define H1_CHUNKED 0x64656b6e756863ULL // "chunked" (7 bytes, folded)

// h1_parse_te tells whether the Transfer-Encoding header at res->te_pos (behind "transfer-encodin") is
// exactly "chunked", with optional whitespace around: 0, or -1 for any other value (another coding, a list)
static __noinline int h1_parse_te(struct h1_head_buffer_t *buf, struct h1_scan_t *res) {
    __u64 p = res->te_pos;
    H1_MASK_OFF(p);
    if ((buf->data[H1_PAD + p] | 0x20) != 'g' || buf->data[H1_PAD + 1 + p] != ':') {
        return -1;
    }
    p += 2;
#pragma clang loop unroll(disable)
    for (int i = 0; i < 16; i++) {
        H1_MASK_OFF(p);
        __u8 ch = buf->data[H1_PAD + p];
        if (ch != ' ' && ch != '\t') {
            break;
        }
        p++;
    }
    H1_MASK_OFF(p);
    if (((h1_load64(&buf->data[H1_PAD + p]) | 0x20202020202020ULL) & 0x00ffffffffffffffULL) != H1_CHUNKED) {
        return -1;
    }
    p += 7;
#pragma clang loop unroll(disable)
    for (int i = 0; i < 16; i++) {
        H1_MASK_OFF(p);
        __u8 ch = buf->data[H1_PAD + p];
        if (ch != ' ' && ch != '\t') {
            break;
        }
        p++;
    }
    H1_MASK_OFF(p);
    if (buf->data[H1_PAD + p] != '\r' || buf->data[H1_PAD + 1 + p] != '\n') {
        return -1;
    }
    return 0;
}

// h1_starts_message tells whether 8 bytes start the way the analyzer takes for a message start
// (reader.Reader.IdentityMessageType: a known method or "HTTP", a prefix of the first 16 bytes)
static __noinline int h1_starts_message(__u64 w) {
    __u64 w3 = w & 0xffffffULL, w4 = w & 0xffffffffULL, w5 = w & 0xffffffffffULL, w6 = w & 0xffffffffffffULL,
          w7 = w & 0xffffffffffffffULL;
    return w3 == 0x544547ULL || w3 == 0x545550ULL || w4 == 0x54534f50ULL || w4 == 0x44414548ULL ||
           w4 == 0x50545448ULL || w5 == 0x4843544150ULL || w5 == 0x4543415254ULL || w6 == 0x4554454c4544ULL ||
           w7 == 0x534e4f4954504fULL || w7 == 0x5443454e4e4f43ULL;
}

// a chunk size line, and the trailers, longer than this are not followed
#define H1_CHUNK_LINE_MAX 64
#define H1_CHUNK_TRAILERS_MAX 256
// the bytes a step of h1_chunks reads, and the steps over a call: a step moves over chunk data and reads the
// bytes of the line break and the size line behind it (or of the trailers), so a call is followed over
// H1_CHUNK_STEPS chunk boundaries (fewer with long size lines)
#define H1_CHUNK_WINDOW 16
#define H1_CHUNK_STEPS 4
// the bytes of a socket call BPF uploads at most (socket_data.h): the analyzer ends a chunked body at the
// bytes of a larger call it did not get, unless they are chunk data with more of it behind
#define H1_UPLOAD_MAX (SOCKET_UPLOAD_CHUNK_LIMIT * SOCKET_UPLOAD_CHUNK_SIZE)

#define H1_C(f) (*(volatile __u8 *)&c->f)

// h1_chunk_bytes walks the framing bytes of a chunked body in the n bytes of buf (the line break behind
// chunk data, a size line, the trailers) as buffer.BodyConsumer parses them, the state in the direction: it
// returns the bytes it went through, up to the start of chunk data or the end of the body, or -1 for a
// framing it does not follow. The analyzer is mirrored exactly where it matters (the line break behind
// the data is one LF or any two bytes), strictly elsewhere: a size line is optional whitespace, 1 to 15 hex
// digits, optional whitespace, an optional extension, an optional CR and the LF.
static __noinline int h1_chunk_bytes(struct h1_head_buffer_t *buf, struct h1_direction_t *c, __u64 n) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < H1_CHUNK_WINDOW; i++) {
        if (i >= n) {
            return i;
        }
        __u8 ch = buf->data[i];
        __u8 phase = H1_C(phase);
        if (phase == H1_CHUNK_CRLF) {
            if (H1_C(crlf) == 0 && ch != '\n') {
                H1_C(crlf) = 1;
                continue;
            }
            H1_C(phase) = H1_CHUNK_SIZE;
            H1_C(line) = 0;
            H1_C(digits) = 0;
            H1_C(line_len) = 0;
            *(volatile __u64 *)&c->remaining = 0;
            continue;
        }
        if (phase == H1_CHUNK_SIZE) {
            __u8 line = H1_C(line), digits = H1_C(digits);
            __u8 len = H1_C(line_len) + 1;
            H1_C(line_len) = len;
            if (len > H1_CHUNK_LINE_MAX) {
                return -1;
            }
            if (ch == '\n') {
                if (digits == 0) {
                    return -1;
                }
                // the last chunk has no data: the trailers follow
                H1_C(phase) = *(volatile __u64 *)&c->remaining != 0 ? H1_CHUNK_DATA : H1_CHUNK_TRAILERS;
                H1_C(line) = 0;
                *(volatile __u16 *)&c->trailers = 0;
                return i + 1;
            }
            if ((line & H1_LINE_EXT) != 0) {
                continue;
            }
            if ((line & H1_LINE_CR) != 0) {
                return -1;
            }
            if (ch == '\r') {
                H1_C(line) = line | H1_LINE_CR;
                continue;
            }
            if (ch == ';') {
                if (digits == 0) {
                    return -1;
                }
                H1_C(line) = line | H1_LINE_EXT;
                continue;
            }
            if (ch == ' ' || ch == '\t') {
                if (digits != 0) {
                    H1_C(line) = line | H1_LINE_TRAIL;
                }
                continue;
            }
            __u64 v;
            if (ch >= '0' && ch <= '9') {
                v = ch - '0';
            } else if ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'f') {
                v = (ch | 0x20) - 'a' + 10;
            } else {
                return -1;
            }
            if ((line & H1_LINE_TRAIL) != 0 || digits >= 15) {
                return -1;
            }
            *(volatile __u64 *)&c->remaining = *(volatile __u64 *)&c->remaining * 16 + v;
            H1_C(digits) = digits + 1;
            continue;
        }
        if (phase == H1_CHUNK_TRAILERS) {
            __u16 t = *(volatile __u16 *)&c->trailers + 1;
            *(volatile __u16 *)&c->trailers = t;
            if (t > H1_CHUNK_TRAILERS_MAX) {
                return -1;
            }
            if (ch == '\n') {
                if ((H1_C(line) & H1_LINE_NONEMPTY) == 0) {
                    // the empty line: the body is complete
                    H1_C(phase) = H1_BOUNDARY;
                    return i + 1;
                }
                H1_C(line) = 0;
            } else if (ch != '\r') {
                H1_C(line) = H1_LINE_NONEMPTY;
            }
            continue;
        }
        return i;
    }
    return H1_CHUNK_WINDOW;
}

// h1_chunks follows a chunked body over a call that is uploaded, from res->w_pos to its end (res->w_size;
// res->w_src and res->w_readable are where its bytes are read from): 0, or -1 when the direction is lost
// (more boundaries than the steps cover, bytes it cannot read, a framing it does not follow, another message
// behind the body). Everything goes through map memory, so the steps end in equal states.
static __noinline int h1_chunks(struct h1_head_buffer_t *buf, struct h1_scan_t *res, struct h1_direction_t *c) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < H1_CHUNK_STEPS; i++) {
        __u64 p = H1_V(w_pos), size = H1_V(w_size);
        if (H1_C(phase) == H1_CHUNK_DATA) {
            __u64 rem = *(volatile __u64 *)&c->remaining, left = size - p;
            __u64 step = rem < left ? rem : left;
            *(volatile __u64 *)&c->remaining = rem - step;
            p += step;
            H1_V(w_pos) = p;
            if (rem == step) {
                H1_C(phase) = H1_CHUNK_CRLF;
                H1_C(crlf) = 0;
            }
        }
        if (p >= size) {
            return 0;
        }
        __u8 phase = H1_C(phase);
        if (phase != H1_CHUNK_CRLF && phase != H1_CHUNK_SIZE && phase != H1_CHUNK_TRAILERS) {
            // another message starts behind the body in the call (pipelining)
            return -1;
        }
        __u64 readable = H1_V(w_readable);
        if (p >= readable) {
            return -1;
        }
        __u64 n = readable - p;
        if (n > H1_CHUNK_WINDOW) {
            n = H1_CHUNK_WINDOW;
        }
        asm volatile("%[v] &= 0x1f;\n" : [v] "+r"(n));
        if (n == 0 || bpf_probe_read(buf->data, n, (char *)H1_V(w_src) + p) != 0) {
            return -1;
        }
        int moved = h1_chunk_bytes(buf, c, n);
        if (moved <= 0) {
            return -1;
        }
        H1_V(w_pos) = p + moved;
    }
    return H1_V(w_pos) >= H1_V(w_size) ? 0 : -1;
}

// h1_message_kind tells what the head at the start of the window is (H1_KIND_*), from its first word,
// and leaves the status code of a response in res->status: a request line starts with a method the
// analyzer knows and a space, a status line with "HTTP/1.0 " or "HTTP/1.1 " and three digits
static __noinline int h1_message_kind(struct h1_head_buffer_t *buf, struct h1_scan_t *res) {
    __u64 w = *(__u64 *)&buf->data[H1_PAD];
    if (w == H1_HTTP11 || w == H1_HTTP10) {
        __u8 s0 = buf->data[H1_PAD + 9], s1 = buf->data[H1_PAD + 10], s2 = buf->data[H1_PAD + 11];
        __u8 behind = buf->data[H1_PAD + 12];
        if (buf->data[H1_PAD + 8] != ' ' || s0 < '1' || s0 > '5' || s1 < '0' || s1 > '9' || s2 < '0' || s2 > '9' ||
            (behind != ' ' && behind != '\r')) {
            return H1_KIND_UNKNOWN;
        }
        H1_V(status) = (s0 - '0') * 100 + (s1 - '0') * 10 + (s2 - '0');
        return H1_KIND_RESPONSE;
    }
    if (w == H1_CONNECT) {
        return H1_KIND_CONNECT;
    }
    if ((w & 0xffffffffffULL) == H1_HEAD) {
        return H1_KIND_HEAD;
    }
    if ((w & 0xffffffffULL) == H1_GET || (w & 0xffffffffULL) == H1_PUT || (w & 0xffffffffffULL) == H1_POST ||
        (w & 0xffffffffffffULL) == H1_PATCH || (w & 0xffffffffffffULL) == H1_TRACE ||
        (w & 0xffffffffffffffULL) == H1_DELETE || w == H1_OPTIONS) {
        return H1_KIND_REQUEST;
    }
    return H1_KIND_UNKNOWN;
}

static __always_inline void h1_lose(struct h1_direction_t *d) {
    d->state = H2C_LOST;
}

// h1_follow moves the cursor of the direction over the call: H2C_CALL_SKIP_PAYLOAD when the call lies
// wholly inside the rest of a Content-Length body, H2C_CALL_UPLOAD otherwise (a head that starts in the
// call is read for the body of its message). o is the other direction of the connection, whose requests
// the responses of this one answer.
static __noinline int h1_follow(struct h2c_call_t *call, struct h1_direction_t *c, struct h1_direction_t *o) {
    struct sock_data_args_t *args = call->args;
    // the size is read again where it is used: a copy kept on the stack on some paths only keeps the verifier
    // from merging them where the head scan and the chunk walk are called
#define size (*(volatile __u64 *)&call->size)
    if (c->state == H2C_LOST) {
        return H2C_CALL_UPLOAD;
    }
    // a call that does not hand over the bytes it reports, an mmsg call (which does not report the bytes per
    // message), a connection without content, or another call of the direction at the same time
    if (args->recv_flags != 0 || call->func_name == SOCKET_OPTS_TYPE_SENDMMSG ||
        call->func_name == SOCKET_OPTS_TYPE_RECVMMSG || call->conn->skip_data_upload != 0 || args->in_flight_direction != 1) {
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    if (c->phase == H1_DEFERRED) {
        // the request the last response answers is counted by now (it was in flight then): a HEAD has no body
        __u8 index = c->deferred_index;
        __u8 counted = o->requests - index;
        if (counted == 0 || counted > H1_MAX_OUTSTANDING) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        if (((o->head_requests >> (index & (H1_MAX_OUTSTANDING - 1))) & 1) != 0) {
            if (c->deferred_rest != 0) {
                // the next message started in the call of the head
                h1_lose(c);
                return H2C_CALL_UPLOAD;
            }
            c->remaining = 0;
            c->phase = H1_BOUNDARY;
        } else {
            c->phase = c->remaining > 0 ? H1_BODY : H1_BOUNDARY;
        }
    }
    __u8 phase = c->phase;
    if (phase == H1_CHUNK_DATA && c->remaining >= size) {
        // wholly chunk data, which the analyzer counts. Of a call larger than the upload limit it gets a part,
        // and when the data ends with the call it ends the body at the bytes it did not get: uploaded.
        if (size > H1_UPLOAD_MAX && c->remaining == size) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        c->remaining -= size;
        if (c->remaining == 0) {
            c->phase = H1_CHUNK_CRLF;
            c->crlf = 0;
        }
        return H2C_CALL_SKIP_PAYLOAD;
    }
    __u64 pos = 0;
    if (phase == H1_BODY) {
        if (c->remaining >= size) {
            c->remaining -= size;
            if (c->remaining == 0) {
                c->phase = H1_BOUNDARY;
            }
            return H2C_CALL_SKIP_PAYLOAD;
        }
        // the body ends inside the call, the next head starts behind it
        pos = c->remaining;
        c->remaining = 0;
        c->phase = H1_BOUNDARY;
    }
    __u32 kZero = 0;
    struct h1_head_buffer_t *buf = bpf_map_lookup_elem(&h1_head_buffer_map, &kZero);
    struct h1_scan_t *res = bpf_map_lookup_elem(&h1_scan_map, &kZero);
    if (buf == NULL || res == NULL) {
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    // where the call is read from, how much of it can be read and where its next head starts go through map
    // memory from here on: a copy on the stack on some paths only keeps the verifier from merging them where
    // the head scan and the chunk walk are called
    H1_V(w_pos) = pos;
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
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    H1_V(w_src) = (__u64)src;
    H1_V(w_readable) = readable;
    H1_V(w_size) = size;
    if (phase == H1_CLOSE) {
        // the rest of a response delimited by the close: the analyzer reads none of it but where it looks for a
        // message start, the first 16 bytes of a call (into the next call when it is shorter). A call is skipped
        // only when those cannot start a message and nothing of it is read from the call in front.
        __u64 w = 0;
        bool skip = size >= 16 && H1_V(w_readable) >= 8 && c->short_call == 0 &&
                    bpf_probe_read(&w, sizeof(w), (char *)H1_V(w_src)) == 0 && h1_starts_message(w) == 0;
        c->short_call = size < 16;
        return skip ? H2C_CALL_SKIP_PAYLOAD : H2C_CALL_UPLOAD;
    }
    __u64 carried = c->carry_len;
    if (phase >= H1_CHUNK_DATA && phase <= H1_CHUNK_TRAILERS) {
        // framing bytes of a chunked body: uploaded, and followed over to where the call ends
        if (size > H1_UPLOAD_MAX) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        goto walk;
    }
    if (H1_V(w_pos) >= H1_V(w_readable) || carried > 8) {
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    if (H1_V(w_pos) == 0 && carried + size <= 8) {
        // a few bytes of a head in a call of their own: kept for the next call
        __u64 at = carried, len = size;
        asm volatile("%[v] &= 7;\n" : [v] "+r"(at));
        asm volatile("%[v] &= 15;\n" : [v] "+r"(len));
        if (len == 0 || bpf_probe_read(&c->carry[at], len, (char *)H1_V(w_src)) != 0) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        c->carry_len = carried + size;
        return H2C_CALL_UPLOAD;
    }
    if (carried != 0 && H1_V(w_pos) != 0) {
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    c->carry_len = 0;
    // the window: the carried bytes, then the call from the position
    __u64 at = H1_V(w_pos);
    __u64 n = H1_V(w_readable) - at;
    if (n > H1_HEAD_MAX - 8) {
        n = H1_HEAD_MAX - 8;
    }
    // bounds for the verifier right before the read, which never change the values
    H1_MASK_OFF(n);
    asm volatile("%[v] &= 0x7fffffff;\n" : [v] "+r"(at));
    asm volatile("%[v] &= 15;\n" : [v] "+r"(carried));
    *(__u64 *)&buf->data[0] = 0;
    *(__u64 *)&buf->data[H1_PAD] = *(__u64 *)c->carry;
    if (n == 0 || n > H1_HEAD_MAX - 8 || bpf_probe_read(&buf->data[H1_PAD + carried], n, (char *)H1_V(w_src) + at) != 0) {
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    n += carried;
    // the 16 bytes behind the window read as zero (a previous call left its bytes there)
    __u64 z = n;
    H1_MASK_OFF(z);
    *(__u64 *)&buf->data[H1_PAD + z] = 0;
    *(__u64 *)&buf->data[H1_PAD + 8 + z] = 0;
    res->n = n;
    // the bytes of the call from the start of the window, and where the window starts in the call
    H1_V(rest) = size - at + carried;
    H1_V(w_pos) = at - carried;
    h1_scan_head(buf, res);
    if (res->end == 0 || res->flags != 0 || res->clc > 1 || res->tec > 1) {
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    // a chunked body: only with Transfer-Encoding exactly "chunked", and without a Content-Length
    bool chunked = false;
    if (res->tec == 1) {
        if (res->clc != 0 || h1_parse_te(buf, res) != 0) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        chunked = true;
    }
    int kind = h1_message_kind(buf, res);
    // whether the message has the body its framing announces (none without one for a request), whether that
    // depends on a request not counted yet, and whether the close of the connection delimits it
    bool framed = true, deferred = false, close = false;
    if (kind == H1_KIND_REQUEST || kind == H1_KIND_HEAD) {
        if (o->state != H2C_LOST) {
            // the responses of the other direction answer the requests in order: keep whether it is a HEAD
            // (the responses may be one ahead: a response whose request was still in flight, H1_DEFERRED)
            __u8 outstanding = c->requests - o->responses;
            if (outstanding >= H1_MAX_OUTSTANDING && outstanding < 0x80) {
                h1_lose(c);
                return H2C_CALL_UPLOAD;
            }
            __u32 bit = 1U << (c->requests & (H1_MAX_OUTSTANDING - 1));
            c->head_requests = kind == H1_KIND_HEAD ? c->head_requests | bit : c->head_requests & ~bit;
            // the bit is in place before the request is counted, which is what the other direction reads
            asm volatile("" ::: "memory");
            c->requests++;
        }
    } else if (kind == H1_KIND_RESPONSE) {
        __u64 status = H1_V(status);
        if (status == 101) {
            // the connection switches to another protocol
            h1_lose(c);
            h1_lose(o);
            return H2C_CALL_UPLOAD;
        }
        if (status >= 200) {
            // a final response answers the oldest request of the other direction it has not answered
            __u8 answered = c->responses;
            __u8 outstanding = o->requests - answered;
            if (outstanding == 0 && *(volatile __u8 *)&args->in_flight_other != 0 && res->clc == 1 && !chunked &&
                status != 204 && status != 304) {
                // the request it answers may still be in flight, its write returned but not counted yet (the
                // peer answered before its exit ran): whether it is a HEAD decides the next call of the direction
                deferred = true;
            } else if (outstanding == 0 || outstanding > H1_MAX_OUTSTANDING) {
                h1_lose(c);
                return H2C_CALL_UPLOAD;
            }
            bool head = !deferred && ((o->head_requests >> (answered & (H1_MAX_OUTSTANDING - 1))) & 1) != 0;
            c->responses = answered + 1;
            if (head || status == 204 || status == 304) {
                framed = false;
            } else if (res->clc == 0 && !chunked) {
                // neither Content-Length nor chunked: the body runs to the close of the connection
                close = true;
            }
        } else {
            // an interim response (100 Continue): no body, the final one follows
            framed = false;
        }
    } else {
        if (kind == H1_KIND_CONNECT) {
            h1_lose(o);
        }
        h1_lose(c);
        return H2C_CALL_UPLOAD;
    }
    if (close) {
        // the analyzer reads the rest of the call as the body, and the calls behind it as messages it skips
        c->phase = H1_CLOSE;
        c->short_call = 0;
        return H2C_CALL_UPLOAD;
    }
    if (framed && chunked) {
        // the chunks start behind the head, in the call or later
        c->phase = H1_CHUNK_SIZE;
        c->line = 0;
        c->digits = 0;
        c->line_len = 0;
        c->remaining = 0;
        if (size > H1_UPLOAD_MAX) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        H1_V(w_pos) = H1_V(w_pos) + res->end;
        goto walk;
    }
    __u64 body = 0;
    if (framed && res->clc == 1) {
        if (h1_parse_cl(buf, res) != 0) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        body = res->cl;
    }
    // the bytes of the call behind the head
    __u64 rest = H1_V(rest) - res->end;
    if (deferred) {
        if (body < rest) {
            h1_lose(c);
            return H2C_CALL_UPLOAD;
        }
        c->remaining = body - rest;
        c->deferred_index = c->responses - 1;
        c->deferred_rest = rest != 0;
        c->phase = H1_DEFERRED;
        return H2C_CALL_UPLOAD;
    }
    if (body > rest) {
        c->remaining = body - rest;
        c->phase = H1_BODY;
    } else if (body < rest) {
        // another message starts inside the call (pipelining): not followed
        h1_lose(c);
    }
    return H2C_CALL_UPLOAD;

walk:
    // the walk is the same for both ways in: everything it needs is in map memory
    if (h1_chunks(buf, res, c) != 0) {
        h1_lose(c);
    }
    return H2C_CALL_UPLOAD;
}
#undef size

// h1_minute is the wall clock minute of a BPF time, as host.SameMinute computes it
static __always_inline __u64 h1_minute(__u64 t) {
    return (boot_time_unix_ns + t) / 60000000000ULL;
}

// h1_hold adds a skipped call to the run its direction holds, uploading the run first when the call
// cannot join it (another function or minute, a counter that would overflow), and uploads the run when
// the body is complete
static __noinline int h1_hold(void *ctx, struct h2c_call_t *call, struct h1_direction_t *c) {
    struct active_connection_t *conn = call->conn;
    struct sock_data_args_t *args = call->args;
    __u64 start = args->start_nacs;
    struct upload_data_args_ext ext = {};
    fill_upload_data_args_ext(&ext, conn, args, call->func_name);
    // another call of the connection uploaded since the run started (one of the other direction, made while
    // a call of this one was in flight, which kept it from uploading the run): the run is uploaded first, so
    // its data ids never cover the one of that call
    __u64 latest;
    socket_data_last_upload(call->conid, conn->random_id, &latest);
    if (c->pending != 0 && (latest != c->prev_data_id || c->pending == 0xff || h1_minute(c->start_time) != h1_minute(start) ||
                            (__u64)c->total_size + call->size > 0xffffffffULL ||
                            !upload_data_args_ext_coalesce(&c->ext, &ext, args->data_id - c->first_data_id))) {
        h1_flush(ctx, call->conid, conn->random_id, c, call->data_direction);
    }
    if (c->pending == 0) {
        c->first_data_id = args->data_id;
        c->start_time = start;
        socket_data_last_upload(call->conid, conn->random_id, &c->prev_data_id);
        c->ext = ext;
        c->total_size = call->size;
    } else {
        c->total_size += call->size;
    }
    // the end is the latest one, as merging the kernel logs takes it
    if (c->pending == 0 || call->curr_nacs > c->end_time) {
        c->end_time = call->curr_nacs;
    }
    c->pending++;
    c->data_id = args->data_id;
    if (c->phase != H1_BODY && c->phase != H1_CHUNK_DATA) {
        // the body, or the data of the chunk, is complete: nothing more joins the run
        h1_flush(ctx, call->conid, conn->random_id, c, call->data_direction);
    }
    return 1;
}

// h1_alone tells whether no other call of the fd was in flight as the call returned: only such a call may
// skip, or hold a call for a coalesced event. The counts are read again wherever they are asked, so no path
// keeps a known value of them for the verifier to walk apart.
static __always_inline bool h1_alone(struct h2c_call_t *call) {
    return *(volatile __u16 *)&call->args->in_flight == 1;
}

// h1_may_flush_own and h1_may_flush_other tell whether the call may upload the run its own or the other
// direction holds: when no call of that direction but itself was in flight as it returned. Only a call
// alone on its fd adds to a run, so no call is adding to it then, and none can start to while the call is
// in flight. Two calls may still upload the same run at once (one of each direction), which the claim in
// h1_flush settles.
static __always_inline bool h1_may_flush_own(struct h2c_call_t *call) {
    return *(volatile __u8 *)&call->args->in_flight_direction == 1;
}
static __always_inline bool h1_may_flush_other(struct h2c_call_t *call) {
    return *(volatile __u8 *)&call->args->in_flight_other == 0;
}

// h1_handle_call follows a socket call of a connection whose directions are followed as HTTP/1
// (H2C_STREAM_HTTP1) and tells whether its socket data must not be uploaded as usual: when it was
// uploaded without its content, or held for a coalesced event. A connection that turns out to be TLS or
// another protocol is not followed anymore.
static __noinline int h1_handle_call(void *ctx, struct h2c_call_t *call) {
    struct h2c_stream_t *stream = call->stream;
    struct active_connection_t *conn = call->conn;
    bool ingress = call->data_direction == SOCK_DATA_DIRECTION_INGRESS;
    // the directions by arithmetic, not by a branch: the 5.5 verifier does not know the direction of a call
    // here, and would walk everything below once per direction
    __u64 idx = call->data_direction;
    asm volatile("%[v] += -1;\n%[v] &= 1;\n" : [v] "+r"(idx));
    // 0 or the size of a direction, by a mask the verifier bounds exactly (it does not bound a product)
    __u64 c_off = 0 - idx, o_off = idx - 1;
    asm volatile("%[v] &= %[s];\n" : [v] "+r"(c_off) : [s] "i"(sizeof(struct h1_direction_t)));
    asm volatile("%[v] &= %[s];\n" : [v] "+r"(o_off) : [s] "i"(sizeof(struct h1_direction_t)));
    struct h1_direction_t *c = (struct h1_direction_t *)((char *)&stream->h1[0] + c_off);
    struct h1_direction_t *o = (struct h1_direction_t *)((char *)&stream->h1[0] + o_off);
    int result = H2C_CALL_UPLOAD;
    // a read that returns after a call with a larger data id uploaded (one that overlapped it, such as the
    // writes of a request body under a blocking read) is read in front of that one, though its bytes may have
    // come after: the analyzer may read the connection out of step from here on, where a call without its
    // bytes reads differently than with them, so nothing of the connection is skipped anymore. A write that
    // returns late sent its bytes before the calls that entered after it, which its data id tells right.
    __u64 latest;
    socket_data_last_upload(call->conid, conn->random_id, &latest);
    if (conn->ssl != 0 || conn->protocol != CONNECTION_PROTOCOL_HTTP1 ||
        (call->data_direction == SOCK_DATA_DIRECTION_INGRESS && call->args->data_id < latest)) {
        h1_lose(c);
        h1_lose(o);
    } else {
        result = h1_follow(call, c, o);
    }
    // nothing of the connection is uploaded while the other direction holds calls. Only after the follow,
    // which uploads nothing: the follow is then walked once by the verifier, not once per way through here.
    if (o->pending != 0 && h1_may_flush_other(call)) {
        h1_flush(ctx, call->conid, conn->random_id, o, ingress ? SOCK_DATA_DIRECTION_EGRESS : SOCK_DATA_DIRECTION_INGRESS);
    }
    // the entry was removed and its element taken by another connection of the fd while the call was
    // followed (a close on another thread): what was written may be this call's state in the other
    // connection's entry, and after every upload of a held run and every hold the same holds
    if (stream->random_id != conn->random_id) {
        c->state = H2C_LOST;
        o->state = H2C_LOST;
        return 0;
    }
    if (o->pending != 0) {
        // not uploaded (a call of its direction is in flight), and the call uploads in some way now
        h1_reserve_run(call->conid, conn->random_id, o);
    }
    if (result != H2C_CALL_SKIP_PAYLOAD || !h1_alone(call)) {
        if (c->pending != 0 && h1_may_flush_own(call)) {
            h1_flush(ctx, call->conid, conn->random_id, c, call->data_direction);
            if (stream->random_id != conn->random_id) {
                c->state = H2C_LOST;
                o->state = H2C_LOST;
                return 0;
            }
        }
        if (c->pending != 0) {
            h1_reserve_run(call->conid, conn->random_id, c);
        }
        if (h1_alone(call) && c->state == H2C_LOST && o->state == H2C_LOST && c->pending == 0 && o->pending == 0) {
            // nothing of the connection is followed or held anymore
            bpf_map_delete_elem(&h2c_stream_map, &call->conid);
        }
        return 0;
    }
    // the calls behind a response delimited by the close are not read as a body: the analyzer reports none of
    // them in a protocol log, so they are not coalesced
    if (!socket_data_event_coalescable() || coalesce_http1_body_payload == 0 || c->phase == H1_CLOSE) {
        return h2c_upload_skipped_payload(ctx, call);
    }
    h1_hold(ctx, call, c);
    // held into an element another connection took meanwhile: the call is uploaded as usual
    if (stream->random_id != conn->random_id) {
        c->pending = 0;
        c->state = H2C_LOST;
        o->state = H2C_LOST;
        return 0;
    }
    return 1;
}
