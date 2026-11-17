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

#include "api.h"
#include "socket_opts.h"
#include "socket_data.h"
#include "socket_reader.h"
#include "queue.h"
#include "protocol_analyzer.h"
#include "../common/connection.h"
#include "../common/data_args.h"



// openssl read or write
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} openssl_sock_data_args SEC(".maps");
// set (to 1, never back) by the OpenSSL probes (tls/openssl.c) before they put the arguments of a call into
// openssl_sock_data_args, the only programs that ever do: while it is 0 the map is empty, and the lookup of it in
// process_write_data is skipped. A program reads it after the probe of the same thread set it, so it never
// misses an entry of its own thread.
volatile __u32 openssl_probe_seen;

#include <transfer_detail.h>

#include "h2c.h"
#include "../l24/l24.h"

// The memory pressure of the user space. The user space refuses the socket data events while the events it
// holds are at its memory budget, after it has copied each of them out of the perf ring (the memory
// protection, see pkg/tools/buffer). While they are, it sets the flag here, and clears it once they fall
// back below about 90% of the budget: the data of a socket call is then not uploaded, only an event of
// the call marked SOCKET_DATA_PAYLOAD_SHED that carries at most SOCKET_DATA_SHED_PREFIX bytes of it, which
// the user space takes for an event it refused (it follows the same gap handling and counts as dropped)
// before decoding it. That saves the copy of the data in the kernel and out of the ring, and the ring.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} socket_data_pressure_map SEC(".maps");

// the payload_skipped mark of an event of a call whose data was not uploaded because of the pressure
#define SOCKET_DATA_PAYLOAD_SHED 3
// the first bytes of the call it carries: the user space tells an HTTP/1 request start by them, as it
// does with the first chunk of a refused event (the longest method, "OPTIONS ", is 8 bytes)
#define SOCKET_DATA_SHED_PREFIX 8

static __always_inline bool socket_data_pressure() {
    __u32 kZero = 0;
    __u32 *pressure = bpf_map_lookup_elem(&socket_data_pressure_map, &kZero);
    return pressure != NULL && *pressure != 0;
}

// upload_socket_data_shed sends the event of a call that would be uploaded with its data while the user
// space is under pressure: the fields of the call, sequence 0, finished, the first bytes of the call and
// the SOCKET_DATA_PAYLOAD_SHED mark. socket_data_last_id_map moves as the upload would move it. It
// returns false when the call would not be uploaded with its data (upload_socket_data decides then).
static __noinline bool upload_socket_data_shed(void *ctx, struct upload_data_args *args) {
    if (args->connection_ssl != args->socket_data_ssl || args->connection_protocol == CONNECTION_PROTOCOL_UNKNOWN ||
        args->connection_skip_data_upload == 1) {
        return false;
    }
    struct socket_data_upload_event *event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*event));
    if (event == NULL) {
        return true;
    }
    fill_socket_data_event(event, args, args->connection_protocol);
    __u64 prev_data_id;
    struct socket_data_last_id_t *latest = socket_data_chain_upload(args->con_id, args->random_id, args->socket_data_id, &prev_data_id);
    event->prev_data_id = prev_data_id;
    event->sequence = 0;
    event->finished = 1;
    event->have_reduce_after_chunk = 0;
    event->payload_skipped = SOCKET_DATA_PAYLOAD_SHED;
    char *src = args->socket_data_buf;
    __u64 n = args->bytes_count;
    if (src == NULL && args->socket_data_iovec != NULL) {
        struct iovec iov = {};
        bpf_probe_read(&iov, sizeof(iov), args->socket_data_iovec);
        src = (char *)iov.iov_base;
        if (iov.iov_len < n) {
            n = iov.iov_len;
        }
    }
    if (n > SOCKET_DATA_SHED_PREFIX) {
        n = SOCKET_DATA_SHED_PREFIX;
    }
    asm volatile("%[v] &= 0xf;\n" : [v] "+r"(n));
    if (src == NULL || n == 0 || n > SOCKET_DATA_SHED_PREFIX || bpf_probe_read(event->buffer, n, src) != 0) {
        n = 0;
    }
    event->data_len = n;
    // the size of the record is taken back from data_len, as in __upload_socket_data_with_buffer
    __u64 len = *(volatile __u16 *)&event->data_len;
    if (len > SOCKET_DATA_SHED_PREFIX) {
        len = SOCKET_DATA_SHED_PREFIX;
    }
    rover_submit_buf(ctx, &socket_data_upload_queue, event, __builtin_offsetof(struct socket_data_upload_event, buffer) + len);

    socket_data_store_after_chain(&args->con_id, args->random_id, args->socket_data_id, latest);
    return true;
}

// the payload_skipped mark of the event of a receive made with MSG_PEEK: the call leaves its bytes in the socket, to be
// received again by the call that consumes them, so they are no part of the stream the reader is handed. The event
// carries the details of the call (its kernel log) and none of its bytes, and it takes no place in the chain of the
// uploads (socket_data_last_id_map): the call after it names the upload before it. The user space reports its kernel
// log and never hands it to a protocol analyzer.
#define SOCKET_DATA_PAYLOAD_PEEK 4

// upload_socket_data_peek sends the event of a receive made with MSG_PEEK, see SOCKET_DATA_PAYLOAD_PEEK
static __noinline void upload_socket_data_peek(void *ctx, struct upload_data_args *args) {
    struct socket_data_upload_event *event = rover_reserve_buf(&socket_data_upload_queue, sizeof(*event));
    if (event == NULL) {
        return;
    }
    fill_socket_data_event(event, args, args->connection_protocol);
    event->prev_data_id = 0;
    event->sequence = 0;
    event->finished = 1;
    event->have_reduce_after_chunk = 0;
    event->payload_skipped = SOCKET_DATA_PAYLOAD_PEEK;
    event->data_len = 0;
    rover_submit_buf(ctx, &socket_data_upload_queue, event, __builtin_offsetof(struct socket_data_upload_event, buffer));
}

static __always_inline void process_write_data(void *ctx, __u64 id, struct sock_data_args_t *args, ssize_t bytes_count,
                                        __u32 data_direction, const bool vecs, __u8 func_name, bool ssl) {
    // the end of the call is read once it is known what the call is (sock_data_args_t.exit_nacs): right behind
    // the lookup of its connection for every call but one of a cleartext connection known as HTTP/2, which reads it in
    // the h2c fast path (h2c_fast_now) or in front of the generic path; the two kinds of calls of the fast path that
    // keep nothing of it (complete unused frames dropped, the payload of a held header dropped) do not read it at all.
    // Nothing in front of those places uses it.
    __u64 curr_nacs = 0;
    __u32 tgid = (__u32)(id >> 32);
    // the callers branch on the size before (a connection is only submitted for a positive one), which leaves
    // a different known range of it on each path, and the verifier would walk everything below once per range:
    // two XORs with a value it does not know make it unknown again (the size itself never changes)
    __u64 forget = args->fd;
    asm volatile("%[b] ^= %[k];\n%[b] ^= %[k];\n" : [b] "+r"(bytes_count) : [k] "r"(forget));

    if (vecs && args->iovlen <= 0) {
        return;
    }
    if (args->fd < 0) {
        return;
    }
    if (bytes_count <= 0) {
        return;
    }

    // get current connection
    struct active_connection_t *conn = get_or_create_active_conn(ctx, tgid, args->fd, GET_OR_CREATE_FUNC_ROLE(func_name, args->sk_role), args->role_sk);
    if (conn == NULL) {
        return;
    }
    if (ssl || conn->protocol != CONNECTION_PROTOCOL_HTTP2 || conn->ssl != 0) {
        args->exit_nacs = bpf_ktime_get_ns();
    }
    // only trace ipv4, v6, or unknown
    if (family_should_trace(conn->socket_family) == false) {
        return;
    }
    // a filtered connection uploads nothing
    if (connection_filtered(&conn->filter)) {
        return;
    }
    // process the ssl request if the fd not found (the map is empty until an OpenSSL probe ran)
    struct sock_data_args_t *ssl_data_args = NULL;
    if (openssl_probe_seen != 0) {
        ssl_data_args = bpf_map_lookup_elem(&openssl_sock_data_args, &id);
    }
    if (ssl_data_args != NULL && ssl_data_args->fd == 0) {
        ssl_data_args->fd = args->fd;
        conn->ssl = true;
    } else if (ssl) {
        conn->ssl = true;
    }
    // the L2 to L4 details of the call in an event of their own (access_log.kernel_metrics.l2_l3, l24/l24.h): every
    // call that reaches its upload, whatever the upload makes of it, sent with the details of the socket call (when the
    // call is the plain socket call of a plain connection, or the TLS library call of a TLS one, as the details were)
    if (kernel_metrics_l2_l3 != 0 && conn->ssl == ssl) {
        l24_upload(ctx, args, gen_tgid_fd(tgid, args->fd), conn->random_id, data_direction | ((__u64)func_name << 8));
    }

    // a socket call is only dropped, skipped or cut once the connection is known to be HTTP/2 before the call,
    // never by the call that is being used to recognize it: taken in front of the h2c upgrade below, so the call
    // that carries the 101 (known as HTTP/2 from it on) is followed but uploaded whole, as the first call of a
    // connection recognized by its preface is.
    // A value of its own (the mask makes the register a new one): the checks of conn->protocol below (the upgrade, the
    // protocol analysis) would otherwise narrow it too, in the register and in its stack slot (6.12 links a copy and
    // its spill), and the follower behind them would be verified once per narrowed value
    __u64 protocol_before_call = conn->protocol;
    asm volatile("%[v] &= 0xff;\n" : [v] "+r"(protocol_before_call));
    // an HTTP/1 connection that switches to h2c with this call (the 101 Switching Protocols to h2c) is HTTP/2 from
    // this call on (syscalls/h2c.h h2c_upgrade): its event and the events behind it say HTTP/2. Here, where the
    // verifier comes with few states: the check is walked once per state it comes with.
    if (conn->protocol == CONNECTION_PROTOCOL_HTTP1 && ssl == false && conn->ssl == 0) {
        h2c_upgrade(ctx, conn, args, gen_tgid_fd(tgid, args->fd), (__u64)bytes_count | ((__u64)data_direction << 56));
    }

    // if the cannot getting the package size and count, then try to get it from the data args
    if (args->total_package_size == 0 && args->package_count == 0) {
        args->total_package_size = bytes_count;
        args->package_count = 1;
    }

    // if the protocol or role is unknown in the connection and the current data content is plaintext
    // then try to use protocol analyzer to analyze request or response and protocol type
    // (or the protocol is one whose content can still turn out to be another, see protocol_analyzer_ext.h)
    __u32 msg_type = 0;
    if ((conn->role == CONNECTION_ROLE_TYPE_UNKNOWN || conn->protocol == 0 || protocol_needs_reanalysis(conn->protocol)) &&
        conn->ssl == ssl) {
        struct socket_buffer_reader_t *buf_reader = read_socket_data(args->buf, args->iovec, bytes_count);
        if (buf_reader != NULL) {
            msg_type = analyze_protocol(buf_reader->buffer, buf_reader->data_len, &conn->protocol);
            // if send request data to remote address or receive response data from remote address
            // then, recognized current connection is client
            if ((msg_type == CONNECTION_MESSAGE_TYPE_REQUEST && data_direction == SOCK_DATA_DIRECTION_EGRESS) ||
                (msg_type == CONNECTION_MESSAGE_TYPE_RESPONSE && data_direction == SOCK_DATA_DIRECTION_INGRESS)) {
                conn->role = CONNECTION_ROLE_TYPE_CLIENT;

            // if send response data to remote address or receive request data from remote address
            // then, recognized current connection is server
            } else if ((msg_type == CONNECTION_MESSAGE_TYPE_RESPONSE && data_direction == SOCK_DATA_DIRECTION_EGRESS) ||
                       (msg_type == CONNECTION_MESSAGE_TYPE_REQUEST && data_direction == SOCK_DATA_DIRECTION_INGRESS)) {
                conn->role = CONNECTION_ROLE_TYPE_SERVER;
            }
        }
    }

    __u64 conid = gen_tgid_fd(tgid, args->fd);

    // the protocol analysis above leaves a different known range of the size on each of its paths, and the
    // follower and its frame walk (syscalls/h2c.h) would be verified once per range: the size goes through
    // the per CPU upload arguments, which every field of is set again below, and comes back unknown (the
    // XOR above would make the verifier track the fd it is XORed with instead)
    struct upload_data_args *size_args = generate_socket_upload_args();
    if (size_args == NULL) {
        return;
    }
    size_args->bytes_count = bytes_count;
    bytes_count = *(volatile ssize_t *)&size_args->bytes_count;
    if (bytes_count <= 0) {
        return;
    }
    // the entry of the connection in the h2c follower (syscalls/h2c.h), for the fast path and h2c_handle_call
    struct h2c_stream_t *stream = NULL;
    if (!ssl && h2c_following()) {
        stream = bpf_map_lookup_elem(&h2c_stream_map, &conid);
    }
    // a counted call of a connection followed as HTTP/2: its leave marks the fd, whose later calls are not
    // counted in flight (socket_data_id_t.no_flight in common/data_args.h; only the HTTP/1 paths read them)
    if (stream != NULL && args->data_id_epoch != 0 && stream->mode == H2C_STREAM_HTTP2 &&
        stream->random_id == conn->random_id && conn->protocol == CONNECTION_PROTOCOL_HTTP2 && conn->ssl == 0) {
        args->no_flight_mark = 1;
    }
    // a call of a followed HTTP/2 connection that only continues what the follower knows (syscalls/h2c.h
    // h2c_fast_call): done here, with exactly what h2c_handle_call would do with it
    if (!ssl && stream != NULL) {
        struct h2c_call_t fast = {
            .conn = conn, .stream = stream, .args = args, .conid = conid, .size = bytes_count,
            .curr_nacs = curr_nacs, .data_direction = data_direction, .func_name = func_name,
            .protocol_before_call = protocol_before_call,
        };
        if (h2c_fast_call(ctx, &fast) != 0) {
            return;
        }
    }
    // the end of the call, unless it was read above or by the fast path before it left the call to the generic path
    if (*(volatile __u64 *)&args->exit_nacs == 0) {
        args->exit_nacs = bpf_ktime_get_ns();
    }
    curr_nacs = *(volatile __u64 *)&args->exit_nacs;
    // the calls in flight as the call returns (common/data_args.h), for the calls that go on (an upload carries them,
    // syscalls/h1.h judges by them); a call of a TLS library has none (its arguments are not those of a socket call).
    // Taken here, not behind the lookup of the arguments: only the calls that go on need them, and nothing in between
    // reads them.
    if (!ssl) {
        socket_data_call_observe(id, args);
    }
    // the bytes to upload when the end of the call lies in an h2c DATA payload, 0 for all (syscalls/h2c.h)
    __u64 upload_size = 0;
    // a receive with MSG_PEEK hands no bytes to the reader: no follower sees it (their cursors stay where the stream
    // is), it is never dropped, skipped, cut, batched or summarized, and it is uploaded without its bytes below
    bool peek = (args->recv_flags & SOCK_RECV_FLAG_MSG_PEEK) != 0;
    // (the upper 32 bits: the h2c DATA payload bytes summarized in front of this call, which its upload
    // carries, common/h2c_sum.h, and the run of whole DATA frames they are: h2c_take_pos)
    if (!peek && h2c_handle_call(ctx, conn, stream, args, conid, bytes_count, curr_nacs, data_direction, func_name, protocol_before_call,
                        ssl, socket_data_pressure(), &upload_size)) {
        return;
    }

    // the pending batch records of this connection were already flushed in h2c_handle_call before it
    // returned false (h2c_batch_flush_for), so the upload below keeps the connection's data id order

    // upload the socket data if need
    struct upload_data_args *upload_data_args = generate_socket_upload_args();
    if (upload_data_args != NULL) {
        upload_data_args->start_time = args->start_nacs;
        upload_data_args->end_time = curr_nacs;
        upload_data_args->con_id = conid;
        upload_data_args->random_id = conn->random_id;
        upload_data_args->socket_data_id = args->data_id;
        upload_data_args->socket_data_iovec = args->iovec;
        upload_data_args->socket_data_iovlen = args->iovlen;
        upload_data_args->bytes_count = bytes_count;
        upload_data_args->socket_data_buf = args->buf;
        upload_data_args->data_direction = data_direction;
        upload_data_args->connection_protocol = conn->protocol;
        upload_data_args->connection_ssl = conn->ssl;
        upload_data_args->socket_ssl_buffer_force_unfinished = args->ssl_buffer_force_unfinished;
        upload_data_args->connection_skip_data_upload = conn->skip_data_upload;
        upload_data_args->socket_data_ssl = ssl;
        fill_upload_data_args_ext(&upload_data_args->ext, conn, args, func_name);
        if (h2c_summarizing()) {
            upload_data_args_ext_set_sum_before(&upload_data_args->ext, upload_size >> 32);
        }
        // the run in front of the call and what the h2c follower knows of its frames
        h2c_take_pos(&upload_data_args->ext);
        if (peek) {
            upload_socket_data_peek(ctx, upload_data_args);
        } else if (socket_data_pressure() && upload_socket_data_shed(ctx, upload_data_args)) {
        } else if (H2C_UPLOAD_CUT(upload_size) != 0 && h2c_upload_cut(ctx, upload_data_args, H2C_UPLOAD_CUT(upload_size))) {
        } else {
            upload_socket_data(ctx, upload_data_args);
        }
    }
}