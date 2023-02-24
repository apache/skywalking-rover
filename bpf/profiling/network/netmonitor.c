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


// +build ignore

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <asm/errno.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "socket.h"
#include "sock_stats.h"
#include "args.h"
#include "protocol_analyzer.h"
#include "socket_detail.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define SOCKET_UPLOAD_CHUNK_LIMIT 12

static __inline bool family_should_trace(const __u32 family) {
    return family != AF_UNKNOWN && family != AF_INET && family != AF_INET6 ? false : true;
}

#define BPF_PROBE_READ_VAR(value, ptr) bpf_probe_read(&value, sizeof(value), ptr)

static __always_inline void submit_new_connection(struct pt_regs* ctx, __u32 func_name, __u32 tgid, __u32 fd, __u64 start_nacs,
                                            struct sockaddr* addr, const struct socket* socket) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    // active connection save
    struct active_connection_t con = {};
    con.pid = tgid;
    con.sockfd = fd;
    // generate random id to keep current connection is unique
    con.random_id = bpf_get_prandom_u32();
    if (func_name == SOCKET_OPTS_TYPE_CONNECT) {
        con.role = CONNECTION_ROLE_TYPE_CLIENT;
    } else if (func_name == SOCKET_OPTS_TYPE_ACCEPT) {
        con.role = CONNECTION_ROLE_TYPE_SERVER;
    } else {
        con.role = CONNECTION_ROLE_TYPE_UNKNOWN;
    }
    __u16 port;
    __u32 need_complete_addr = 1;
    if (socket != NULL) {
        need_complete_addr = 0;
        // only get from accept function(server side)
        struct sock* s;
        BPF_CORE_READ_INTO(&s, socket, sk);

        short unsigned int skc_family;
        BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
        con.socket_family = skc_family;

        if (con.socket_family == AF_INET) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            con.local_port = port;
            BPF_CORE_READ_INTO(&con.local_addr_v4, s, __sk_common.skc_rcv_saddr);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            con.remote_port = bpf_ntohs(port);
            BPF_CORE_READ_INTO(&con.remote_addr_v4, s, __sk_common.skc_daddr);
        } else if (con.socket_family == AF_INET6) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            con.local_port = port;
            BPF_CORE_READ_INTO(&con.local_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            con.remote_port = bpf_ntohs(port);
            BPF_CORE_READ_INTO(&con.remote_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
       }
    } else if (addr != NULL) {
        con.socket_family = _(addr->sa_family);
        if (con.socket_family == AF_INET) {
            struct sockaddr_in *daddr = (struct sockaddr_in *)addr;
            bpf_probe_read(&con.remote_addr_v4, sizeof(con.remote_addr_v4), &daddr->sin_addr.s_addr);
            bpf_probe_read(&port, sizeof(port), &daddr->sin_port);
            con.remote_port = bpf_ntohs(port);
        } else if (con.socket_family == AF_INET6) {
            struct sockaddr_in6 *daddr = (struct sockaddr_in6 *)addr;
            bpf_probe_read(&con.remote_addr_v6, sizeof(con.remote_addr_v6), &daddr->sin6_addr.s6_addr);
            bpf_probe_read(&port, sizeof(port), &daddr->sin6_port);
            con.remote_port = bpf_ntohs(port);
        }
    } else {
        con.socket_family = AF_UNKNOWN;
    }

    // save to the active connection map
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct socket_connect_event_t *event = create_socket_connect_event();
    // only trace ipv4, v6, or unknown
    // pid is not contains(monitored)
    // cannot create connect event object
    if (family_should_trace(con.socket_family) == false || tgid_should_trace(tgid) == false || !event) {
        con.connect_event_send = false;
        bpf_map_update_elem(&active_connection_map, &conid, &con, 0);
        return;
    }
    // default setting as sent
    con.connect_event_send = true;
    bpf_map_update_elem(&active_connection_map, &conid, &con, 0);

    // send to user-space that have connection activated
    event->conid = conid;
    event->random_id = con.random_id;
    event->func_name = func_name;
    if (con.role != CONNECTION_ROLE_TYPE_UNKNOWN) {
        event->exe_time = curr_nacs - start_nacs;
    }
    event->pid = tgid;
    event->sockfd = fd;

    // fill the connection
    event->role = con.role;
    event->socket_family = con.socket_family;
    event->need_complete_addr = need_complete_addr;
    event->local_addr_v4 = con.local_addr_v4;
    __builtin_memcpy(&event->local_addr_v6, &con.local_addr_v4, 16*sizeof(__u8));
    event->local_port = con.local_port;
    event->remote_addr_v4 = con.remote_addr_v4;
    __builtin_memcpy(&event->remote_addr_v6, &con.remote_addr_v6, 16*sizeof(__u8));
    event->remote_port = con.remote_port;

    __u32 ret = bpf_perf_event_output(ctx, &socket_connection_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
    // if not send event success, then update to the event not sent
    if (ret < 0) {
        struct active_connection_t *con = bpf_map_lookup_elem(&active_connection_map, &conid);
        if (con != NULL) {
            con->connect_event_send = false;
            bpf_map_update_elem(&active_connection_map, &conid, con, 0);
        }
    }
}

static __inline void notify_close_connection(struct pt_regs* ctx, __u64 conid, struct active_connection_t* con, __u64 start_time, __u64 end_time) {
    // if the connect event not send, then check the pid or socket family
    if (con->connect_event_send == false) {
        // only trace ipv4, v6, or unknown
        if (family_should_trace(con->socket_family) == false) {
            return;
        }
        // ignore send close event if current process should not trace
        if (tgid_should_trace(con->pid) == false) {
            return;
        }
    }

    __u64 exe_time = (__u64)(end_time - start_time);
    struct socket_close_event_t close_event = {};

    close_event.conid = conid;
    close_event.random_id = con->random_id;
    close_event.exe_time = exe_time;
    close_event.pid = con->pid;
    close_event.sockfd = con->sockfd;
    close_event.role = con->role;
    close_event.protocol = con->protocol;
    close_event.ssl = con->ssl;

    close_event.socket_family = con->socket_family;
    close_event.local_addr_v4 = con->local_addr_v4;
    __builtin_memcpy(&close_event.local_addr_v6, &con->local_addr_v4, 16*sizeof(__u8));
    close_event.local_port = con->local_port;
    close_event.remote_addr_v4 = con->remote_addr_v4;
    __builtin_memcpy(&close_event.remote_addr_v6, &con->remote_addr_v6, 16*sizeof(__u8));
    close_event.remote_port = con->remote_port;

    close_event.write_bytes = con->write_bytes;
    close_event.write_count = con->write_count;
    close_event.write_exe_time = con->write_exe_time;
    close_event.read_bytes = con->read_bytes;
    close_event.read_count = con->read_count;
    close_event.read_exe_time = con->read_exe_time;
    close_event.write_rtt_count = con->write_rtt_count;
    close_event.write_rtt_time = con->write_rtt_time;

    bpf_perf_event_output(ctx, &socket_close_event_queue, BPF_F_CURRENT_CPU, &close_event, sizeof(close_event));
}

static __inline void submit_close_connection(struct pt_regs* ctx, __u32 tgid, __u32 fd, __u64 start_nacs) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t* con = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (con == NULL) {
        return;
    }
    notify_close_connection(ctx, conid, con, start_nacs, curr_nacs);
    bpf_map_delete_elem(&active_connection_map, &conid);
}

static __inline struct active_connection_t* get_or_create_active_conn(struct pt_regs *ctx, __u32 tgid, __u32 fd, __u32 func_name) {
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t *conn = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (conn != NULL) {
        return conn;
    }
    submit_new_connection(ctx, func_name, tgid, fd, 0, NULL, NULL);
    return bpf_map_lookup_elem(&active_connection_map, &conid);
}

static __always_inline void set_conn_as_ssl(struct pt_regs* ctx, __u32 tgid, __u32 fd, __u32 func_name) {
    struct active_connection_t* conn = get_or_create_active_conn(ctx, tgid, fd, func_name);
    if (conn == NULL) {
        return;
    }
    conn->ssl = true;
};

static __inline void submit_connection_when_not_exists(struct pt_regs *ctx, __u64 id, const struct connect_args_t* connect_args, __u32 func_name) {
    __u32 tgid = (__u32)(id >> 32);
    __u32 fd = connect_args->fd;
    // pid is contains
    if (tgid_should_trace(tgid) == false) {
        return;
    }

    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t *conn = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (conn != NULL) {
       return;
    }
    submit_new_connection(ctx, func_name, tgid, connect_args->fd, connect_args->start_nacs, connect_args->addr, NULL);
}

static __always_inline void resent_connect_event(struct pt_regs *ctx, __u32 tgid, __u32 fd, __u64 conid, struct active_connection_t *con) {
    struct socket_connect_event_t *event = create_socket_connect_event();
    if (!event) {
        return;
    }
    event->conid = conid;
    event->random_id = con->random_id;
    event->func_name = SOCKET_OPTS_TYPE_RESENT;
    event->pid = tgid;
    event->sockfd = fd;
    event->role = con->role;
    event->socket_family = con->socket_family;
    event->need_complete_addr = 1;
    event->remote_port = 0;
    __u32 ret = bpf_perf_event_output(ctx, &socket_connection_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
    if (ret >= 0) {
        con->connect_event_send = true;
        bpf_map_update_elem(&active_connection_map, &conid, con, 0);
    }
}

static __always_inline void __upload_socket_data_with_buffer(void *ctx, __u8 index, char* buf, size_t size, __u32 is_finished, __u8 have_reduce_after_chunk, struct socket_data_upload_event *event) {
    event->sequence = index;
    event->data_len = size;
    event->finished = is_finished;
    event->have_reduce_after_chunk = have_reduce_after_chunk;
    if (size <= 0) {
        return;
    }
    asm volatile("%[size] &= 0x7ff;\n" ::[size] "+r"(size) :);
    bpf_probe_read(&event->buffer, size & 0x7ff, buf);

    bpf_perf_event_output(ctx, &socket_data_upload_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

static __always_inline void upload_socket_data_buf(void *ctx, char* buf, ssize_t size, struct socket_data_upload_event *event, __u8 force_unfinished) {
    ssize_t already_send = 0;
#pragma unroll
    for (__u8 index = 0; index < SOCKET_UPLOAD_CHUNK_LIMIT; index++) {
        // calculate bytes need to send
        ssize_t remaining = size - already_send;
        size_t need_send_in_chunk = 0;
        __u8 have_reduce_after_chunk = 0;
        if (remaining > MAX_TRANSMIT_SOCKET_READ_LENGTH) {
            need_send_in_chunk = MAX_TRANSMIT_SOCKET_READ_LENGTH;
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
if (iov_index < iovlen) {                                   \
    struct iovec cur_iov;                                   \
    BPF_PROBE_READ_VAR(cur_iov, &iov[iov_index]);           \
    ssize_t remaining = size - already_send;                \
    size_t need_send_in_chunk = remaining - cur_iov_sended; \
    __u8 have_reduce_after_chunk = 0;                       \
    if (cur_iov_sended + need_send_in_chunk > cur_iov.iov_len) {            \
        need_send_in_chunk = cur_iov.iov_len - cur_iov_sended;              \
        if (need_send_in_chunk > MAX_TRANSMIT_SOCKET_READ_LENGTH) {         \
            need_send_in_chunk = MAX_TRANSMIT_SOCKET_READ_LENGTH;           \
            have_reduce_after_chunk = 1;                                    \
        } else {                                                            \
            iov_index++;                                                    \
            cur_iov_sended = 0;                                             \
        }                                                                   \
    } else if (need_send_in_chunk > MAX_TRANSMIT_SOCKET_READ_LENGTH) {      \
        need_send_in_chunk = MAX_TRANSMIT_SOCKET_READ_LENGTH;               \
        have_reduce_after_chunk = 1;                                        \
    }                                                                       \
    __u32 is_finished = (need_send_in_chunk + already_send) >= size || loop_count == (SOCKET_UPLOAD_CHUNK_LIMIT - 1) ? true : false;                            \
    __upload_socket_data_with_buffer(ctx, loop_count, cur_iov.iov_base + cur_iov_sended, need_send_in_chunk, is_finished, have_reduce_after_chunk, event);      \
    already_send += need_send_in_chunk;                                                                                              \
    loop_count++;                                                                                                                    \
}

static __always_inline void upload_socket_data_iov(void *ctx, struct iovec* iov, const size_t iovlen, ssize_t size, struct socket_data_upload_event *event) {
    ssize_t already_send = 0;
    ssize_t cur_iov_sended = 0;
    __u8 iov_index = 0;
    __u8 loop_count = 0;

    // each count is same with SOCKET_UPLOAD_CHUNK_LIMIT
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
    UPLOAD_PER_SOCKET_DATA_IOV();
}

static __inline void upload_socket_data(void *ctx, __u64 start_time, __u64 end_time, __u64 conid, struct active_connection_t *connection, struct sock_data_args_t *args, ssize_t bytes_count, __u32 existing_msg_type, __u32 data_direction, bool ssl) {
    // generate event
    __u32 kZero = 0;
    struct socket_data_upload_event *event = bpf_map_lookup_elem(&socket_data_upload_event_per_cpu_map, &kZero);
    if (event == NULL) {
        return;
    }
    // unknown protocol then ignore
    if (connection->protocol == CONNECTION_PROTOCOL_UNKNOWN) {
        return;
    }
    // ssl must same, means only process the plain data
    if (connection->ssl != ssl) {
        return;
    }

    // basic data
    event->start_time = start_time;
    event->end_time = end_time;
    event->protocol = connection->protocol;
    event->direction = data_direction;
    event->conid = conid;
    event->randomid = connection->random_id;
    event->total_size = bytes_count;
    event->data_id = args->data_id;

    if (args->buf != NULL) {
        upload_socket_data_buf(ctx, args->buf, bytes_count, event, args->ssl_buffer_force_unfinished);
    } else if (args->iovec != NULL) {
        upload_socket_data_iov(ctx, args->iovec, args->iovlen, bytes_count, event);
    }
}

static __always_inline void process_write_data(struct pt_regs *ctx, __u64 id, struct sock_data_args_t *args, ssize_t bytes_count,
                                        __u32 data_direction, const bool vecs, __u8 func_name, bool ssl) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    __u32 tgid = (__u32)(id >> 32);

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
    __u64 conid = gen_tgid_fd(tgid, args->fd);
    struct active_connection_t *conn = get_or_create_active_conn(ctx, tgid, args->fd, func_name);
    if (conn == NULL) {
        return;
    }
    // only trace ipv4, v6, or unknown
    if (family_should_trace(conn->socket_family) == false) {
        return;
    }
    // process the ssl request if the fd not found
    struct sock_data_args_t *ssl_data_args = bpf_map_lookup_elem(&openssl_sock_data_args, &id);
    if (ssl_data_args != NULL && ssl_data_args->fd == 0) {
        ssl_data_args->fd = args->fd;
        conn->ssl = true;
    }

    // if connect event is not sent
    if (conn->connect_event_send == false) {
        // if the connection should trace, double check
        if (tgid_should_trace(tgid) == false) {
            return;
        }
        // resent the connection event
        resent_connect_event(ctx, tgid, args->fd, conid, conn);
    }

    // if the protocol or role is unknown in the connection and the current data content is plaintext
    // then try to use protocol analyzer to analyze request or response and protocol type
    __u32 msg_type = 0;
    if ((conn->role == CONNECTION_ROLE_TYPE_UNKNOWN || conn->protocol == 0) && conn->ssl == ssl) {
        struct socket_buffer_reader_t *buf_reader = read_socket_data(args, bytes_count);
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

    // upload the socket detail
    upload_socket_detail(ctx, conid, conn, func_name, args, ssl);

    // upload the socket data if need
    upload_socket_data(ctx, args->start_nacs, curr_nacs, conid, conn, args, bytes_count, msg_type, data_direction, ssl);

    // add statics when is not ssl(native buffer)
    if (ssl == false) {
        __u64 exe_time = curr_nacs - args->start_nacs;
        if (data_direction == SOCK_DATA_DIRECTION_EGRESS) {
            conn->write_bytes += bytes_count;
            conn->write_count++;
            conn->write_exe_time += exe_time;

            add_to_socket_connection_stats_histogram(conid, conn->random_id, SOCK_DATA_DIRECTION_EGRESS,
                            SOCKET_CONNECTION_STATS_HISTOGRAM_DATA_TYPE_EXE_TIME, exe_time);
        } else {
            conn->read_bytes += bytes_count;
            conn->read_count++;
            conn->read_exe_time += exe_time;

            add_to_socket_connection_stats_histogram(conid, conn->random_id, SOCK_DATA_DIRECTION_INGRESS,
                                    SOCKET_CONNECTION_STATS_HISTOGRAM_DATA_TYPE_EXE_TIME, exe_time);
        }
    }

    // RTT
    if (args->rtt_count > 0) {
        conn->write_rtt_count += args->rtt_count;
        conn->write_rtt_time += args->rtt_time;

        __u64 avg_rtt = args->rtt_time / args->rtt_count;
        add_to_socket_connection_stats_histogram(conid, conn->random_id, SOCK_DATA_DIRECTION_EGRESS,
                SOCKET_CONNECTION_STATS_HISTOGRAM_DATA_TYPE_RTT, avg_rtt);
    }
}

static __inline void process_connect(struct pt_regs *ctx, __u64 id, struct connect_args_t *connect_args) {
    int ret = PT_REGS_RC(ctx);
    if (ret < 0 && ret != -EINPROGRESS) {
        return;
    }
    if (connect_args->fd < 0) {
        return;
    }
    __u32 tgid = id >> 32;
    struct sock *sock = connect_args->sock;
    struct socket *s = _(sock->sk_socket);
    submit_new_connection(ctx, SOCKET_OPTS_TYPE_CONNECT, tgid, connect_args->fd, connect_args->start_nacs, connect_args->addr, s);
}

SEC("kprobe/connect")
int sys_connect(struct pt_regs *ctx) {
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    uint64_t id = bpf_get_current_pid_tgid();

    struct connect_args_t connect_args = {};
    connect_args.fd = _(PT_REGS_PARM1(ctx));
    bpf_probe_read(&connect_args.addr, sizeof(connect_args.addr), &(PT_REGS_PARM2(ctx)));
    connect_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
	return 0;
}

SEC("kretprobe/connect")
int sys_connect_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args) {
        process_connect(ctx, id, connect_args);
    }

    bpf_map_delete_elem(&conecting_args, &id);
	return 0;
}

SEC("kprobe/tcp_connect")
int tcp_connect(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);;
    if (connect_args) {
        connect_args->sock = (void *)PT_REGS_PARM1(ctx);
    }
    return 0;
}

static __inline void process_accept(struct pt_regs *ctx, __u64 id, struct accept_args_t *accept_args) {
    int fd = PT_REGS_RC(ctx);
    if (fd < 0) {
        return;
    }
    __u32 tgid = id >> 32;

    submit_new_connection(ctx, SOCKET_OPTS_TYPE_ACCEPT, tgid, fd, accept_args->start_nacs, accept_args->addr, accept_args->socket);
}

SEC("kprobe/sys_accept")
int sys_accept(struct pt_regs *ctx) {
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t sock = {};
//    sock.addr = (void *)PT_REGS_PARM2(ctx);
    bpf_probe_read(&sock.addr, sizeof(sock.addr), &(PT_REGS_PARM2(ctx)));
    sock.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&accepting_args, &id, &sock, 0);
    return 0;
}

SEC("kretprobe/sys_accept")
int sys_accept_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_sock = bpf_map_lookup_elem(&accepting_args, &id);
    if (accept_sock) {
        process_accept(ctx, id, accept_sock);
    }
    bpf_map_delete_elem(&accepting_args, &id);
    return 0;
}

SEC("kretprobe/sock_alloc")
int sock_alloc_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_sock = bpf_map_lookup_elem(&accepting_args, &id);
    if (accept_sock) {
        struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
        accept_sock->socket = sock;
    }
    return 0;
}

SEC("kprobe/sendto")
int sys_sendto(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    __u32 fd = _(PT_REGS_PARM1(ctx));
    char* buf;
    bpf_probe_read(&buf, sizeof(buf), &(PT_REGS_PARM2(ctx)));

    struct sockaddr* sockaddr;
    bpf_probe_read(&sockaddr, sizeof(sockaddr), &(PT_REGS_PARM5(ctx)));
    if (sockaddr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = sockaddr;
        connect_args.fd = fd;
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, fd, SOCKET_OPTS_TYPE_SENDTO);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/sendto")
int sys_sendto_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);

    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);;
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDTO);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_SENDTO, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/tcp_rcv_established")
int tcp_rcv_established(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        struct sock *sk = (void *)PT_REGS_PARM1(ctx);
        struct tcp_sock *tcp_sock = (struct tcp_sock *)sk;
        if (tcp_sock != NULL) {
            __u32 srtt;
            BPF_CORE_READ_INTO(&srtt, tcp_sock, srtt_us);
            data_args->rtt_time += srtt >> 3;
            data_args->rtt_count += 1;
        }
    }
    return 0;
}

SEC("kprobe/write")
int sys_write(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char* buf;
    bpf_probe_read(&buf, sizeof(buf), &(PT_REGS_PARM2(ctx)));

    struct sock_data_args_t data_args = {};
    data_args.fd = _(PT_REGS_PARM1(ctx));
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_WRITE);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/write")
int sys_write_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_WRITE, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/send")
int sys_send(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char* buf;
    bpf_probe_read(&buf, sizeof(buf), &(PT_REGS_PARM2(ctx)));

    struct sock_data_args_t data_args = {};
    data_args.fd = _(PT_REGS_PARM1(ctx));
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_SEND);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/send")
int sys_send_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, false, SOCKET_OPTS_TYPE_SEND, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/writev")
int sys_writev(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    struct iovec *iovec;
    bpf_probe_read(&iovec, sizeof(iovec), &(PT_REGS_PARM2(ctx)));

    struct sock_data_args_t data_args = {};
    data_args.fd = _(PT_REGS_PARM1(ctx));
    data_args.iovlen = _(PT_REGS_PARM3(ctx));
    data_args.iovec = iovec;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_WRITEV);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/writev")
int sys_writev_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_WRITEV, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/sendmsg")
int sys_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    struct user_msghdr* msghdr;
    bpf_probe_read(&msghdr, sizeof(msghdr), &(PT_REGS_PARM2(ctx)));
    if (msghdr == NULL) {
        return 0;
    }
    __u32 fd = _(PT_REGS_PARM1(ctx));

    struct sockaddr* addr = _(msghdr->msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = fd;
        connect_args.start_nacs = bpf_ktime_get_ns();
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    data_args.iovlen = _(msghdr->msg_iovlen);
    data_args.iovec = _(msghdr->msg_iov);
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_SENDMSG);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/sendmsg")
int sys_sendmsg_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);
    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);;
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDMSG);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    // socket data
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_SENDMSG, false);
    }
    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/sendmmsg")
int sys_sendmmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    struct mmsghdr* mmsghdr;
    bpf_probe_read(&mmsghdr, sizeof(mmsghdr), &(PT_REGS_PARM2(ctx)));
    __u32 vlen = _(PT_REGS_PARM3(ctx));
    if (mmsghdr == NULL || vlen <= 0) {
        return 0;
    }

    __u32 fd = _(PT_REGS_PARM1(ctx));

    struct sockaddr* addr = _(mmsghdr->msg_hdr.msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = fd;
        connect_args.start_nacs = bpf_ktime_get_ns();
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    struct iovec *msg_iov = _(mmsghdr->msg_hdr.msg_iov);
    data_args.iovec = msg_iov;
    size_t msg_iovlen = _(mmsghdr->msg_hdr.msg_iovlen);
    data_args.iovlen = msg_iovlen;
    data_args.msg_len = &mmsghdr->msg_hdr.msg_iovlen;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_SENDMMSG);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/sendmmsg")
int sys_sendmmsg_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    int msgs_count = PT_REGS_RC(ctx);
    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);;
    if (connect_args && msgs_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_SENDMMSG);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    // socket data
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        __u32 bytes_count;
        BPF_PROBE_READ_VAR(bytes_count, data_args->msg_len);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS, true, SOCKET_OPTS_TYPE_SENDMMSG, false);
    }
    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

static __inline void process_sendfile(struct pt_regs* ctx, __u64 id, struct sendfile_args_t* args, ssize_t bytes_count) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    __u64 tgid = (__u32)(id >> 32);
    if (args->out_fd < 0) {
        return;
    }
    if (bytes_count <= 0) {
        return;
    }
    if (tgid_should_trace(tgid) == false) {
        return;
    }
    __u64 conid = gen_tgid_fd(tgid, args->out_fd);
    struct active_connection_t *conn = get_or_create_active_conn(ctx, tgid, args->out_fd, SOCKET_OPTS_TYPE_SENDFILE);
    if (conn == NULL) {
        return;
    }
    if (family_should_trace(conn->socket_family) == false) {
        return;
    }

    // add statics
    __u64 exe_time = curr_nacs - args->start_nacs;
    conn->write_bytes += bytes_count;
    conn->write_count++;
    conn->write_exe_time += exe_time;

    add_to_socket_connection_stats_histogram(conid, conn->random_id, SOCK_DATA_DIRECTION_EGRESS,
                    SOCKET_CONNECTION_STATS_HISTOGRAM_DATA_TYPE_EXE_TIME, exe_time);
}


SEC("kprobe/sendfile")
int sys_sendfile(struct pt_regs *ctx) {
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    __u64 id = bpf_get_current_pid_tgid();

    struct sendfile_args_t args = {};
    args.out_fd = _(PT_REGS_PARM1(ctx));
    args.in_fd = _(PT_REGS_PARM2(ctx));
    args.count = _(PT_REGS_PARM4(ctx));
    args.start_nacs = bpf_ktime_get_ns();
    args.data_id = generate_socket_data_id(id, args.out_fd, SOCKET_OPTS_TYPE_SENDFILE);
    bpf_map_update_elem(&sendfile_args, &id, &args, 0);
    return 0;
}

SEC("kretprobe/sendfile")
int sys_sendfile_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sendfile_args_t* args = bpf_map_lookup_elem(&sendfile_args, &id);
    if (args != NULL) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_sendfile(ctx, id, args, bytes_count);
    }
    bpf_map_delete_elem(&sendfile_args, &id);
    return 0;
}

SEC("kprobe/read")
int sys_read(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char* buf;
    bpf_probe_read(&buf, sizeof(buf), &(PT_REGS_PARM2(ctx)));

    struct sock_data_args_t data_args = {};
    data_args.fd = _(PT_REGS_PARM1(ctx));
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_READ);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/read")
int sys_read_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_READ, false);
    }
    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/readv")
int sys_readv(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    struct iovec *iovec;
    bpf_probe_read(&iovec, sizeof(iovec), &(PT_REGS_PARM2(ctx)));

    struct sock_data_args_t data_args = {};
    data_args.fd = _(PT_REGS_PARM1(ctx));
    data_args.iovlen = _(PT_REGS_PARM3(ctx));
    data_args.iovec = iovec;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_READV);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/readv")
int sys_readv_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args && data_args->is_sock_event) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_READV, false);
    }

    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/recv")
int sys_recv(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char* buf;
    bpf_probe_read(&buf, sizeof(buf), &(PT_REGS_PARM2(ctx)));

    struct sock_data_args_t data_args = {};
    data_args.fd = _(PT_REGS_PARM1(ctx));
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECV);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/recv")
int sys_recv_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        ssize_t bytes_count = PT_REGS_RC(ctx);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_RECV, false);
    }
    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/recvfrom")
int sys_recvfrom(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char* buf;
    bpf_probe_read(&buf, sizeof(buf), &(PT_REGS_PARM2(ctx)));

    struct sockaddr* sock;
    bpf_probe_read(&sock, sizeof(sock), &(PT_REGS_PARM5(ctx)));
    __u32 fd = _(PT_REGS_PARM1(ctx));
    if (sock != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = sock;
        connect_args.fd = fd;
        connect_args.start_nacs = bpf_ktime_get_ns();
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    data_args.buf = buf;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECVFROM);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/recvfrom")
int sys_recvfrom_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);
    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);;
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVFROM);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    // socket data
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, false, SOCKET_OPTS_TYPE_RECVFROM, false);
    }
    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/recvmsg")
int sys_recvmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    struct user_msghdr* msghdr;
    bpf_probe_read(&msghdr, sizeof(msghdr), &(PT_REGS_PARM2(ctx)));
    if (msghdr == NULL) {
        return 0;
    }
    __u32 fd = _(PT_REGS_PARM1(ctx));

    struct sockaddr* addr = _(msghdr->msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = fd;
        connect_args.start_nacs = bpf_ktime_get_ns();
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    data_args.iovlen = _(msghdr->msg_iovlen);
    data_args.iovec = _(msghdr->msg_iov);
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECVMSG);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/recvmsg")
int sys_recvmsg_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);
    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && bytes_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVMSG);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    // socket data
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_RECVMSG, false);
    }
    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/recvmmsg")
int sys_recvmmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid_should_trace(tgid) == false) {
        return 0;
    }
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    struct mmsghdr* mmsghdr;
    bpf_probe_read(&mmsghdr, sizeof(mmsghdr), &(PT_REGS_PARM2(ctx)));
    __u32 vlen = _(PT_REGS_PARM3(ctx));
    if (mmsghdr == NULL || vlen <= 0) {
        return 0;
    }

    __u32 fd = _(PT_REGS_PARM1(ctx));

    struct sockaddr* addr = _(mmsghdr->msg_hdr.msg_name);
    if (addr != NULL) {
        struct connect_args_t connect_args = {};
        connect_args.addr = addr;
        connect_args.fd = fd;
        connect_args.start_nacs = bpf_ktime_get_ns();
        bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    }

    struct sock_data_args_t data_args = {};
    data_args.fd = fd;
    struct iovec *msg_iov = _(mmsghdr->msg_hdr.msg_iov);
    data_args.iovec = msg_iov;
    size_t msg_iovlen = _(mmsghdr->msg_hdr.msg_iovlen);
    data_args.iovlen = msg_iovlen;
    data_args.msg_len = &mmsghdr->msg_hdr.msg_iovlen;
    data_args.start_nacs = bpf_ktime_get_ns();
    data_args.data_id = generate_socket_data_id(id, data_args.fd, SOCKET_OPTS_TYPE_RECVMMSG);
    bpf_map_update_elem(&socket_data_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/recvmmsg")
int sys_recvmmsg_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    int msgs_count = PT_REGS_RC(ctx);
    // connection
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args && msgs_count > 0) {
        submit_connection_when_not_exists(ctx, id, connect_args, SOCKET_OPTS_TYPE_RECVMMSG);
    }
    bpf_map_delete_elem(&conecting_args, &id);

    // socket data
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args) {
        __u32 bytes_count;
        BPF_PROBE_READ_VAR(bytes_count, data_args->msg_len);
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS, true, SOCKET_OPTS_TYPE_RECVMMSG, false);
    }
    bpf_map_delete_elem(&socket_data_args, &id);
    return 0;
}

SEC("kprobe/close")
int sys_close(struct pt_regs* ctx) {
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    __u64 id = bpf_get_current_pid_tgid();

    struct sock_close_args_t close_args = {};
    close_args.fd = _(PT_REGS_PARM1(ctx));
    close_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&closing_args, &id, &close_args, 0);
    return 0;
}

static __inline void process_close_sock(struct pt_regs* ctx, __u64 id, struct sock_close_args_t *args) {
    __u32 tgid = (__u32)(id >> 32);
    int ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return;
    }
    if (args->fd < 0) {
        return;
    }

    submit_close_connection(ctx, tgid, args->fd, args->start_nacs);
}

SEC("kretprobe/close")
int sys_close_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_close_args_t *close_args = bpf_map_lookup_elem(&closing_args, &id);
    if (close_args) {
        process_close_sock(ctx, id, close_args);
    }
    bpf_map_delete_elem(&closing_args, &id);
    return 0;
}

SEC("kprobe/security_socket_sendmsg")
int security_socket_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        data_args->is_sock_event = true;
    }
    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int security_socket_recvmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args != NULL) {
        data_args->is_sock_event = true;
    }
    return 0;
}

static __inline void send_socket_exception_operation_event(struct pt_regs *ctx, __u32 type, struct sock *s) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    // pid is contains
    if (tgid_should_trace(tgid) == false) {
        return;
    }

    struct socket_exception_operation_event_t event = {};
    event.pid = tgid;
    event.type = type;
    __u16 skc_family, port;
    BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
    event.socket_family = skc_family;
    if (event.socket_family == AF_INET) {
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
        event.local_port = port;
        BPF_CORE_READ_INTO(&event.local_addr_v4, s, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
        event.remote_port = bpf_ntohs(port);
        BPF_CORE_READ_INTO(&event.remote_addr_v4, s, __sk_common.skc_daddr);
    } else if (event.socket_family == AF_INET6) {
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
        event.local_port = port;
        BPF_CORE_READ_INTO(&event.local_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
        event.remote_port = bpf_ntohs(port);
        BPF_CORE_READ_INTO(&event.remote_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    } else {
        return;
    }

    bpf_perf_event_output(ctx, &socket_exception_operation_event_queue, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("kprobe/tcp_retransmit_skb")
int tcp_retransmit(struct pt_regs *ctx) {
    struct sock *s = (void *)PT_REGS_PARM1(ctx);
    send_socket_exception_operation_event(ctx, SOCKET_EXCEPTION_OPERATION_TYPE_RETRANSMIT, s);
    return 0;
}

SEC("kprobe/tcp_drop")
int tcp_drop(struct pt_regs *ctx) {
    struct sock *s = (void *)PT_REGS_PARM1(ctx);
    send_socket_exception_operation_event(ctx, SOCKET_EXCEPTION_OPERATION_TYPE_DROP, s);
    return 0;
}

SEC("kprobe/kfree_skb_reason")
int kfree_skb_reason(struct pt_regs *ctx) {
    struct sock *s = (void *)PT_REGS_PARM1(ctx);
    enum skb_drop_reason reason = PT_REGS_PARM2(ctx);

    if (reason > SKB_DROP_REASON_NOT_SPECIFIED) {
        send_socket_exception_operation_event(ctx, SOCKET_EXCEPTION_OPERATION_TYPE_DROP, s);
    }
    return 0;
}

#include "openssl.c"
#include "go_tls.c"
#include "node_tls.c"
#include "socket_detail.c"