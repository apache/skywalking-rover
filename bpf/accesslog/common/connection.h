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
#include "socket.h"
#include "data_args.h"
#include "socket_opts.h"
#include "queue.h"
#include "socket_data.h"
#include "h2c_state.h"
#include "h2c_batch.h"
#include "h2c_sum.h"
#include "sock.h"

// syscall:connect
struct connect_args_t {
    __u32 fd;
    __u32 has_remote;
    struct sockaddr* addr;
    struct sock *sock;
    __u64 start_nacs;

    struct connect_track_remote remote;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} conecting_args SEC(".maps");
// Never fewer than the entries conecting_args holds: an insert that succeeded adds 1 (one that replaced an entry
// as well, which only ever leaves it above), a delete that removed an entry takes 1. While it is 0 the map is empty, and
// the programs that look it up skip the lookup and the delete: the nf_confirm kprobe runs for every packet of the host,
// the exits of the sends and receives that may carry an address for every such call of every process. An entry is
// only ever looked up by its own thread (the key is the thread), after the insert that made it, so a lookup never
// misses one because of a count it does not see yet.
// The count is written by every connect, the flags of .bss are read by every call: it lives in a data section of its
// own (a map of its own to the loader, apart from .bss), on a cache line of its own (ACCESSLOG_LIVE_COUNTER).
#ifndef ACCESSLOG_LIVE_COUNTER
#define ACCESSLOG_LIVE_COUNTER __attribute__((section(".data.live"), aligned(64)))
#endif
volatile __u32 conecting_args_live ACCESSLOG_LIVE_COUNTER = 0;

static __always_inline void conecting_args_put(__u64 *id, struct connect_args_t *args) {
    if (bpf_map_update_elem(&conecting_args, id, args, 0) == 0) {
        __sync_fetch_and_add(&conecting_args_live, 1);
    }
}

static __always_inline struct connect_args_t *conecting_args_get(__u64 *id) {
    if (conecting_args_live == 0) {
        return NULL;
    }
    return bpf_map_lookup_elem(&conecting_args, id);
}

static __always_inline void conecting_args_del(__u64 *id) {
    if (conecting_args_live != 0 && bpf_map_delete_elem(&conecting_args, id) == 0) {
        __sync_fetch_and_add(&conecting_args_live, -1);
    }
}

// syscall:accept
struct accept_args_t {
    struct sockaddr* addr;
    struct socket* socket;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct accept_args_t);
} accepting_args SEC(".maps");

// syscall:close
struct sock_close_args_t {
    int fd;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_close_args_t);
} closing_args SEC(".maps");

// notify to the user-space the connection connected(connect, accept)
// only traced connection ipv4/v6 or unknown connection
struct socket_connect_event_t {
    // current connection id
    __u64 conid;
    // random value in one active connection
    // generate a unique ID through connection_id + random_id, which is convenient for histogram data storage.
    // we need random_id becase socketfd would be multiplexed in the same pid,
    // but the metrics data(histogram) is MAP data, which can only be read by user-space with interval, so it would cause data delay.
    __u64 random_id;
    // connect operation start nanosecond
    __u64 start_time;
    // connect operation finish nanosecond
    __u64 end_time;
    // current process id
    __u32 pid;
    // current socket fd
    __u32 sockfd;
    // create from function name
    __u8 func_name;

    // the type of role in current connection
    __u8 role;
    // socket type
    __u8 socket_family;
    // is connect success or not
    __u8 success;
    __u32 __pad0;

    // upstream
    __u32 remote_addr_v4;
    __u32 remote_port;
    __u8 remote_addr_v6[16];
    // downstream
    __u32 local_addr_v4;
    __u32 local_port;
    __u8 local_addr_v6[16];

    __u64 conntrack_upstream_ipl;
    __u64 conntrack_upstream_iph;
    __u32 conntrack_upstream_port;
};
DATA_QUEUE(socket_connection_event_queue);

#include <connection_filter.h>

// active connection cached into the hashmap
// if connection closed, then deleted
struct active_connection_t {
    // random value in one active connection
    // generate a unique ID through connection_id + random_id, which is convenient for histogram data storage
    __u64 random_id;
    // process id
    __u32 pid;
    // socket fd under process
    __u32 sockfd;
    // the type of role in current connection
    __u32 role;
    // socket type
    __u32 socket_family;

    // for protocol analyze
    __u8 protocol;
    // current connection is ssl
    __u8 ssl;
    // skip data upload when the protocol break(such as HTTP2)
    __u8 skip_data_upload;
    // whether the connection is filtered, see connection_filter.h
    struct connection_filter_state filter;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct active_connection_t);
} active_connection_map SEC(".maps");
static __inline __u64 gen_tgid_fd(__u32 tgid, __u32 sockfd) {
    return ((__u64)tgid << 32) | sockfd;
}
struct socket_close_event_t {
    // current connection id
    __u64 conid;
    // random value in one active connection
    // generate a unique ID through connection_id + random_id, which is convenient for histogram data storage
    __u64 random_id;

    // close event execute time
    __u64 start_time;
    __u64 end_time;
    // process id
    __u32 pid;
    // socket fd under process
    __u32 sockfd;
    // close success
    __u32 success;
};
DATA_QUEUE(socket_close_event_queue);

static __inline bool family_should_trace(const __u32 family) {
    return family != AF_UNKNOWN && family != AF_INET && family != AF_INET6 ? false : true;
}

static __always_inline void submit_new_connection(void* ctx, bool success, __u32 func_name, __u32 tgid, __u32 fd, __u64 start_nacs,
                                            struct sockaddr* addr, const struct socket* socket, struct connect_track_remote* conntrack, __u8 role) {
    // send to the user-space the connection event
    __u64 curr_nacs = bpf_ktime_get_ns();
    struct socket_connect_event_t *event;
    event = rover_reserve_buf(&socket_connection_event_queue, sizeof(*event));
    if (event == NULL) {
        return;
    }

    __u64 conid = gen_tgid_fd(tgid, fd);
    __u64 random_id = bpf_get_prandom_u32();
    event->conid = conid;
    event->random_id = random_id;
    event->start_time = start_nacs;
    event->end_time = curr_nacs;
    event->func_name = func_name;
    if (func_name == SOCKET_OPTS_TYPE_CONNECT) {
        role = CONNECTION_ROLE_TYPE_CLIENT;
    } else if (func_name == SOCKET_OPTS_TYPE_ACCEPT) {
        role = CONNECTION_ROLE_TYPE_SERVER;
    }
    event->role = role;
    event->pid = tgid;
    event->sockfd = fd;

    // cleanup and fill the conntrack
    event->conntrack_upstream_iph = 0;
    event->conntrack_upstream_ipl = 0;
    event->conntrack_upstream_port = 0;
    if (conntrack != NULL) {
        event->conntrack_upstream_iph = (__u64)conntrack->iph;
        event->conntrack_upstream_ipl = (__u64)conntrack->ipl;
        event->conntrack_upstream_port = conntrack->port;
    }
    event->success = success;

    __u16 port;
    __u8 socket_family;
    event->local_port = 0;
    event->remote_port = 0;
    if (socket == NULL) {
        struct task_struct* task_ptr = (struct task_struct*)bpf_get_current_task();
        struct files_struct *files = _(task_ptr->files);
        struct fdtable *fdtable = _(files->fdt);
        struct file *fd_data;
        struct file **fd_ptr;
        bpf_probe_read_kernel(&fd_ptr, sizeof(fd_ptr), &fdtable->fd);
        bpf_probe_read_kernel(&fd_data, sizeof(fd_data), &fd_ptr[fd]);
        socket = _(fd_data->private_data);
    }
    if (socket != NULL) {
        // only get from accept function(server side)
        struct sock* s;
        BPF_CORE_READ_INTO(&s, socket, sk);

        short unsigned int skc_family;
        BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
        event->socket_family = skc_family;
        socket_family = skc_family;

        if (event->socket_family == AF_INET) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            event->local_port = port;
            BPF_CORE_READ_INTO(&event->local_addr_v4, s, __sk_common.skc_rcv_saddr);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            event->remote_port = bpf_ntohs(port);
            BPF_CORE_READ_INTO(&event->remote_addr_v4, s, __sk_common.skc_daddr);
        } else if (event->socket_family == AF_INET6) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            event->local_port = port;
            BPF_CORE_READ_INTO(&event->local_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            event->remote_port = bpf_ntohs(port);
            BPF_CORE_READ_INTO(&event->remote_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        }
    } else if (addr != NULL) {
        event->socket_family = _(addr->sa_family);
        socket_family = event->socket_family;
        if (event->socket_family == AF_INET) {
            struct sockaddr_in *daddr = (struct sockaddr_in *)addr;
            bpf_probe_read(&event->remote_addr_v4, sizeof(event->remote_addr_v4), &daddr->sin_addr.s_addr);
            bpf_probe_read(&port, sizeof(port), &daddr->sin_port);
            event->remote_port = bpf_ntohs(port);
            // cleanup the local address
            event->local_addr_v4 = 0;
        } else if (event->socket_family == AF_INET6) {
            struct sockaddr_in6 *daddr = (struct sockaddr_in6 *)addr;
            bpf_probe_read(&event->remote_addr_v6, sizeof(event->remote_addr_v6), &daddr->sin6_addr.s6_addr);
            bpf_probe_read(&port, sizeof(port), &daddr->sin6_port);
            event->remote_port = bpf_ntohs(port);
            __builtin_memset(&event->local_addr_v6, 0, sizeof(event->local_addr_v6));
        }
    } else {
        event->socket_family = AF_UNKNOWN;
        socket_family = AF_UNKNOWN;
    }

    struct active_connection_t con = {};
    bool filtered = connection_filter_on_connect(event, &con.filter);

    rover_submit_buf(ctx, &socket_connection_event_queue, event, sizeof(*event));
    if (success == false) {
        return;
    }

    if (tgid_is_ztunnel(tgid)) {
        // if the connection is ztunnel, then not save into the active connection
        return;
    }

    // if connect success, then add the activate connection into the kernel
    // active connection save
    con.random_id = random_id;
    con.pid = tgid;
    con.sockfd = fd;
    con.role = role;
    con.socket_family = socket_family;
    if (bpf_map_update_elem(&active_connection_map, &conid, &con, 0) != 0) {
        // not an active connection (the map is full): nothing of it is followed
        h2c_forget_connection(conid);
        return;
    }
    // a filtered connection uploads nothing, so it is never followed either
    if (filtered) {
        h2c_forget_connection(conid);
    } else {
        h2c_follow_new_connection(conid, random_id, func_name);
    }
}

// func_role: the function name << 8 | the role (a BPF call takes five arguments); role_sk: the socket the role is read
// from when it is not known (sock_data_args_t.role_sk), NULL for none
#define GET_OR_CREATE_FUNC_ROLE(func_name, role) ((((__u32)(func_name)) << 8) | (__u8)(role))
static __noinline struct active_connection_t* get_or_create_active_conn(void *ctx, __u32 tgid, __u32 fd, __u32 func_role, void *role_sk) {
    __u32 func_name = func_role >> 8;
    __u8 role = func_role & 0xff;
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t *conn = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (conn != NULL) {
        return conn;
    }
    if (role == CONNECTION_ROLE_TYPE_UNKNOWN && role_sk != NULL) {
        role = get_sock_role(CONNECTION_ROLE_TYPE_UNKNOWN, (struct sock *)role_sk);
    }
    submit_new_connection(ctx, true, func_name, tgid, fd, 0, NULL, NULL, NULL, role);
    return bpf_map_lookup_elem(&active_connection_map, &conid);
}


static __inline void submit_connection_when_not_exists(void *ctx, __u64 id, struct connect_args_t* connect_args, __u32 func_name, __u8 role) {
    __u32 tgid = (__u32)(id >> 32);
    __u32 fd = connect_args->fd;

    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t *conn = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (conn != NULL) {
       return;
    }
    submit_new_connection(ctx, true, func_name, tgid, connect_args->fd, connect_args->start_nacs, connect_args->addr, NULL, &connect_args->remote, role);
}

// release_connection_state drops the per connection state the socket calls of a connection keep, on
// every close, filtered or not: a socket fd is reused by the next connection of the process
static __inline void release_connection_state(__u64 conid) {
    bpf_map_delete_elem(&socket_data_last_id_map, &conid);
    bpf_map_delete_elem(&socket_data_id_generate_map, &conid);
    h2c_forget_connection(conid);
}

static __inline void notify_close_connection(void* ctx, __u64 conid, struct active_connection_t* con, __u64 start_time, __u64 end_time, int ret) {
    // the skipped calls of an HTTP/1 body that are still held come before the close (syscalls/h1.h)
    h1_flush_connection(ctx, conid, con->random_id);
    // the summaries of the current streams go with the batch below (common/h2c_sum.h)
    h2c_sum_close(ctx, conid, con->random_id);
    // the batched records of this CPU go out before the close notification; records of this connection on
    // other CPUs flush within the kick period, which is below the user-space gap wait (see h2c_batch.h)
    if (h2c_batching()) {
        h2c_batch_flush(ctx);
    }
    release_connection_state(conid);
    struct socket_close_event_t *close_event;
    close_event = rover_reserve_buf(&socket_close_event_queue, sizeof(*close_event));
    if (close_event == NULL) {
        return;
    }

    close_event->conid = conid;
    close_event->random_id = con->random_id;
    close_event->start_time = start_time;
    close_event->end_time = end_time;
    close_event->pid = con->pid;
    close_event->sockfd = con->sockfd;
    close_event->success = ret > 0 ? true : false;

    rover_submit_buf(ctx, &socket_close_event_queue, close_event, sizeof(*close_event));
}

static __inline void submit_close_connection(void* ctx, __u32 tgid, __u32 fd, __u64 start_nacs, int ret) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t* con = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (con == NULL) {
        // the data id generator of a socket call may exist without an active connection; the rest of the
        // connection state cannot
        bpf_map_delete_elem(&socket_data_id_generate_map, &conid);
        return;
    }
    // a filtered connection is only dropped, nothing is notified
    if (connection_filtered(&con->filter)) {
        release_connection_state(conid);
        bpf_map_delete_elem(&active_connection_map, &conid);
        return;
    }
    notify_close_connection(ctx, conid, con, start_nacs, curr_nacs, ret);
    bpf_map_delete_elem(&active_connection_map, &conid);
}