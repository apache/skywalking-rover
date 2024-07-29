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

// syscall:connect
struct connect_args_t {
    __u32 fd;
    __u32 fix;
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
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_connection_event_queue SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_connect_event_t);
    __uint(max_entries, 1);
} socket_connect_event_per_cpu_map SEC(".maps");
static __inline struct socket_connect_event_t* create_socket_connect_event() {
  __u32 kZero = 0;
  return bpf_map_lookup_elem(&socket_connect_event_per_cpu_map, &kZero);
}

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
    __u8 pad0;
    __u32 pad1;
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
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_close_event_queue SEC(".maps");

static __inline bool family_should_trace(const __u32 family) {
    return family != AF_UNKNOWN && family != AF_INET && family != AF_INET6 ? false : true;
}

static __always_inline void submit_new_connection(void* ctx, bool success, __u32 func_name, __u32 tgid, __u32 fd, __u64 start_nacs,
                                            struct sockaddr* addr, const struct socket* socket, struct connect_track_remote* conntrack, __u8 role) {
    // send to the user-space the connection event
    __u64 curr_nacs = bpf_ktime_get_ns();
    struct socket_connect_event_t *event = create_socket_connect_event();
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
        event->role = CONNECTION_ROLE_TYPE_CLIENT;
    } else if (func_name == SOCKET_OPTS_TYPE_ACCEPT) {
        event->role = CONNECTION_ROLE_TYPE_SERVER;
    } else {
        event->role = role;
    }
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
    event->local_port = 0;
    event->remote_port = 0;
    if (socket != NULL) {
        // only get from accept function(server side)
        struct sock* s;
        BPF_CORE_READ_INTO(&s, socket, sk);

        short unsigned int skc_family;
        BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
        event->socket_family = skc_family;

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
    }

    bpf_perf_event_output(ctx, &socket_connection_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
    if (success == false) {
        return;
    }

    // if connect success, then add the activate connection into the kernel
    // active connection save
    struct active_connection_t con = {};
    con.random_id = event->random_id;
    con.pid = tgid;
    con.sockfd = fd;
    con.role = event->role;
    con.socket_family = event->socket_family;
    bpf_map_update_elem(&active_connection_map, &conid, &con, 0);
}

static __inline struct active_connection_t* get_or_create_active_conn(void *ctx, __u32 tgid, __u32 fd, __u32 func_name, __u8 role) {
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t *conn = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (conn != NULL) {
        return conn;
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

static __inline void notify_close_connection(void* ctx, __u64 conid, struct active_connection_t* con, __u64 start_time, __u64 end_time, int ret) {
    struct socket_close_event_t close_event = {};

    close_event.conid = conid;
    close_event.random_id = con->random_id;
    close_event.start_time = start_time;
    close_event.end_time = end_time;
    close_event.pid = con->pid;
    close_event.sockfd = con->sockfd;
    close_event.success = ret > 0 ? true : false;

    bpf_perf_event_output(ctx, &socket_close_event_queue, BPF_F_CURRENT_CPU, &close_event, sizeof(close_event));
}

static __inline void submit_close_connection(void* ctx, __u32 tgid, __u32 fd, __u64 start_nacs, int ret) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t* con = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (con == NULL) {
        return;
    }
    notify_close_connection(ctx, conid, con, start_nacs, curr_nacs, ret);
    bpf_map_delete_elem(&active_connection_map, &conid);
}