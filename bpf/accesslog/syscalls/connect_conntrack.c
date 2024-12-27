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

#include "connect_conntrack.h"
#include "../common/data_args.h"

static __always_inline void nf_conntrack_read_in6_addr(__u64 *addr_h, __u64 *addr_l, const struct in6_addr *in6) {
    bpf_probe_read(addr_h, sizeof(*addr_h), &in6->s6_addr32[0]);
    bpf_probe_read(addr_l, sizeof(*addr_l), &in6->s6_addr32[2]);
}

static __always_inline int nf_conntrack_tuple_to_conntrack_tuple(struct connect_args_t *connect_args, conntrack_tuple_t *t, const struct nf_conntrack_tuple *ct) {
    __builtin_memset(t, 0, sizeof(conntrack_tuple_t));

    switch (ct->dst.protonum) {
        case IPPROTO_TCP:
            t->sport = ct->src.u.tcp.port;
            t->dport = ct->dst.u.tcp.port;
            break;
        case IPPROTO_UDP:
            t->sport = ct->src.u.udp.port;
            t->dport = ct->dst.u.udp.port;
            break;
        default:
            return 0;
    }

    t->sport = bpf_ntohs(t->sport);
    t->dport = bpf_ntohs(t->dport);
    if (t->sport == 0 || t->dport == 0) {
        return 0;
    }

    if (ct->src.l3num == AF_INET) {
        t->saddr_l = ct->src.u3.ip;
        t->daddr_l = ct->dst.u3.ip;

        if (!t->saddr_l || !t->daddr_l) {
            return 0;
        }
    } else if (ct->src.l3num == AF_INET6) {
        nf_conntrack_read_in6_addr(&t->saddr_h, &t->saddr_l, &ct->src.u3.in6);
        nf_conntrack_read_in6_addr(&t->daddr_h, &t->daddr_l, &ct->dst.u3.in6);

        if (!t->saddr_h || !t->saddr_l || !t->daddr_h || !t->daddr_l) {
            return 0;
        }
    }

    struct sock *sock = connect_args->sock;
    struct socket *tmps = _(sock->sk_socket);
    if (tmps != NULL) {
        struct sock* s;
        BPF_CORE_READ_INTO(&s, tmps, sk);
        short unsigned int skc_family;
        BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
        if (skc_family == AF_INET) {
            __u16 local_port;
            BPF_CORE_READ_INTO(&local_port, s, __sk_common.skc_num);
            __u32 local_addr_v4;
            BPF_CORE_READ_INTO(&local_addr_v4, s, __sk_common.skc_rcv_saddr);
            // make sure connntrack with the same socket address
            if (local_addr_v4 != t->daddr_l || local_port != t->dport) {
                return 0;
            }
        }
    }
    return 1;
}

static __always_inline int nf_conn_aware(struct pt_regs* ctx, struct nf_conn *ct) {
    if (ct == NULL) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (!connect_args) {
        return 0;
    }

    // already contains the remote address
    if (connect_args->has_remote && &(connect_args->remote) != NULL) {
        return 0;
    }

    __u32 status;
    if (bpf_probe_read(&status, sizeof(status), &(ct->status)) != 0) {
        return 0; // Invalid ct pointer
    }

    if (!(status & IPS_CONFIRMED)) {
        return 0;
    }
    if (!(status & IPS_NAT_MASK)) {
        return 0;
    }

    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
    if (bpf_probe_read(&tuplehash, sizeof(tuplehash), &(ct->tuplehash)) != 0) {
        return 0; // Invalid ct pointer
    }

    struct nf_conntrack_tuple reply = tuplehash[IP_CT_DIR_REPLY].tuple;

    conntrack_tuple_t reply_conn = {};
    if (!nf_conntrack_tuple_to_conntrack_tuple(connect_args, &reply_conn, &reply)) {
        return 0;
    }

    struct connect_track_remote remote = {};
    remote.iph = reply_conn.saddr_h;
    remote.ipl = reply_conn.saddr_l;
    remote.port = reply_conn.sport;
    connect_args->remote = remote;
    connect_args->has_remote = 1;
    bpf_map_update_elem(&conecting_args, &id, connect_args, 0);

    return 0;
}

SEC("kprobe/__nf_conntrack_hash_insert")
int nf_conntrack_hash_insert(struct pt_regs* ctx) {
    return nf_conn_aware(ctx, (struct nf_conn*)PT_REGS_PARM1(ctx));
}

SEC("kprobe/nf_confirm")
int nf_confirm(struct pt_regs* ctx) {
    return nf_conn_aware(ctx, (struct nf_conn*)PT_REGS_PARM3(ctx));
}

SEC("kprobe/ctnetlink_fill_info")
int nf_ctnetlink_fill_info(struct pt_regs* ctx) {
    return nf_conn_aware(ctx, (struct nf_conn*)PT_REGS_PARM5(ctx));
}