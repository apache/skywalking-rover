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

// nf_conn_aware_ct: confirmed is false when the caller is the confirmation of ct itself, before it set IPS_CONFIRMED
// (the kprobe at the entry of __nf_conntrack_confirm): the NAT of the entry is set up by then (the nat hooks run before
// the confirm), only the bit is missing
static __always_inline int nf_conn_aware_ct(void* ctx, struct nf_conn *ct, bool confirmed) {
    // (every packet of the host comes here: nothing to do while no thread is in a connect, common/connection.h)
    if (ct == NULL || conecting_args_live == 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args = conecting_args_get(&id);
    if (!connect_args) {
        return 0;
    }

    // already contains the remote address
    if (connect_args->has_remote) {
        return 0;
    }

    __u32 status;
    if (bpf_probe_read(&status, sizeof(status), &(ct->status)) != 0) {
        return 0; // Invalid ct pointer
    }

    if (confirmed && !(status & IPS_CONFIRMED)) {
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
    // (connect_args points into the thread's entry of conecting_args: written in place)
    connect_args->remote = remote;
    connect_args->has_remote = 1;

    return 0;
}

static __always_inline int nf_conn_aware(void* ctx, struct nf_conn *ct) {
    return nf_conn_aware_ct(ctx, ct, true);
}

SEC("kprobe/__nf_conntrack_hash_insert")
int nf_conntrack_hash_insert(struct pt_regs* ctx) {
    return nf_conn_aware(ctx, (struct nf_conn*)PT_REGS_PARM1(ctx));
}

SEC("kprobe/nf_confirm")
int nf_confirm(struct pt_regs* ctx) {
    return nf_conn_aware(ctx, (struct nf_conn*)PT_REGS_PARM3(ctx));
}

// the fentry twin of the trampoline attach (common/sys_attach.h), only for the NAT hook legacy: every packet of the
// host passes nf_confirm, and the program has nothing to do while no thread is in a connect. The third argument, as
// the kprobe takes it: the loader only attaches the twin where the kernel BTF says that argument is the struct
// nf_conn (nf_confirm(skb, protoff, ct, ctinfo)), not the hook state of nf_confirm(priv, skb, state) (6.x).
SEC("fentry/nf_confirm")
int fentry_nf_confirm(__u64 *ctx) {
    return nf_conn_aware(ctx, (struct nf_conn*)ctx[2]);
}


// The confirmation of a new conntrack entry: __nf_conntrack_confirm(skb) runs once per new entry, for the first
// packet of a connect in the connecting thread (the SYN goes through the output hooks in connect), and at its exit the
// entry is confirmed and its NAT set up. __nf_conntrack_hash_insert, which it calls, is inlined on some newer kernels (6.12)
// and, where it is not, runs before IPS_CONFIRMED is set there, so the legacy hook never sees a confirmed entry;
// and nf_confirm, hooked for every packet of the host, gets the hook state as its third argument since its signature
// became (priv, skb, state), where the kprobes read the entry: neither found a NAT on 6.12. The entry of the packet is
// skb->_nfct without the ctinfo bits (NFCT_PTRMASK).
#define ACCESSLOG_NFCT_PTRMASK (~7UL)
#define ACCESSLOG_NF_ACCEPT 1

static __always_inline struct nf_conn *nf_conn_of_skb(struct sk_buff *skb) {
    long unsigned int nfct = 0;
    if (skb == NULL || bpf_core_read(&nfct, sizeof(nfct), &skb->_nfct) != 0) {
        return NULL;
    }
    return (struct nf_conn *)(nfct & ACCESSLOG_NFCT_PTRMASK);
}

// the trampoline: once the entry is confirmed (NF_ACCEPT), with the same checks as nf_confirm
SEC("fexit/__nf_conntrack_confirm")
int fexit_nf_conntrack_confirm(__u64 *ctx) {
    if (conecting_args_live == 0 || (int)ctx[1] != ACCESSLOG_NF_ACCEPT) {
        return 0;
    }
    return nf_conn_aware_ct(ctx, nf_conn_of_skb((struct sk_buff *)ctx[0]), true);
}

// without trampolines and without the symbol __nf_conntrack_hash_insert: the entry of the confirmation, before the bit
SEC("kprobe/__nf_conntrack_confirm")
int kprobe_nf_conntrack_confirm(struct pt_regs *ctx) {
    if (conecting_args_live == 0) {
        return 0;
    }
    return nf_conn_aware_ct(ctx, nf_conn_of_skb((struct sk_buff *)PT_REGS_PARM1(ctx)), false);
}
