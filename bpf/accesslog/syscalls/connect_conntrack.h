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

#include <linux/types.h>

#include <linux/netfilter/nf_conntrack_tuple_common.h>

typedef struct {
    /* Using the type unsigned __int128 generates an error in the ebpf verifier */
    __u64 saddr_h;
    __u64 saddr_l;
    __u64 daddr_h;
    __u64 daddr_l;
    __u16 sport;
    __u16 dport;
    __u32 netns;
    // Metadata description:
    // First bit indicates if the connection is TCP (1) or UDP (0)
    // Second bit indicates if the connection is V6 (1) or V4 (0)
    __u32 metadata; // This is that big because it seems that we atleast need a 32-bit aligned struct

    __u32 _pad;
} conntrack_tuple_t;


struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	/* Layer 3 protocol */
	u_int16_t l3num;
} __attribute__((preserve_access_index));


struct nf_conntrack_tuple {
	struct nf_conntrack_man src;
	/* These are the parts of the tuple which are fixed. */
    	struct {
    		union nf_inet_addr u3;
    		union {
    			/* Add other protocols here. */
    			__be16 all;

    			struct {
    				__be16 port;
    			} tcp;
    			struct {
    				__be16 port;
    			} udp;
    			struct {
    				u_int8_t type, code;
    			} icmp;
    			struct {
    				__be16 port;
    			} dccp;
    			struct {
    				__be16 port;
    			} sctp;
    			struct {
    				__be16 key;
    			} gre;
    		} u;

    		/* The protocol. */
    		u_int8_t protonum;

    		/* The direction (for tuplehash) */
    		u_int8_t dir;
    	} dst;
} __attribute__((preserve_access_index));

struct hlist_nulls_node {
	struct hlist_nulls_node *next, **pprev;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple_hash {
    struct hlist_nulls_node hnnode;
	struct nf_conntrack_tuple tuple;
} __attribute__((preserve_access_index));

struct nf_conn {
	__u32 timeout;
	struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
	long unsigned int status;
	__u32 mark;
} __attribute__((preserve_access_index));