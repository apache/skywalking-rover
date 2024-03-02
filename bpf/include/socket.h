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

#define SKB_DST_NOREF	1UL
#define SKB_DST_PTRMASK	~(SKB_DST_NOREF)
typedef int64_t s64;
typedef s64	ktime_t;

struct in6_addr_redefine {
	union {
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
} __attribute__((preserve_access_index));

typedef __u32 __portpair;
typedef __u64 __addrpair;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

struct sock_common {
	union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;
			__be32	skc_rcv_saddr;
		} __attribute__((preserve_access_index));
	};
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;
			__u16	skc_num;
		} __attribute__((preserve_access_index));
	};
	short unsigned int skc_family;
	struct in6_addr_redefine		skc_v6_daddr;
    struct in6_addr_redefine		skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct socket {
	struct sock		*sk;
} __attribute__((preserve_access_index));

struct iov_iter {
	__u64 count;
	union {
		const struct iovec *iov;
		const struct iovec *__iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
		struct xarray *xarray;
		struct pipe_inode_info *pipe;
	};
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common	__sk_common;
	struct socket		*sk_socket;
	__u32			sk_max_ack_backlog;
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u32 srtt_us;
	__u32 copied_seq;
    __u32 write_seq;
    __u32 packets_out;
    __u32 retrans_out;
} __attribute__((preserve_access_index));

struct user_msghdr {
	void		*msg_name;	/* ptr to socket address structure */
	struct iovec	*msg_iov;	/* scatter/gather array */
	__kernel_size_t	msg_iovlen;		/* # elements in msg_iov */
} __attribute__((preserve_access_index));

struct mmsghdr {
	struct user_msghdr msg_hdr;
	unsigned int msg_len;
} __attribute__((preserve_access_index));

struct list_head {
	struct list_head *next;
	struct list_head *prev;
} __attribute__((preserve_access_index));
struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((preserve_access_index));

struct sk_buff {
    union {
        struct {
            struct sk_buff *next;
            struct sk_buff *prev;
            union {
                 struct net_device *dev;
                 long unsigned int dev_scratch;
            };
        } __attribute__((preserve_access_index));
        struct rb_node rbnode;
        struct list_head list;
    };
	struct sock		*sk;
	union {
        struct {
            long unsigned int _skb_refdst;
            void (*destructor)(struct sk_buff *);
        };
        long unsigned int _sk_redir;
    };
    union {
        ktime_t tstamp;
        __u64 skb_mstamp_ns;
    };
    int			skb_iif;
    unsigned int len;
    unsigned int data_len;
    unsigned char		*head,
                        *data;
} __attribute__((preserve_access_index));

struct net {
	int			ifindex;
} __attribute__((preserve_access_index));

enum skb_drop_reason {
	SKB_DROP_REASON_NOT_SPECIFIED,
	SKB_DROP_REASON_NO_SOCKET,
	SKB_DROP_REASON_PKT_TOO_SMALL,
	SKB_DROP_REASON_TCP_CSUM,
	SKB_DROP_REASON_TCP_FILTER,
	SKB_DROP_REASON_UDP_CSUM,
	SKB_DROP_REASON_MAX,
};

struct dst_entry {
	struct net_device *dev;
} __attribute__((preserve_access_index));

struct net_device {
	int ifindex;
	unsigned long		state;
	unsigned int		mtu;
} __attribute__((preserve_access_index));

struct skb_shared_info {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff *frag_list;
	unsigned int gso_type;
	__u32 tskey;
	void *destructor_arg;
} __attribute__((preserve_access_index));