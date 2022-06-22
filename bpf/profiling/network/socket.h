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

struct sock {
	struct sock_common	__sk_common;
	struct socket		*sk_socket;
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u32 srtt_us;
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