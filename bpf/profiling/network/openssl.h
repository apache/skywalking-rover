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

struct openssl_fd_symaddr {
    // read the BIO offset from ssl
    __u32 bio_read_offset;
    __u32 bio_write_offset;
    // read the fd offset from BIO
    __u32 fd_offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, struct openssl_fd_symaddr);
} openssl_fd_symaddr_finder SEC(".maps");
static __inline struct openssl_fd_symaddr* get_openssl_fd_symaddr(__u32 tgid) {
    struct openssl_fd_symaddr *addr = bpf_map_lookup_elem(&openssl_fd_symaddr_finder, &tgid);
    return addr;
}

// openssl read or write
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} openssl_sock_data_args SEC(".maps");