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

struct node_tls_symaddr_t {
    __u32 tlsWrapStreamListenerOffset;
    __u32 streamListenerStreamOffset;
    __u32 streamBaseStreamResourceOffset;
    __u32 libuvStreamWrapStreamBaseOffset;
    __u32 libuvStreamWrapStreamOffset;
    __u32 uvStreamSIOWatcherOffset;
    __u32 uvIOSFDOffset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, void*);
} node_tls_wrap_construct_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, void*);
	__type(value, void*);
} node_tls_ssl_wrap_mapping SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, struct node_tls_symaddr_t);
} node_tls_symaddr_map SEC(".maps");
static __inline int get_node_tls_wrap_fd(__u32 tgid, void *tlsWrap) {
    struct node_tls_symaddr_t *addr = bpf_map_lookup_elem(&node_tls_symaddr_map, &tgid);
    if (addr == NULL) {
        return -1;
    }

    void *stream = NULL;
    bpf_probe_read(&stream, sizeof(stream), tlsWrap + addr->tlsWrapStreamListenerOffset + addr->streamListenerStreamOffset);
    if (stream == NULL) {
        return -1;
    }

    void *uv_stream = NULL;
    bpf_probe_read(&uv_stream, sizeof(uv_stream), stream - addr->streamBaseStreamResourceOffset - addr->libuvStreamWrapStreamBaseOffset +
                                                          addr->libuvStreamWrapStreamOffset);
    if (uv_stream == NULL) {
        return -1;
    }

    __u64 fd;
    bpf_probe_read(&fd, sizeof(fd), uv_stream + addr->uvStreamSIOWatcherOffset + addr->uvIOSFDOffset);
    return fd;
}
static __inline int get_node_tls_fd(__u32 tgid, void *ssl) {
    void **tlsWrap = bpf_map_lookup_elem(&node_tls_ssl_wrap_mapping, &ssl);
    if (tlsWrap == NULL) {
        return -1;
    }
    return get_node_tls_wrap_fd(tgid, *tlsWrap);
}