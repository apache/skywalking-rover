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

struct ztunnel_socket_mapping_t {
    __u32 orginal_src_ip;       // origin local ip
    __u32 original_dst_ip;      // origin remote ip(should be service ip)
    __u16 src_port;             // origin local port
    __u16 dst_port;             // origin remote port
    __u32 lb_dst_ip;            // load balanced remote ip(should be real pod ip)
    __u16 lb_dst_port;          // load balanced remote port
    __u16 pad0;
    __u32 pad1;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ztunnel_lb_socket_mapping_event_queue SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ztunnel_socket_mapping_t);
    __uint(max_entries, 1);
} ztunnel_socket_mapping_event_per_cpu_map SEC(".maps");

static __inline struct ztunnel_socket_mapping_t* create_ztunnel_socket_mapping_event() {
  __u32 kZero = 0;
  return bpf_map_lookup_elem(&ztunnel_socket_mapping_event_per_cpu_map, &kZero);
}