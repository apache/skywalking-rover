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

// ZTUNNEL_CONNECTION_RESULT_WINDOW is how many bytes of ztunnel's ConnectionResult the identity
// probe copies out. The struct measured 408 bytes on ztunnel 1.28, so this leaves headroom for
// the layout to grow across versions; user space still refuses any offset set whose own recorded
// window exceeds what was copied here, so a future ztunnel that outgrows the window degrades to
// "no identity" rather than to a truncated read.
#define ZTUNNEL_CONNECTION_RESULT_WINDOW 512

// ztunnel_connection_result_t carries a RAW copy of ztunnel's ConnectionResult. The probe
// deliberately does no field decoding: the field offsets are version specific and, on a binary
// with no debug info and no table entry, only discoverable by calibrating against known-good
// values at runtime. Shipping the bytes lets ALL of that logic - offset selection, pointer
// chasing into the refcounted string buffers, and the plausibility checks - live in user space,
// where it is testable and can be re-derived without reloading the BPF program.
struct ztunnel_connection_result_t {
    __u32 pid;
    __u32 window;
    __u8 data[ZTUNNEL_CONNECTION_RESULT_WINDOW];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ztunnel_connection_result_event_queue SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ztunnel_connection_result_t);
    __uint(max_entries, 1);
} ztunnel_connection_result_event_per_cpu_map SEC(".maps");

// the event is far larger than the BPF stack allows, so it is built in a per-CPU map slot,
// the same pattern the socket mapping event uses
static __inline struct ztunnel_connection_result_t* create_ztunnel_connection_result_event() {
  __u32 kZero = 0;
  return bpf_map_lookup_elem(&ztunnel_connection_result_event_per_cpu_map, &kZero);
}

// ztunnel_offsets_config_t is the RESOLVED ConnectionResult field offsets, pushed from user space
// once it has determined them(from the binary's DWARF, the pre-generated table, or runtime
// calibration). While no valid config exists for a pid the probe ships the full window above so
// user space can still calibrate; once a config is present the probe extracts only the fields
// named here and ships the much smaller compact event, cutting the perf-buffer bytes ~6x so a
// busy ztunnel loses far fewer samples. Offsets are signed because an absent field is -1
// (OffsetAbsent in user space) and the probe then leaves that pointer zero.
struct ztunnel_offsets_config_t {
    __s32 valid;                    // 0 until user space has resolved and written these offsets
    __s32 src;                      // SocketAddr offsets within ConnectionResult
    __s32 dst;
    __s32 reporter;                 // single-byte direction enums(absolute within ConnectionResult)
    __s32 security_policy;
    __s32 has_direction;            // 1 when reporter/security_policy are meaningful
    __s32 source_principal;         // Identity::Spiffe base offsets within ConnectionResult
    __s32 destination_principal;
    __s32 source_namespace;         // nullable ArcStr pointer offsets
    __s32 destination_namespace;
    __s32 source_cluster;
    __s32 destination_cluster;
    __s32 identity_namespace;       // offsets WITHIN an Identity::Spiffe, added to a principal base
    __s32 identity_service_account;
};

// keyed by the ztunnel pid, mirroring the per-pid symbol-offset maps the TLS probes use; a
// ztunnel restart gets a fresh pid and therefore a fresh(initially absent) config.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ztunnel_offsets_config_t);
    __uint(max_entries, 16);
} ztunnel_offsets_config_map SEC(".maps");

// ztunnel_connection_result_compact_t is the lean event shipped once offsets are known: the peer
// addresses and direction decoded in the probe, plus the RAW pointer values of the identity
// strings(which live in refcounted heap buffers the probe cannot copy) for user space to follow
// via /proc/<pid>/mem exactly as it does today. ~88 bytes vs the 520 byte full window.
struct ztunnel_connection_result_compact_t {
    __u32 pid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  reporter;
    __u8  security_policy;
    __u8  has_direction;
    __u8  pad0;
    __u32 pad1;                 // explicit: the __u64 fields below need 8-byte alignment
    __u64 src_principal_ns_ptr;
    __u64 src_principal_sa_ptr;
    __u64 dst_principal_ns_ptr;
    __u64 dst_principal_sa_ptr;
    __u64 src_namespace_ptr;
    __u64 dst_namespace_ptr;
    __u64 src_cluster_ptr;
    __u64 dst_cluster_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ztunnel_connection_result_compact_event_queue SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ztunnel_connection_result_compact_t);
    __uint(max_entries, 1);
} ztunnel_connection_result_compact_event_per_cpu_map SEC(".maps");

static __inline struct ztunnel_connection_result_compact_t* create_ztunnel_connection_result_compact_event() {
  __u32 kZero = 0;
  return bpf_map_lookup_elem(&ztunnel_connection_result_compact_event_per_cpu_map, &kZero);
}