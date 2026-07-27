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

#include "ztunnel.h"

static __inline bool get_socket_addr_ip_in_ztunnel(bool success, void * arg, __u32 *ip, __u16 *port) {
    if (!success) {
        return false;
    }
    __u8 sockaddr[8];
    if (bpf_probe_read(&sockaddr, sizeof(sockaddr), (void *)arg) != 0) {
       return false;
    }
    // ip is stored in sockaddr[2], sockaddr[3], sockaddr[4], sockaddr[5]
    *ip = ((__u32)sockaddr[2] << 24) | ((__u32)sockaddr[3] << 16) | ((__u32)sockaddr[4] << 8) | (__u32)sockaddr[5];
    if (port != NULL) {
        // port is stored in sockaddr[6], sockaddr[7](should convert to big-endian)
        *port = ((__u16)sockaddr[7] << 8) | sockaddr[6];
    }
    return true;
}

// read_ztunnel_compact_ptr reads the 8-byte ArcStr pointer value at self+off. A negative off marks
// an absent field(OffsetAbsent in user space) and yields a zero pointer, which user space decodes
// as "field not present". A failed read also yields zero, so a garbage offset degrades to a miss.
static __inline __u64 read_ztunnel_compact_ptr(void *self, __s32 off) {
    __u64 ptr = 0;
    if (off < 0) {
        return 0;
    }
    bpf_probe_read_user(&ptr, sizeof(ptr), (void *)((char *)self + off));
    return ptr;
}

SEC("uprobe/connection_manager_track_outbound")
int connection_manager_track_outbound(struct pt_regs* ctx) {
    struct ztunnel_socket_mapping_t *event = create_ztunnel_socket_mapping_event();
    if (event == NULL) {
        return 0;
    }
    bool success = true;
    // track_outbound(&self, src, original_dst, actual_dst) returns a large ConnectionResult
    // struct via a hidden sret pointer. On x86-64 SysV the sret pointer occupies the first
    // integer arg register(PARM1), so &self is PARM2 and the three SocketAddr args are PARM3/4/5.
    // On AArch64 AAPCS64 the sret pointer is passed in x8, which is OUTSIDE the PARM1..8 arg
    // registers, so the arguments are NOT shifted: &self is PARM1 and the args are PARM2/3/4.
    // original_dst is the service ClusterIP, actual_dst is the load balanced real pod.
#if defined(bpf_target_x86)
    void *src_arg = (void *)PT_REGS_PARM3(ctx);
    void *original_dst_arg = (void *)PT_REGS_PARM4(ctx);
    void *actual_dst_arg = (void *)PT_REGS_PARM5(ctx);
#else
    void *src_arg = (void *)PT_REGS_PARM2(ctx);
    void *original_dst_arg = (void *)PT_REGS_PARM3(ctx);
    void *actual_dst_arg = (void *)PT_REGS_PARM4(ctx);
#endif
    success = get_socket_addr_ip_in_ztunnel(success, src_arg, &event->orginal_src_ip, &event->src_port);
    success = get_socket_addr_ip_in_ztunnel(success, original_dst_arg, &event->original_dst_ip, &event->dst_port);
    success = get_socket_addr_ip_in_ztunnel(success, actual_dst_arg, &event->lb_dst_ip, &event->lb_dst_port);
    if (!success) {
        return 0;
    }
    bpf_perf_event_output(ctx, &ztunnel_lb_socket_mapping_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// ConnectionResult::new(src: SocketAddr, dst: SocketAddr, hbone_target, ...) is an
// associated function(no &self) that ztunnel constructs UNCONDITIONALLY for every proxied
// connection - including the outbound legs that skip track_outbound through an early-return
// in proxy_to - so it is a strictly-higher-coverage, log-level-independent source(the same
// data ztunnel would print as the "connection complete"/"connection opened" access log, but
// captured at construction time regardless of the log level). It returns a large struct via
// the hidden sret pointer, which on x86-64 occupies PARM1 and shifts the arguments by one
// (src=PARM2, dst=PARM3); on AArch64 the sret pointer is in x8(not a PARM) so the arguments
// are not shifted(src=PARM1, dst=PARM2). src is the downstream app addr and dst is the REAL
// backend pod addr. There is no service ClusterIP among the arguments, so this mapping is
// keyed by the source address alone in user space(the app's ephemeral src port is unique per
// connection). original_dst_ip is left zero to mark this event as a "src-only" mapping.
SEC("uprobe/connection_result_new")
int connection_result_new(struct pt_regs* ctx) {
    struct ztunnel_socket_mapping_t *event = create_ztunnel_socket_mapping_event();
    if (event == NULL) {
        return 0;
    }
    bool success = true;
#if defined(bpf_target_x86)
    void *src_arg = (void *)PT_REGS_PARM2(ctx);
    void *dst_arg = (void *)PT_REGS_PARM3(ctx);
#else
    void *src_arg = (void *)PT_REGS_PARM1(ctx);
    void *dst_arg = (void *)PT_REGS_PARM2(ctx);
#endif
    success = get_socket_addr_ip_in_ztunnel(success, src_arg, &event->orginal_src_ip, &event->src_port);
    success = get_socket_addr_ip_in_ztunnel(success, dst_arg, &event->lb_dst_ip, &event->lb_dst_port);
    if (!success) {
        return 0;
    }
    event->original_dst_ip = 0;
    event->dst_port = 0;
    bpf_perf_event_output(ctx, &ztunnel_lb_socket_mapping_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// ConnectionResult::record_internal(&mut self, res) is the function that WRITES the ztunnel
// access log line, so &self holds exactly what that line carries: the peer addresses, the
// HBONE target(the real backend pod), and the whole CommonTrafficLabels - which includes the
// source/destination principals and clusters. Reading it here replaces tailing the access log
// file entirely, and does so a poll interval earlier(no kubelet write + tailer read in between).
//
// It is the most stable probe point available: present in every ztunnel from 1.24 through
// master and in the vendor rebuilds, and - unlike the ConnectionResult constructors, which
// return a large struct through a hidden sret pointer that shifts the argument registers on
// x86-64 but not on AArch64 - it returns unit, so &self is in PARM1 on BOTH architectures with
// no arch-conditional register juggling.
//
// record_internal is generic over the error type, so Rust may emit several monomorphized
// copies; user space attaches to every matching symbol(see the attach helper in ztunnel.go).
SEC("uprobe/connection_result_record_internal")
int connection_result_record_internal(struct pt_regs* ctx) {
    void *self = (void *)PT_REGS_PARM1(ctx);
    if (self == NULL) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ztunnel_offsets_config_t *cfg = bpf_map_lookup_elem(&ztunnel_offsets_config_map, &pid);

    // FAST PATH: once user space has resolved the offsets and written them here, extract only the
    // named fields and ship the ~88 byte compact event instead of the 520 byte window. The identity
    // strings live behind pointers in refcounted heap buffers the probe cannot copy, so their raw
    // addresses are shipped for user space to follow via /proc/<pid>/mem, exactly as it does today.
    if (cfg != NULL && cfg->valid) {
        struct ztunnel_connection_result_compact_t *ev = create_ztunnel_connection_result_compact_event();
        if (ev == NULL) {
            return 0;
        }
        // clear the reused per-CPU slot so no stale field from a previous event leaks through
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->pid = pid;
        // reuse the same SocketAddr decoder the mapping probes use; the event slot is memset to 0
        // so a failed read leaves ip/port zero, and user space treats a zero src as "not a usable
        // peer"(decodeCompact), so no separate BPF-side zero check is needed here
        get_socket_addr_ip_in_ztunnel(true, (void *)((char *)self + cfg->src), &ev->src_ip, &ev->src_port);
        get_socket_addr_ip_in_ztunnel(true, (void *)((char *)self + cfg->dst), &ev->dst_ip, &ev->dst_port);
        // gate each single-byte read on its OWN offset being present: user space derives
        // has_direction from reporter alone, so a set with reporter present but security_policy
        // absent(-1) must still not read self+(-1). "direction known" means the reporter byte is
        // meaningful; the security_policy byte is read independently when its offset resolved.
        ev->has_direction = cfg->reporter >= 0 ? 1 : 0;
        if (cfg->reporter >= 0) {
            bpf_probe_read_user(&ev->reporter, sizeof(ev->reporter), (void *)((char *)self + cfg->reporter));
        }
        if (cfg->security_policy >= 0) {
            bpf_probe_read_user(&ev->security_policy, sizeof(ev->security_policy), (void *)((char *)self + cfg->security_policy));
        }
        // identity string pointers: the two principal members are read at principal_base + member,
        // the namespace/cluster labels at their own offsets; an absent base(-1) yields a null pointer
        __s32 src_p = cfg->source_principal, dst_p = cfg->destination_principal;
        ev->src_principal_ns_ptr = read_ztunnel_compact_ptr(self, src_p < 0 ? -1 : src_p + cfg->identity_namespace);
        ev->src_principal_sa_ptr = read_ztunnel_compact_ptr(self, src_p < 0 ? -1 : src_p + cfg->identity_service_account);
        ev->dst_principal_ns_ptr = read_ztunnel_compact_ptr(self, dst_p < 0 ? -1 : dst_p + cfg->identity_namespace);
        ev->dst_principal_sa_ptr = read_ztunnel_compact_ptr(self, dst_p < 0 ? -1 : dst_p + cfg->identity_service_account);
        ev->src_namespace_ptr = read_ztunnel_compact_ptr(self, cfg->source_namespace);
        ev->dst_namespace_ptr = read_ztunnel_compact_ptr(self, cfg->destination_namespace);
        ev->src_cluster_ptr = read_ztunnel_compact_ptr(self, cfg->source_cluster);
        ev->dst_cluster_ptr = read_ztunnel_compact_ptr(self, cfg->destination_cluster);
        bpf_perf_event_output(ctx, &ztunnel_connection_result_compact_event_queue, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
        return 0;
    }

    // SLOW PATH: offsets not resolved yet(user space is still calibrating), so ship the full window
    // and let it scan. A partial read leaves stale bytes from the previous event in the per-CPU
    // slot, which user space could decode as a plausible-looking identity belonging to another
    // connection, so a failed copy drops the event instead of forwarding it.
    struct ztunnel_connection_result_t *event = create_ztunnel_connection_result_event();
    if (event == NULL) {
        return 0;
    }
    event->pid = pid;
    event->window = ZTUNNEL_CONNECTION_RESULT_WINDOW;
    if (bpf_probe_read_user(&event->data, sizeof(event->data), self) != 0) {
        return 0;
    }
    bpf_perf_event_output(ctx, &ztunnel_connection_result_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}
