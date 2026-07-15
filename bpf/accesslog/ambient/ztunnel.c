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
