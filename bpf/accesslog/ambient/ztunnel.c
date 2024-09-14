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
    success = get_socket_addr_ip_in_ztunnel(success, (void *)PT_REGS_PARM3(ctx), &event->orginal_src_ip, &event->src_port);
    success = get_socket_addr_ip_in_ztunnel(success, (void *)PT_REGS_PARM4(ctx), &event->original_dst_ip, &event->dst_port);
    success = get_socket_addr_ip_in_ztunnel(success, (void *)PT_REGS_PARM5(ctx), &event->lb_dst_ip, NULL);
    if (!success) {
        return 0;
    }
    bpf_perf_event_output(ctx, &ztunnel_lb_socket_mapping_event_queue, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}
