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

#include "socket_detail.h"
#include "args.h"
#include "sock_stats.h"

SEC("kprobe/ip_finish_output")
int ip_finish_output(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args == NULL) {
        return 0;
    }

    struct sk_buff *buff = (void *)PT_REGS_PARM3(ctx);
    long unsigned int _skb_refdst;
    bpf_probe_read(&_skb_refdst, sizeof(_skb_refdst), &buff->_skb_refdst);
    struct dst_entry *entry = (void *)(_skb_refdst & SKB_DST_PTRMASK);
    struct net_device *device;
    bpf_probe_read(&device, sizeof(device), &entry->dev);

    int ifindex;
    bpf_probe_read(&ifindex, sizeof(ifindex), &device->ifindex);

    unsigned int data_len;
    bpf_probe_read(&data_len, sizeof(data_len), &buff->len);

    data_args->package_count++;
    data_args->total_package_size += data_len;
    data_args->ifindex = ifindex;

     struct sock *sock = (void *)PT_REGS_PARM2(ctx);
    struct tcp_sock *tcp_sock = (struct tcp_sock *)sock;
     __u32 packets_out;
    __u32 retrans_out;
    __u32 srtt;
    BPF_CORE_READ_INTO(&srtt, tcp_sock, srtt_us);
    srtt = srtt >> 3;
    BPF_CORE_READ_INTO(&packets_out, tcp_sock, packets_out);
    BPF_CORE_READ_INTO(&retrans_out, tcp_sock, retrans_out);
    return 0;
}

SEC("kprobe/skb_copy_datagram_iter")
int skb_copy_datagram_iter(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args = bpf_map_lookup_elem(&socket_data_args, &id);
    if (data_args == NULL) {
        return 0;
    }
    __u64 conid = gen_tgid_fd((__u32)(id >> 32), data_args->fd);
    struct active_connection_t *con = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (con == NULL) {
        return 0;
    }

    const struct sk_buff *buff = (void *)PT_REGS_PARM1(ctx);
    int len = PT_REGS_PARM4(ctx);
    int ifindex;
    bpf_probe_read(&ifindex, sizeof(ifindex), &buff->skb_iif);

    if (con->last_recv_sk_buff == NULL || con->last_recv_sk_buff != buff || data_args->package_count == 0) {
        data_args->package_count++;
        con->last_recv_sk_buff = (void *)buff;
    }
    data_args->ifindex = ifindex;
    data_args->total_package_size += len;

    struct sock *sock;
    bpf_probe_read(&sock, sizeof(sock), &buff->sk);
    struct tcp_sock *tcp_sock = (struct tcp_sock *)sock;
    __u32 packets_out;
    __u32 retrans_out;
    bpf_probe_read(&packets_out, sizeof(packets_out), &tcp_sock->packets_out);
    bpf_probe_read(&retrans_out, sizeof(retrans_out), &tcp_sock->retrans_out);
    return 0;
}
