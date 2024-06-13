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

package collector

import (
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/module"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var l24CollectorsInstance = NewL24Collector()

type L24Collector struct {
}

func NewL24Collector() *L24Collector {
	return &L24Collector{}
}

func (c *L24Collector) Start(mgr *module.Manager, context *common.AccessLogContext) error {
	c.startWrite(mgr, context)
	c.startRead(mgr, context)
	return nil
}

func (c *L24Collector) startRead(_ *module.Manager, context *common.AccessLogContext) {
	// l2
	context.BPF.AddTracePoint("net", "netif_receive_skb", context.BPF.TracepointNetifReceiveSkb)

	// l3
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"ip_rcv": context.BPF.IpRcv})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"ip_rcv": context.BPF.IpRcvRet})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"ip_rcv_finish": context.BPF.IpRcvFinish})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"ip_local_deliver": context.BPF.IpLocalDeliver})
	// it's not exist in old kernel versions
	_ = context.BPF.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{"ip_list_rcv": context.BPF.IpListRcv})
	_ = context.BPF.AddLinkOrError(link.Kretprobe, map[string]*ebpf.Program{"ip_list_rcv": context.BPF.IpListRcvRet})
	_ = context.BPF.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{"ip_sublist_rcv_finish": context.BPF.IpSublistRcvFinish})
	_ = context.BPF.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{"ip_local_deliver_finish": context.BPF.IpLocalDeliverFinish})

	// l4
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_v4_rcv": context.BPF.TcpV4Rcv})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"tcp_v4_rcv": context.BPF.TcpV4RcvRet})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_v6_rcv": context.BPF.TcpV6Rcv})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"tcp_v6_rcv": context.BPF.TcpV6RcvRet})
}

func (c *L24Collector) startWrite(_ *module.Manager, context *common.AccessLogContext) {
	// l4
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_sendmsg": context.BPF.TcpSendmsg})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"tcp_sendmsg": context.BPF.TcpSendmsgRet})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"__tcp_transmit_skb": context.BPF.TcpTransmitSkb})
	context.BPF.AddTracePoint("tcp", "tcp_retransmit_skb", context.BPF.TracepointTcpRetransmitSkb)
	context.BPF.AddTracePoint("skb", "kfree_skb", context.BPF.KfreeSkb)

	// l3
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"__ip_queue_xmit": context.BPF.IpQueueXmit})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"__ip_queue_xmit": context.BPF.IpQueueXmitRet})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"__ip_local_out": context.BPF.IpLocal})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"ip_output": context.BPF.IpOutput})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"ip_finish_output2": context.BPF.IpFinishOutput2})
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"neigh_resolve_output": context.BPF.NeighResolveOutput})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"neigh_resolve_output": context.BPF.NeighResolveOutputRet})

	// netlink
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"nf_hook_slow": context.BPF.NfHookSlow})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"nf_hook_slow": context.BPF.NfHookSlowRet})

	// l2
	context.BPF.AddLink(link.Kprobe, map[string]*ebpf.Program{"__dev_queue_xmit": context.BPF.DevQueueEmit})
	context.BPF.AddLink(link.Kretprobe, map[string]*ebpf.Program{"__dev_queue_xmit": context.BPF.DevQueueEmitRet})
	context.BPF.AddTracePoint("net", "net_dev_start_xmit", context.BPF.TracepointNetDevStartXmit)
	context.BPF.AddTracePoint("net", "net_dev_xmit", context.BPF.TracepointNetDevXmit)
}

func (c *L24Collector) Stop() {
}
