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
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

var l24Log = logger.GetLogger("access_log", "collector", "l24")

const (
	// l24StoreCapacity bounds the details kept: some 200 bytes each with the map, so about 40MB when it is full
	l24StoreCapacity = 200000
	// the details live l24TTLFlushes flush periods (at least l24MinTTL) until a kernel log takes them, and one flush
	// period after that
	l24TTLFlushes = 3
	l24MinTTL     = 5 * time.Second
	// l24QueuePerCPUBuffer is the per-CPU perf buffer of the l24 events (152 bytes each)
	l24QueuePerCPUBuffer = 512 * 1024
)

// L24Collector collects the L2 to L4 details of the socket calls (access_log.kernel_metrics.l2_l3): it attaches the
// programs of bpf/accesslog/l24 and keeps the events they send in the store the kernel transfer logs take them from
// (events.L24Store, pkg/accesslog/forwarder/transfer.go). With the switch off it does nothing.
type L24Collector struct {
	store *events.L24Store
}

func NewL24Collector() *L24Collector {
	return &L24Collector{}
}

// l24Hook is a kernel function or tracepoint of an l24 program
type l24Hook struct {
	program string
	// kind: kprobe, kretprobe or tracepoint ("group/name" in symbol)
	kind   string
	symbol string
}

// l24Hooks are the hooks of bpf/accesslog/l24. None is required: a hook the kernel does not have (the static
// functions ip_rcv_finish and ip_local_deliver_finish are inlined by some builds, ip_list_rcv and
// ip_sublist_rcv_finish are 4.19+) only leaves its metrics at 0.
var l24Hooks = []l24Hook{
	// write: L4
	{"l24_tcp_sendmsg", "kprobe", "tcp_sendmsg"},
	{"l24_tcp_sendmsg_ret", "kretprobe", "tcp_sendmsg"},
	{"l24_tcp_transmit_skb", "kprobe", "__tcp_transmit_skb"},
	{"l24_tcp_retransmit_skb", "tracepoint", "tcp/tcp_retransmit_skb"},
	// write: L3
	{"l24_ip_queue_xmit", "kprobe", "__ip_queue_xmit"},
	{"l24_ip_queue_xmit_ret", "kretprobe", "__ip_queue_xmit"},
	{"l24_ip_local_out", "kprobe", "__ip_local_out"},
	{"l24_ip_output", "kprobe", "ip_output"},
	{"l24_ip_finish_output2", "kprobe", "ip_finish_output2"},
	{"l24_neigh_resolve_output", "kprobe", "neigh_resolve_output"},
	{"l24_neigh_resolve_output_ret", "kretprobe", "neigh_resolve_output"},
	// netfilter
	{"l24_nf_hook_slow", "kprobe", "nf_hook_slow"},
	{"l24_nf_hook_slow_ret", "kretprobe", "nf_hook_slow"},
	// write: L2
	{"l24_dev_queue_xmit", "kprobe", "__dev_queue_xmit"},
	{"l24_dev_queue_xmit_ret", "kretprobe", "__dev_queue_xmit"},
	{"l24_net_dev_start_xmit", "tracepoint", "net/net_dev_start_xmit"},
	{"l24_net_dev_xmit", "tracepoint", "net/net_dev_xmit"},
	// read: L2
	{"l24_netif_receive_skb", "tracepoint", "net/netif_receive_skb"},
	{"l24_skb_copy_datagram_iovec", "tracepoint", "skb/skb_copy_datagram_iovec"},
	// read: L3
	{"l24_ip_rcv", "kprobe", "ip_rcv"},
	{"l24_ip_rcv_ret", "kretprobe", "ip_rcv"},
	{"l24_ip_list_rcv", "kprobe", "ip_list_rcv"},
	{"l24_ip_list_rcv_ret", "kretprobe", "ip_list_rcv"},
	{"l24_ip_rcv_finish", "kprobe", "ip_rcv_finish"},
	{"l24_ip_sublist_rcv_finish", "kprobe", "ip_sublist_rcv_finish"},
	{"l24_ip_local_deliver", "kprobe", "ip_local_deliver"},
	{"l24_ip_local_deliver_finish", "kprobe", "ip_local_deliver_finish"},
	// read: L4
	{"l24_tcp_v4_rcv", "kprobe", "tcp_v4_rcv"},
	{"l24_tcp_v4_rcv_ret", "kretprobe", "tcp_v4_rcv"},
	{"l24_tcp_v6_rcv", "kprobe", "tcp_v6_rcv"},
	{"l24_tcp_v6_rcv_ret", "kretprobe", "tcp_v6_rcv"},
}

// l24TTL is how long the details of a call wait for its kernel log: a few flush periods, as the kernel logs of a
// flush are built at its end
func l24TTL(flushPeriod time.Duration) time.Duration {
	return max(l24TTLFlushes*flushPeriod, l24MinTTL)
}

func (c *L24Collector) Start(_ *module.Manager, ctx *common.AccessLogContext) error {
	if !ctx.Config.KernelMetrics.L2L3 || !ctx.BPF.KernelMetricsL2L3() {
		return nil
	}
	flushPeriod, err := time.ParseDuration(ctx.Config.Flush.Period)
	if err != nil || flushPeriod <= 0 {
		flushPeriod = time.Second
	}
	c.store = events.NewL24Store(l24StoreCapacity, l24TTL(flushPeriod), flushPeriod)
	c.store.StartSweeper(flushPeriod)
	registerL24Telemetry(c.store)
	events.SetL24Store(c.store)

	// the events first: a program attached before would send events nobody reads
	store := c.store
	ctx.BPF.ReadEventAsyncWithBufferSize(ctx.BPF.SocketL24Queue, func(data interface{}) {
		event := data.(*events.SocketL24Event)
		store.Put(events.L24Key{ConnectionID: event.ConnectionID, RandomID: event.RandomID, DataID: event.DataID},
			&event.Metrics)
	}, l24QueuePerCPUBuffer, 1, func() interface{} {
		// one goroutine reads the ring and the store copies the details: one event serves every read
		return &events.SocketL24Event{}
	})

	programs := l24Programs(ctx)
	attached, failed := 0, 0
	for _, h := range l24Hooks {
		p := programs[h.program]
		if p == nil || !ctx.BPF.L24ProgramLoaded(h.program) {
			failed++
			l24Log.Warnf("the L2/L3 kernel metrics program %s is not loaded, %s %s is not traced", h.program, h.kind, h.symbol)
			continue
		}
		if err := attachL24Hook(ctx, h, p); err != nil {
			failed++
			l24Log.Warnf("cannot attach the L2/L3 kernel metrics program %s to %s %s, its metrics stay 0: %v",
				h.program, h.kind, h.symbol, err)
			continue
		}
		attached++
	}
	l24Log.Infof("L2/L3 kernel metrics: %d hooks attached, %d not", attached, failed)
	return nil
}

func attachL24Hook(ctx *common.AccessLogContext, h l24Hook, p *ebpf.Program) error {
	switch h.kind {
	case "kprobe":
		return ctx.BPF.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{h.symbol: p})
	case "kretprobe":
		return ctx.BPF.AddLinkOrError(link.Kretprobe, map[string]*ebpf.Program{h.symbol: p})
	case "tracepoint":
		for i := 0; i < len(h.symbol); i++ {
			if h.symbol[i] == '/' {
				return ctx.BPF.AddTracePointOrError(h.symbol[:i], h.symbol[i+1:], p)
			}
		}
	}
	return fmt.Errorf("unknown hook %s %s", h.kind, h.symbol)
}

// l24Programs are the l24 programs of the loader by their name in the object
func l24Programs(ctx *common.AccessLogContext) map[string]*ebpf.Program {
	b := ctx.BPF
	return map[string]*ebpf.Program{
		"l24_tcp_sendmsg":              b.L24TcpSendmsg,
		"l24_tcp_sendmsg_ret":          b.L24TcpSendmsgRet,
		"l24_tcp_transmit_skb":         b.L24TcpTransmitSkb,
		"l24_tcp_retransmit_skb":       b.L24TcpRetransmitSkb,
		"l24_ip_queue_xmit":            b.L24IpQueueXmit,
		"l24_ip_queue_xmit_ret":        b.L24IpQueueXmitRet,
		"l24_ip_local_out":             b.L24IpLocalOut,
		"l24_ip_output":                b.L24IpOutput,
		"l24_ip_finish_output2":        b.L24IpFinishOutput2,
		"l24_neigh_resolve_output":     b.L24NeighResolveOutput,
		"l24_neigh_resolve_output_ret": b.L24NeighResolveOutputRet,
		"l24_nf_hook_slow":             b.L24NfHookSlow,
		"l24_nf_hook_slow_ret":         b.L24NfHookSlowRet,
		"l24_dev_queue_xmit":           b.L24DevQueueXmit,
		"l24_dev_queue_xmit_ret":       b.L24DevQueueXmitRet,
		"l24_net_dev_start_xmit":       b.L24NetDevStartXmit,
		"l24_net_dev_xmit":             b.L24NetDevXmit,
		"l24_netif_receive_skb":        b.L24NetifReceiveSkb,
		"l24_skb_copy_datagram_iovec":  b.L24SkbCopyDatagramIovec,
		"l24_ip_rcv":                   b.L24IpRcv,
		"l24_ip_rcv_ret":               b.L24IpRcvRet,
		"l24_ip_list_rcv":              b.L24IpListRcv,
		"l24_ip_list_rcv_ret":          b.L24IpListRcvRet,
		"l24_ip_rcv_finish":            b.L24IpRcvFinish,
		"l24_ip_sublist_rcv_finish":    b.L24IpSublistRcvFinish,
		"l24_ip_local_deliver":         b.L24IpLocalDeliver,
		"l24_ip_local_deliver_finish":  b.L24IpLocalDeliverFinish,
		"l24_tcp_v4_rcv":               b.L24TcpV4Rcv,
		"l24_tcp_v4_rcv_ret":           b.L24TcpV4RcvRet,
		"l24_tcp_v6_rcv":               b.L24TcpV6Rcv,
		"l24_tcp_v6_rcv_ret":           b.L24TcpV6RcvRet,
	}
}

func registerL24Telemetry(store *events.L24Store) {
	telemetry.Register("rover_kernel_metrics_l2_l3_entries",
		"The L2/L3 details of socket calls waiting for their kernel logs", telemetry.Gauge,
		func() float64 { return float64(store.Len()) })
	telemetry.Register("rover_kernel_metrics_l2_l3_dropped_total",
		"The L2/L3 details of socket calls dropped because the store was full (their kernel logs have no L2/L3 metrics)",
		telemetry.Counter, func() float64 { return float64(store.Dropped()) })
	telemetry.Register("rover_kernel_metrics_l2_l3_expired_total",
		"The L2/L3 details of socket calls removed after their time", telemetry.Counter,
		func() float64 { return float64(store.Expired()) })
}

func (c *L24Collector) Stop() {
	if c.store != nil {
		c.store.Stop()
		events.SetL24Store(nil)
	}
}
