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

package analyze

import (
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
)

// The trampoline attach (skywalking-rover/pkg/accesslog/bpf/attach.go and bpf/accesslog/common/sys_attach.h, the
// attach modes of access_log.bpf.attach_mode) runs the same program bodies from fentry/fexit on the syscall wrappers,
// fentry on the socket kprobes and a raw tracepoint for the skb copy, instead of the syscall tracepoints, kprobes and
// the skb tracepoint. TestAttachModeSameOutput runs the scripted exchange (h2cFastTraffic) once with each attach,
// on a loader of its own, and requires the same events, compact records and summaries (everything but the times, the
// connection ids and the ports). Skipped where the kernel has no trampolines
// (5.5 without BTF): the loader falls back to the tracepoints.
func TestAttachModeSameOutput(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	run := func(t *testing.T, mode string) *h2cFastOutput {
		loader, err := h2cLoadAttachBPF(mode)
		if err != nil {
			t.Fatal(err)
		}
		defer loader.Close()
		twins := 0
		for _, hook := range []string{"read", "write", "writev", "connect", "accept", "accept4", "close",
			"security_socket_sendmsg", "security_socket_recvmsg"} {
			if loader.UsesTwin(hook) {
				twins++
			}
		}
		switch {
		case mode == bpf.AttachTracepoint && twins != 0:
			t.Fatalf("tracepoint mode attached %d twins", twins)
		case mode == bpf.AttachTrampoline && twins == 0:
			t.Skipf("the kernel attaches no trampoline twin (mode %s)", loader.AttachMode())
		case mode == bpf.AttachTrampoline && twins != 9:
			t.Logf("only %d of the 9 hooks use their twin", twins)
		}
		return h2cFastRun(t, loader)
	}
	tp := run(t, bpf.AttachTracepoint)
	tr := run(t, bpf.AttachTrampoline)
	if len(tp.events) == 0 || len(tp.summaries) == 0 {
		t.Fatalf("the run gave %d events and %d summaries", len(tp.events), len(tp.summaries))
	}
	h2cFastCompare(t, "event", tp.events, tr.events)
	h2cFastCompare(t, "summary", tp.summaries, tr.summaries)
	t.Logf("%d events, %d summaries in both", len(tr.events), len(tr.summaries))
}
