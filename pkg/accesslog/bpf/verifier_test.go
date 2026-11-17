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

package bpf

import (
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestEveryProgramLoads loads every program of the access log object into the kernel on its own. The
// socket data upload is unrolled into each syscall exit and TLS uretprobe, so a change to the upload
// chunk count or to the chunk body can push those programs over the verifier's 1M processed
// instruction limit ("BPF program is too large"), which no unit test of the Go side would notice and
// which makes the whole access log module fail to start. Needs root, skipped otherwise.
//
// The object as the loader makes it (NewLoaderWithOptions): the atomic exchange of the upload chain only where the
// kernel runs it (stripped otherwise, as 5.10 refuses the instruction), and the programs of the side of each hook
// the attach plan does not use stubbed, as the loader stubs them. Every plan the loader can take on this kernel is
// loaded: the host plan (auto), the tracepoint plan (the fallback when the trampoline programs do not load: every
// classic program), and the NAT plans kprobe and legacy (legacy loads nf_confirm and its twin where it attaches). A
// program already loaded unchanged by an earlier plan is not loaded again. The plans l2l3 load the object with the L2 to L4
// details on (kernel_metrics_l2_l3, l24.go), which changes the exit programs, and with the programs of l24 loaded for
// real (they are in every plan: only the loader stubs them, with the switch off).
func TestEveryProgramLoads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise the memlock limit: %v", err)
	}
	plans := []struct {
		name, attach, nat string
		l2l3              bool
	}{
		{"host", "", "", false},
		{"tracepoint", AttachTracepoint, "", false},
		{"nat-kprobe", "", natHookKprobe, false},
		{"nat-legacy", "", natHookLegacy, false},
		{"tracepoint-nat-legacy", AttachTracepoint, natHookLegacy, false},
		{"l2l3", "", "", true},
		{"l2l3-tracepoint", AttachTracepoint, "", true},
	}
	loaded := map[string]bool{}
	for _, pl := range plans {
		t.Run(pl.name, func(t *testing.T) {
			spec, err := loadSpecWithOptions(LoaderOptions{KernelMetricsL2L3: pl.l2l3})
			if err != nil {
				t.Fatalf("cannot read the access log BPF object: %v", err)
			}
			nat := planNATHook(pl.nat, spec)
			plan := planAttach(pl.attach, spec, nat.unusedHooks())
			applyAttachPlan(spec, plan)
			applyNATPlan(spec, nat)
			t.Logf("attach: %s; NAT address: %s", plan, nat)
			for name, program := range spec.Programs {
				key := fmt.Sprintf("%s|l2l3=%v", programKey(name, program), pl.l2l3)
				if loaded[key] {
					continue
				}
				single := &ebpf.CollectionSpec{
					Maps:      spec.Maps,
					Programs:  map[string]*ebpf.ProgramSpec{name: program},
					Types:     spec.Types,
					ByteOrder: spec.ByteOrder,
				}
				collection, err := ebpf.NewCollection(single)
				if err != nil {
					t.Errorf("program %s cannot be loaded: %v", name, err)
					continue
				}
				loaded[key] = true
				collection.Close()
			}
		})
	}
}

// programKey tells programs apart that load differently: a stub, a twin attached elsewhere, another body
func programKey(name string, p *ebpf.ProgramSpec) string {
	return fmt.Sprintf("%s|%v|%v|%s|%s|%d", name, p.Type, p.AttachType, p.AttachTo, p.SectionName, len(p.Instructions))
}
