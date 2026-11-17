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
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// The NAT address of a connect (bpf/accesslog/syscalls/connect_conntrack.c): the remote address behind a DNAT
// (a Service) comes from the reply tuple of the connection's conntrack entry, read while the thread is in the connect.
//
// access_log.bpf.nat_hook (LoaderOptions.NATHook) selects where it is read:
//
//	auto (default)  fexit __nf_conntrack_confirm, once per new entry, where it attaches (BTF, a trampoline); otherwise
//	                the kprobe at the entry of __nf_conntrack_confirm (the kprobe __nf_conntrack_hash_insert only where
//	                that cannot attach: it needs IPS_CONFIRMED, which 6.12 sets after the insert). nf_confirm, which runs
//	                for every packet, is not attached.
//	confirm         the fexit only (nothing when it does not attach)
//	kprobe          the fallback of auto without trampolines: the kprobe at the entry of __nf_conntrack_confirm
//	legacy          the kprobe __nf_conntrack_hash_insert and nf_confirm (kprobe or its fentry twin, the twin only where
//	                the kernel BTF gives nf_confirm a struct nf_conn * third argument), which on 6.12 never see a NAT
//	                (the first is inlined, the second gets the hook state as its third argument)
//
// The programs of nf_confirm are only loaded (and its twin probed) for legacy: nf_confirm runs for every packet.

const (
	natHookAuto    = "auto"
	natHookConfirm = "confirm"
	natHookLegacy  = "legacy"
	natHookKprobe  = "kprobe"
)

// natPlan is how the loader reads the NAT address
type natPlan struct {
	mode string
	// fexit is true when fexit __nf_conntrack_confirm is used
	fexit  bool
	reason string
}

func planNATHook(mode string, spec *ebpf.CollectionSpec) *natPlan {
	return planNATHookEnv(mode, spec, hostEnv)
}

func planNATHookEnv(mode string, spec *ebpf.CollectionSpec, env planEnv) *natPlan {
	mode = strings.TrimSpace(strings.ToLower(mode))
	switch mode {
	case "":
		mode = natHookAuto
	case natHookAuto, natHookConfirm, natHookLegacy, natHookKprobe:
	default:
		log.Warnf("the NAT hook %q is not one of auto, confirm, kprobe, legacy: auto", mode)
		mode = natHookAuto
	}
	plan := &natPlan{mode: mode}
	if mode == natHookLegacy || mode == natHookKprobe {
		plan.reason = "NAT hook " + mode
		return plan
	}
	p := spec.Programs["fexit_nf_conntrack_confirm"]
	switch {
	case p == nil:
		plan.reason = "the object has no fexit_nf_conntrack_confirm"
	case env.goarch != "amd64":
		plan.reason = "not x86_64"
	default:
		if err := env.kernelBTF(); err != nil {
			plan.reason = fmt.Sprintf("no kernel BTF: %v", err)
		} else if err := env.probe(p, ""); err != nil {
			plan.reason = fmt.Sprintf("fexit __nf_conntrack_confirm does not attach: %v", err)
		} else {
			plan.fexit = true
			plan.reason = "fexit __nf_conntrack_confirm attaches"
		}
	}
	return plan
}

// unusedHooks are the hooks of the attach plan (attach.go) this NAT plan attaches nothing to: nf_confirm, unless legacy
func (p *natPlan) unusedHooks() map[string]bool {
	if p.mode == natHookLegacy {
		return map[string]bool{}
	}
	return map[string]bool{"nf_confirm": true}
}

func (p *natPlan) String() string {
	how := "fexit __nf_conntrack_confirm"
	switch {
	case p.mode == natHookLegacy:
		how = "kprobes __nf_conntrack_hash_insert and nf_confirm (legacy)"
	case !p.fexit && p.mode == natHookConfirm:
		how = "nothing"
	case !p.fexit:
		how = "kprobe at the entry of __nf_conntrack_confirm (or __nf_conntrack_hash_insert)"
	}
	return fmt.Sprintf("mode %s: %s (%s)", p.mode, how, p.reason)
}

// applyNATPlan stubs the fexit program where it is not used (it cannot load without BTF)
func applyNATPlan(spec *ebpf.CollectionSpec, plan *natPlan) {
	if !plan.fexit {
		stubProgram(spec.Programs["fexit_nf_conntrack_confirm"])
	}
}

// NATHookPlan is the plan of the NAT address hooks, for the log and the tests
func (l *Loader) NATHookPlan() string {
	return l.nat.String()
}

// AddNATHooks attaches the programs that read the NAT address of a connect, as planned (LoaderOptions.NATHook). The kprobes may
// not attach (a kernel without conntrack, an inlined symbol): their errors are returned, not kept, as before.
func (l *Loader) AddNATHooks() error {
	switch {
	case l.nat.mode == natHookLegacy:
		_ = l.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{"__nf_conntrack_hash_insert": l.NfConntrackHashInsert})
		return l.AddKprobeHookOrError("nf_confirm", l.NfConfirm, l.FentryNfConfirm)
	case l.nat.fexit:
		return l.AddTracingOrError(l.FexitNfConntrackConfirm)
	case l.nat.mode == natHookConfirm:
		return fmt.Errorf("fexit __nf_conntrack_confirm is not available (%s)", l.nat.reason)
	}
	// the entry of __nf_conntrack_confirm (an exported function, on every kernel): the kprobe of __nf_conntrack_hash_insert
	// requires IPS_CONFIRMED, which newer kernels (6.12) set after the insert, so it only comes second (an unusual kernel
	// that has no __nf_conntrack_confirm to probe)
	if err := l.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{"__nf_conntrack_confirm": l.KprobeNfConntrackConfirm}); err == nil {
		return nil
	}
	return l.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{"__nf_conntrack_hash_insert": l.NfConntrackHashInsert})
}
