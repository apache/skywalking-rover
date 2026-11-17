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
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// testSpec is an object with every program of the attach hooks and the NAT hooks, each a body of two instructions
func testSpec() *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}}
	body := func() asm.Instructions {
		return asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}
	}
	add := func(name string, typ ebpf.ProgramType, attachType ebpf.AttachType, to string) {
		spec.Programs[name] = &ebpf.ProgramSpec{Name: name, Type: typ, AttachType: attachType, AttachTo: to, Instructions: body()}
	}
	for _, h := range attachHooks {
		for i, name := range h.fast {
			switch {
			case h.raw != "":
				add(name, ebpf.RawTracepoint, ebpf.AttachNone, h.raw)
			case i == 1:
				add(name, ebpf.Tracing, ebpf.AttachTraceFExit, "__x64_sys_"+h.name)
			default:
				add(name, ebpf.Tracing, ebpf.AttachTraceFEntry, "__x64_sys_"+h.name)
			}
		}
		for _, name := range h.slow {
			add(name, ebpf.TracePoint, ebpf.AttachNone, "syscalls/"+name)
		}
		if h.btf != "" {
			add(h.btf, ebpf.Tracing, ebpf.AttachTraceRawTp, h.raw)
		}
	}
	add("fexit_nf_conntrack_confirm", ebpf.Tracing, ebpf.AttachTraceFExit, "__nf_conntrack_confirm")
	add("kprobe_nf_conntrack_confirm", ebpf.Kprobe, ebpf.AttachNone, "__nf_conntrack_confirm")
	add("nf_conntrack_hash_insert", ebpf.Kprobe, ebpf.AttachNone, "__nf_conntrack_hash_insert")
	return spec
}

func isStub(p *ebpf.ProgramSpec) bool {
	return p.Type == ebpf.SocketFilter && len(p.Instructions) == 2 && p.Instructions[0].Constant == 0
}

// nfConfirmFunc is nf_confirm with the third argument of the type given
func nfConfirmFunc(third btf.Type) *btf.Func {
	ptr := func(t btf.Type) btf.Type { return &btf.Pointer{Target: t} }
	return &btf.Func{Name: "nf_confirm", Type: &btf.FuncProto{Params: []btf.FuncParam{
		{Name: "a", Type: ptr(&btf.Struct{Name: "sk_buff"})},
		{Name: "b", Type: &btf.Int{Name: "unsigned int", Size: 4}},
		{Name: "c", Type: third},
	}}}
}

var (
	nfConnArg    = &btf.Pointer{Target: &btf.Struct{Name: "nf_conn"}}
	hookStateArg = &btf.Pointer{Target: &btf.Const{Type: &btf.Struct{Name: "nf_hook_state"}}}
)

// testEnv is a host of x86_64 with kernel BTF that runs trampolines without preemption, where every twin attaches
func testEnv() planEnv {
	return planEnv{
		goarch: "amd64",
		kernelFunc: func(name, _ string) (*btf.Func, error) {
			if name == "nf_confirm" {
				return nfConfirmFunc(nfConnArg), nil
			}
			return &btf.Func{Name: name, Type: &btf.FuncProto{}}, nil
		},
		kernelBTF:   func() error { return nil },
		preemptible: func() (bool, string) { return false, "" },
		probe:       func(*ebpf.ProgramSpec, string) error { return nil },
		busy:        func() map[string]bool { return nil },
	}
}

func TestPlanAttach(t *testing.T) { //nolint:funlen // table-driven test
	natUnused := map[string]bool{"nf_confirm": true}
	tests := []struct {
		name   string
		mode   string
		unused map[string]bool
		env    func(e *planEnv)
		// wantMode is the mode of the plan; fast and slow name hooks that must use their twin or their classic programs
		wantMode   string
		fast, slow []string
		btf        []string
		reason     string
	}{
		{name: "tracepoint mode", mode: "tracepoint", wantMode: AttachTracepoint, slow: []string{"read", "nf_confirm"},
			reason: reasonAttachModeTracepoint},
		{name: "upper case and blanks", mode: " Tracepoint ", wantMode: AttachTracepoint, slow: []string{"read"}},
		{name: "not x86_64", env: func(e *planEnv) { e.goarch = "arm64" }, wantMode: AttachTracepoint, slow: []string{"read"},
			reason: "x86_64"},
		{name: "no kernel BTF", env: func(e *planEnv) { e.kernelBTF = func() error { return errors.New("none") } },
			wantMode: AttachTracepoint, slow: []string{"read"}, reason: "no kernel BTF"},
		{name: "preemptible auto", env: func(e *planEnv) { e.preemptible = func() (bool, string) { return true, "PREEMPT_RT" } },
			wantMode: AttachTracepoint, slow: []string{"read"}, reason: "PREEMPT_RT"},
		{name: "preemptible trampoline", mode: "trampoline",
			env:      func(e *planEnv) { e.preemptible = func() (bool, string) { return true, "PREEMPT_RT" } },
			unused:   natUnused,
			wantMode: AttachTrampoline, fast: []string{"read", "close", "tcp_sendmsg"}},
		{name: "unknown mode is auto", mode: "fast", unused: natUnused, wantMode: AttachAuto, fast: []string{"read"}},
		{name: "no __x64_sys_read", env: func(e *planEnv) {
			e.kernelFunc = func(_, _ string) (*btf.Func, error) { return nil, errors.New("not found") }
		}, wantMode: AttachTracepoint, slow: []string{"read"}, reason: "__x64_sys_read"},
		{name: "every twin attaches", unused: natUnused, wantMode: AttachAuto,
			fast: []string{"read", "write", "accept4", "security_socket_recvmsg", "tcp_sendmsg", "skb_copy_datagram_iovec"},
			btf:  []string{"skb_copy_datagram_iovec"}},
		{name: "a twin that does not attach", unused: natUnused, env: func(e *planEnv) {
			e.probe = func(p *ebpf.ProgramSpec, _ string) error {
				if p.Name == "fexit_exit_close" {
					return errors.New("no")
				}
				return nil
			}
		}, wantMode: AttachAuto, fast: []string{"read"}, slow: []string{"close"}, reason: "fexit_exit_close: no"},
		{name: "tp_btf does not attach: raw tracepoint", unused: natUnused, env: func(e *planEnv) {
			e.probe = func(p *ebpf.ProgramSpec, _ string) error {
				if p.Name == "tp_btf_skb_copy_datagram_iovec" {
					return errors.New("no")
				}
				return nil
			}
		}, wantMode: AttachAuto, fast: []string{"skb_copy_datagram_iovec"}},
		{name: "a function ftrace already calls something for", unused: natUnused, env: func(e *planEnv) {
			e.busy = func() map[string]bool { return map[string]bool{"__x64_sys_write": true} }
		}, wantMode: AttachAuto, fast: []string{"read"}, slow: []string{"write"}, reason: "already traced"},
		{name: "nothing attaches", unused: natUnused, env: func(e *planEnv) {
			e.probe = func(*ebpf.ProgramSpec, string) error { return errors.New("no") }
		}, wantMode: AttachTracepoint, slow: []string{"read", "skb_copy_datagram_iovec"}},
		{name: "legacy NAT: nf_confirm twin where its third argument is struct nf_conn *", unused: map[string]bool{},
			wantMode: AttachAuto, fast: []string{"nf_confirm", "read"}},
		{name: "legacy NAT: nf_confirm(priv, skb, state) keeps the kprobe", unused: map[string]bool{}, env: func(e *planEnv) {
			e.kernelFunc = func(name, module string) (*btf.Func, error) {
				if name == "nf_confirm" {
					if module != moduleNfConntrack {
						t.Errorf("nf_confirm looked up in module %q", module)
					}
					return nfConfirmFunc(hookStateArg), nil
				}
				return &btf.Func{Name: name, Type: &btf.FuncProto{}}, nil
			}
		}, wantMode: AttachAuto, fast: []string{"read"}, slow: []string{"nf_confirm"}, reason: "not struct nf_conn"},
		{name: "legacy NAT: nf_confirm not in the BTF keeps the kprobe", unused: map[string]bool{}, env: func(e *planEnv) {
			e.kernelFunc = func(name, _ string) (*btf.Func, error) {
				if name == "nf_confirm" {
					return nil, errors.New("not found")
				}
				return &btf.Func{Name: name, Type: &btf.FuncProto{}}, nil
			}
		}, wantMode: AttachAuto, fast: []string{"read"}, slow: []string{"nf_confirm"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv()
			probed := map[string]bool{}
			if tt.env != nil {
				tt.env(&env)
			}
			probe := env.probe
			var mu sync.Mutex
			env.probe = func(p *ebpf.ProgramSpec, raw string) error {
				// (the probes run in parallel)
				mu.Lock()
				probed[p.Name] = true
				mu.Unlock()
				return probe(p, raw)
			}
			plan := planAttachEnv(tt.mode, testSpec(), tt.unused, env)
			if plan.mode != tt.wantMode {
				t.Errorf("mode %s, want %s (%s)", plan.mode, tt.wantMode, plan)
			}
			for _, h := range tt.fast {
				if !plan.fast[h] {
					t.Errorf("hook %s does not use its twin: %s", h, plan)
				}
			}
			for _, h := range tt.slow {
				if plan.fast[h] {
					t.Errorf("hook %s uses its twin: %s", h, plan)
				}
			}
			for _, h := range tt.btf {
				if !plan.btf[h] {
					t.Errorf("hook %s does not use its tp_btf twin: %s", h, plan)
				}
			}
			if tt.reason != "" && !strings.Contains(plan.reason, tt.reason) {
				t.Errorf("reason %q does not say %q", plan.reason, tt.reason)
			}
			for h := range tt.unused {
				if plan.fast[h] || !plan.unused[h] {
					t.Errorf("unused hook %s: fast %t, unused %t", h, plan.fast[h], plan.unused[h])
				}
				if probed["fentry_"+h] {
					t.Errorf("the twin of the unused hook %s was probed", h)
				}
			}
		})
	}
}

func TestApplyAttachPlan(t *testing.T) {
	plan := &attachPlan{mode: AttachAuto, syscallPrefix: "__x64_sys_",
		fast:   map[string]bool{"read": true, "accept": true, "skb_copy_datagram_iovec": true, "tcp_sendmsg": true},
		btf:    map[string]bool{"skb_copy_datagram_iovec": true},
		unused: map[string]bool{"nf_confirm": true}}
	spec := testSpec()
	applyAttachPlan(spec, plan)
	stub := map[string]bool{
		// the hooks with the twin: their classic programs
		"tracepoint_enter_read": true, "tracepoint_exit_read": true, "tcp_sendmsg": true,
		"tracepoint_skb_copy_datagram_iovec": true,
		// the tp_btf program, loaded in place of the raw tracepoint twin
		"tp_btf_skb_copy_datagram_iovec": true,
		// the hooks with the classic programs: their twins (accept4 keeps the tracepoints accept shares with it)
		"fentry_enter_write": true, "fexit_exit_write": true, "fentry_enter_accept4": true, "fexit_exit_accept4": true,
		// the unused hook: both sides
		"nf_confirm": true, "fentry_nf_confirm": true,
	}
	keep := []string{"fentry_enter_read", "fexit_exit_read", "tracepoint_enter_write", "tracepoint_exit_write",
		"fentry_enter_accept", "tracepoint_enter_accept", "tracepoint_exit_accept", "fentry_tcp_sendmsg",
		"raw_tp_skb_copy_datagram_iovec", "fexit_nf_conntrack_confirm", "nf_conntrack_hash_insert"}
	for name := range stub {
		if !isStub(spec.Programs[name]) {
			t.Errorf("%s is not a stub", name)
		}
	}
	for _, name := range keep {
		if isStub(spec.Programs[name]) {
			t.Errorf("%s is a stub", name)
		}
	}
	if p := spec.Programs["raw_tp_skb_copy_datagram_iovec"]; p.Type != ebpf.Tracing || p.AttachType != ebpf.AttachTraceRawTp {
		t.Errorf("the raw tracepoint twin is not the tp_btf program: %v %v", p.Type, p.AttachType)
	}

	// another prefix of the syscall wrappers renames the attach points of the trampolines
	spec = testSpec()
	applyAttachPlan(spec, &attachPlan{mode: AttachAuto, syscallPrefix: "__ia32_sys_", fast: map[string]bool{"read": true},
		btf: map[string]bool{}})
	if to := spec.Programs["fentry_enter_read"].AttachTo; to != "__ia32_sys_read" {
		t.Errorf("fentry_enter_read attaches to %s", to)
	}

	// the tracepoint plan stubs every twin and no classic program
	spec = testSpec()
	applyAttachPlan(spec, tracepointPlan("test"))
	for _, h := range attachHooks {
		for _, name := range h.fast {
			if !isStub(spec.Programs[name]) {
				t.Errorf("tracepoint plan: %s is not a stub", name)
			}
		}
		for _, name := range h.slow {
			if isStub(spec.Programs[name]) {
				t.Errorf("tracepoint plan: %s is a stub", name)
			}
		}
	}
}

func TestPlanNATHook(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		env       func(e *planEnv)
		wantMode  string
		wantFexit bool
		unused    bool
	}{
		{name: "default", wantMode: natHookAuto, wantFexit: true, unused: true},
		{name: "unknown", mode: "nope", wantMode: natHookAuto, wantFexit: true, unused: true},
		{name: "confirm", mode: "Confirm", wantMode: natHookConfirm, wantFexit: true, unused: true},
		{name: "kprobe", mode: "kprobe", wantMode: natHookKprobe, unused: true},
		{name: "legacy", mode: "legacy", wantMode: natHookLegacy},
		{name: "not x86_64", env: func(e *planEnv) { e.goarch = "arm64" }, wantMode: natHookAuto, unused: true},
		{name: "no kernel BTF", env: func(e *planEnv) { e.kernelBTF = func() error { return errors.New("none") } },
			wantMode: natHookAuto, unused: true},
		{name: "fexit does not attach", env: func(e *planEnv) {
			e.probe = func(*ebpf.ProgramSpec, string) error { return errors.New("no") }
		}, wantMode: natHookAuto, unused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv()
			if tt.env != nil {
				tt.env(&env)
			}
			plan := planNATHookEnv(tt.mode, testSpec(), env)
			if plan.mode != tt.wantMode || plan.fexit != tt.wantFexit {
				t.Errorf("plan %s, want mode %s fexit %t", plan, tt.wantMode, tt.wantFexit)
			}
			if got := plan.unusedHooks()["nf_confirm"]; got != tt.unused {
				t.Errorf("nf_confirm unused %t, want %t", got, tt.unused)
			}
			spec := testSpec()
			applyNATPlan(spec, plan)
			if isStub(spec.Programs["fexit_nf_conntrack_confirm"]) == plan.fexit {
				t.Errorf("fexit_nf_conntrack_confirm stubbed %t with fexit %t", !plan.fexit, plan.fexit)
			}
		})
	}
	// without the program in the object
	spec := testSpec()
	delete(spec.Programs, "fexit_nf_conntrack_confirm")
	if plan := planNATHookEnv("", spec, testEnv()); plan.fexit {
		t.Errorf("fexit without the program: %s", plan)
	}
}

func TestKernelBefore(t *testing.T) {
	tests := []struct {
		release      string
		major, minor int
		want         bool
	}{
		{"5.10.0-32-amd64", 5, 11, true},
		{"5.11.0", 5, 11, false},
		{"6.12.110+", 5, 11, false},
		{"4.19.0", 5, 11, true},
		{"5.4", 5, 11, true},
		{"6", 5, 11, false},
		{"", 5, 11, false},
		{"5.5.0-050500-generic", 5, 5, false},
	}
	for _, tt := range tests {
		if got := kernelBefore(tt.release, tt.major, tt.minor); got != tt.want {
			t.Errorf("kernelBefore(%q, %d, %d) = %t, want %t", tt.release, tt.major, tt.minor, got, tt.want)
		}
	}
}

func TestPreemptible(t *testing.T) {
	noDyn := func() (string, error) { return "", errors.New("no debugfs") }
	dyn := func(m string) func() (string, error) { return func() (string, error) { return m, nil } }
	cmd := func(v string) func() string { return func() string { return v } }
	tests := []struct {
		name, release, version string
		dynamic                func() (string, error)
		cmdline                func() string
		want                   bool
	}{
		{"before 5.11 disables preemption", "5.10.0", "#1 SMP PREEMPT_RT", noDyn, cmd(""), false},
		{"PREEMPT_RT", "6.12.0", "#1 SMP PREEMPT_RT Mon", noDyn, cmd(""), true},
		{"PREEMPT", "6.1.0", "#1 SMP PREEMPT Debian", noDyn, cmd(""), true},
		{"PREEMPT_LAZY", "6.13.0", "#1 SMP PREEMPT_LAZY", noDyn, cmd(""), true},
		{"not preemptible", "6.1.0", "#1 SMP Debian 6.1.0", noDyn, cmd(""), false},
		{"dynamic none", "6.12.0", "#1 SMP PREEMPT_DYNAMIC", dyn("none"), cmd("full"), false},
		{"dynamic voluntary", "6.12.0", "#1 SMP PREEMPT_DYNAMIC", dyn("voluntary"), cmd(""), false},
		{"dynamic full", "6.12.0", "#1 SMP PREEMPT_DYNAMIC", dyn("full"), cmd("none"), true},
		{"dynamic lazy", "6.12.0", "#1 SMP PREEMPT_DYNAMIC", dyn("lazy"), cmd(""), true},
		{"dynamic unknown, command line none", "6.12.0", "#1 SMP PREEMPT_DYNAMIC", noDyn, cmd("none"), false},
		{"dynamic unknown, command line voluntary", "6.12.0", "#1 SMP PREEMPT_DYNAMIC", noDyn, cmd("voluntary"), false},
		{"dynamic unknown", "6.12.0", "#1 SMP PREEMPT_DYNAMIC", noDyn, cmd(""), true},
	}
	for _, tt := range tests {
		if got, why := preemptibleFrom(tt.release, tt.version, tt.dynamic, tt.cmdline); got != tt.want {
			t.Errorf("%s: preemptible %t (%s), want %t", tt.name, got, why, tt.want)
		}
	}
}

func TestParsePreempt(t *testing.T) {
	for data, want := range map[string]string{
		"none (voluntary) full\n":      "voluntary",
		"(none) voluntary full lazy\n": "none",
		"none voluntary full (lazy)":   "lazy",
	} {
		if got, err := parsePreemptMode(data); err != nil || got != want {
			t.Errorf("parsePreemptMode(%q) = %q, %v, want %q", data, got, err, want)
		}
	}
	if _, err := parsePreemptMode("none voluntary full"); err == nil {
		t.Errorf("a mode without parentheses")
	}
	for data, want := range map[string]string{
		"BOOT_IMAGE=/vmlinuz root=/dev/sda1 preempt=full quiet\n": "full",
		"BOOT_IMAGE=/vmlinuz root=/dev/sda1":                      "",
		"preempt=none":                                            "none",
	} {
		if got := parseCmdlinePreempt(data); got != want {
			t.Errorf("parseCmdlinePreempt(%q) = %q, want %q", data, got, want)
		}
	}
}

func TestFuncArgIsStructPointer(t *testing.T) {
	if err := funcArgIsStructPointer(nfConfirmFunc(nfConnArg), 2, "nf_conn"); err != nil {
		t.Errorf("struct nf_conn *: %v", err)
	}
	typedef := &btf.Pointer{Target: &btf.Typedef{Name: "nf_conn_t", Type: &btf.Volatile{Type: &btf.Struct{Name: "nf_conn"}}}}
	if err := funcArgIsStructPointer(nfConfirmFunc(typedef), 2, "nf_conn"); err != nil {
		t.Errorf("a typedef of struct nf_conn *: %v", err)
	}
	if err := funcArgIsStructPointer(nfConfirmFunc(hookStateArg), 2, "nf_conn"); err == nil {
		t.Errorf("const struct nf_hook_state * taken for struct nf_conn *")
	}
	if err := funcArgIsStructPointer(nfConfirmFunc(nfConnArg), 3, "nf_conn"); err == nil {
		t.Errorf("an argument beyond the prototype")
	}
	if err := funcArgIsStructPointer(&btf.Func{Name: "f", Type: &btf.Int{Name: "int", Size: 4}}, 0, "nf_conn"); err == nil {
		t.Errorf("a function without prototype")
	}
}
