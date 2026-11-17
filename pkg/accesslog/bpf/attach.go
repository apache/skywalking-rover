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
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// The attach of the socket call programs (bpf/accesslog/common/sys_attach.h). Every hook below has its classic
// programs (the syscall tracepoints, kprobes, the skb tracepoint) and a twin that runs the same body from a BPF
// trampoline (fentry/fexit on the syscall wrapper or the kernel function) or a raw tracepoint. The twins only run for
// the calls of their own function and skip the tracepoint dispatch (perf_syscall_enter/exit and their perf buffer,
// kprobe_ftrace_handler); and once no syscall tracepoint is attached at all, the tasks of the host leave the syscall
// slow path (TIF_SYSCALL_TRACEPOINT).
//
// access_log.bpf.attach_mode (LoaderOptions.AttachMode) selects:
//
//	auto (default)  the twins of the hooks whose twin attaches on this kernel (probed one by one when the loader
//	                starts), where the kernel has BTF, is x86_64, and runs trampoline programs without preemption
//	trampoline      as auto without the preemption check
//	tracepoint      the classic programs only
//
// A hook whose twin is not used keeps its classic programs; the programs of the side not used are loaded as stubs
// (the twins cannot be loaded without BTF; the classic exits would double the verification time).

const (
	AttachAuto       = "auto"
	AttachTrampoline = "trampoline"
	AttachTracepoint = "tracepoint"
)

const (
	// goarchAMD64 is the only GOARCH the trampoline programs (and the fexit NAT hook) run on
	goarchAMD64 = "amd64"
	// x64SyscallPrefix is the prefix of the syscall wrappers the twins are compiled for
	x64SyscallPrefix = "__x64_sys_"
	// bpfLicense is the license of the programs the loader builds itself
	bpfLicense = "GPL"
	// hookNfConfirm is the hook (and kernel function) nf_confirm
	hookNfConfirm = "nf_confirm"
	// moduleNfConntrack is the kernel module of nf_confirm when vmlinux does not have it
	moduleNfConntrack = "nf_conntrack"
	// reasonAttachModeTracepoint is the plan reason of the tracepoint attach mode
	reasonAttachModeTracepoint = "attach mode tracepoint"
)

// attachHook is one hook point: the programs of its twin (fast) and its classic programs (slow)
type attachHook struct {
	name string
	fast []string
	slow []string
	// raw is the raw tracepoint name of a raw tracepoint twin
	raw string
	// btf is the BTF-typed raw tracepoint (tp_btf) program preferred to the raw tracepoint twin fast[0] where it
	// attaches: it is loaded in place of that twin (applyAttachPlan) and attached as a tracing program
	btf string
	// argStruct, when set, is the struct the fentry twin reads its argument argIndex as a pointer to: the twin is
	// only used where the kernel BTF of the function says so (its signature changed between kernels)
	argStruct string
	argIndex  int
}

func syscallHook(call string) attachHook {
	return attachHook{name: call, fast: []string{"fentry_enter_" + call, "fexit_exit_" + call},
		slow: []string{"tracepoint_enter_" + call, "tracepoint_exit_" + call}}
}

// attachHooks are all the hooks with a twin. accept4 shares the tracepoint programs of accept.
//
//nolint:goconst // the table spells the BPF program and kernel function names as the C sources do
var attachHooks = func() []attachHook {
	var hooks []attachHook
	for _, call := range []string{"read", "write", "readv", "writev", "sendto", "recvfrom", "sendmsg", "recvmsg",
		"sendmmsg", "recvmmsg", "connect", "accept", "close"} {
		hooks = append(hooks, syscallHook(call))
	}
	hooks = append(hooks,
		attachHook{name: "accept4", fast: []string{"fentry_enter_accept4", "fexit_exit_accept4"},
			slow: []string{"tracepoint_enter_accept", "tracepoint_exit_accept"}},
		attachHook{name: "security_socket_recvmsg", fast: []string{"fentry_security_socket_recvmsg"},
			slow: []string{"security_socket_recvmsg"}},
		attachHook{name: "security_socket_sendmsg", fast: []string{"fentry_security_socket_sendmsg"},
			slow: []string{"security_socket_sendmsg"}},
		attachHook{name: "tcp_sendmsg", fast: []string{"fentry_tcp_sendmsg"}, slow: []string{"tcp_sendmsg"}},
		// (only for the NAT hook legacy, see nat.go: nf_confirm(skb, protoff, ct, ctinfo) before 6.x)
		attachHook{name: hookNfConfirm, fast: []string{"fentry_nf_confirm"}, slow: []string{hookNfConfirm},
			argStruct: "nf_conn", argIndex: 2},
		attachHook{name: "skb_copy_datagram_iovec", fast: []string{"raw_tp_skb_copy_datagram_iovec"},
			slow: []string{"tracepoint_skb_copy_datagram_iovec"}, raw: "skb_copy_datagram_iovec",
			btf: "tp_btf_skb_copy_datagram_iovec"},
	)
	return hooks
}()

// attachPlan is what the loader attaches for each hook
type attachPlan struct {
	mode   string
	reason string
	// fast is the set of hooks that use their twin
	fast map[string]bool
	// btf is the set of hooks of fast whose twin is their BTF-typed raw tracepoint (attachHook.btf)
	btf map[string]bool
	// syscallPrefix is the prefix of the syscall wrappers of the kernel ("__x64_sys_")
	syscallPrefix string
	// unused is the set of hooks that attach nothing in this load (the NAT hooks the NAT plan does not use): neither
	// side is probed, both are stubbed
	unused map[string]bool
}

func (p *attachPlan) anyFast() bool {
	return len(p.fast) > 0
}

// tracepointPlan is the classic attach
func tracepointPlan(reason string) *attachPlan {
	return &attachPlan{mode: AttachTracepoint, reason: reason, fast: map[string]bool{}, btf: map[string]bool{}}
}

func (p *attachPlan) String() string {
	var fast, slow, unused []string
	for _, h := range attachHooks {
		if p.unused[h.name] {
			unused = append(unused, h.name)
		} else if p.btf[h.name] {
			fast = append(fast, h.name+"(tp_btf)")
		} else if p.fast[h.name] {
			fast = append(fast, h.name)
		} else {
			slow = append(slow, h.name)
		}
	}
	sort.Strings(fast)
	sort.Strings(slow)
	out := fmt.Sprintf("mode %s (%s), trampoline/raw tracepoint: %v, tracepoint/kprobe: %v", p.mode, p.reason, fast, slow)
	if len(unused) > 0 {
		out += fmt.Sprintf(", not attached: %v", unused)
	}
	return out
}

// planEnv is what planning reads of the host, a variable for the tests
type planEnv struct {
	goarch string
	// kernelFunc finds a function in the kernel BTF (vmlinux, then the module named), an error without kernel BTF
	// or when the function is not there
	kernelFunc func(name, module string) (*btf.Func, error)
	// kernelBTF tells whether the kernel has BTF
	kernelBTF   func() error
	preemptible func() (bool, string)
	probe       func(spec *ebpf.ProgramSpec, raw string) error
	busy        func() map[string]bool
}

var hostEnv = planEnv{
	goarch:      runtime.GOARCH,
	kernelFunc:  kernelBTFFunc,
	kernelBTF:   func() error { _, err := btf.LoadKernelSpec(); return err },
	preemptible: trampolinePreemptible,
	probe:       probeTwin,
	busy:        ftraceBusyFunctions,
}

// kernelBTFFunc finds the function in the BTF of vmlinux, or in that of the module when it is not there
func kernelBTFFunc(name, module string) (*btf.Func, error) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}
	var fn *btf.Func
	if err = kernel.TypeByName(name, &fn); err == nil || module == "" {
		return fn, err
	}
	mod, merr := btf.LoadKernelModuleSpec(module)
	if merr != nil {
		return nil, fmt.Errorf("%v; module %s: %v", err, module, merr)
	}
	if err := mod.TypeByName(name, &fn); err != nil {
		return nil, err
	}
	return fn, nil
}

// funcArgIsStructPointer tells whether argument index of the function is a pointer to struct name (through
// typedefs and qualifiers)
func funcArgIsStructPointer(fn *btf.Func, index int, name string) error {
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return fmt.Errorf("%s has no prototype", fn.Name)
	}
	if index >= len(proto.Params) {
		return fmt.Errorf("%s has %d arguments", fn.Name, len(proto.Params))
	}
	ptr, ok := btf.UnderlyingType(proto.Params[index].Type).(*btf.Pointer)
	if ok {
		if st, isStruct := btf.UnderlyingType(ptr.Target).(*btf.Struct); isStruct && st.Name == name {
			return nil
		}
	}
	return fmt.Errorf("argument %d of %s is %v, not struct %s *", index, fn.Name, proto.Params[index].Type, name)
}

// hookModules is the kernel module a hooked function may be in when vmlinux does not have it
var hookModules = map[string]string{hookNfConfirm: moduleNfConntrack}

// planAttach decides the attach of each hook for the requested mode (auto when empty); the hooks of unused attach
// nothing
func planAttach(mode string, spec *ebpf.CollectionSpec, unused map[string]bool) *attachPlan {
	return planAttachEnv(mode, spec, unused, hostEnv)
}

func planAttachEnv(mode string, spec *ebpf.CollectionSpec, unused map[string]bool, env planEnv) *attachPlan {
	plan := planAttachMode(mode, spec, unused, env)
	plan.unused = unused
	return plan
}

func planAttachMode(mode string, spec *ebpf.CollectionSpec, unused map[string]bool, env planEnv) *attachPlan {
	mode = normalizeAttachMode(mode)
	if reason := attachPrecondition(mode, env); reason != "" {
		return tracepointPlan(reason)
	}
	plan := &attachPlan{mode: mode, reason: "probed", fast: map[string]bool{}, btf: map[string]bool{}, syscallPrefix: x64SyscallPrefix}
	// (read before the probes: the ftrace entries of a probe stay listed for a while after its detach)
	busy := env.busy()
	start := time.Now()
	results, btfOK := probeAttachHooks(spec, unused, env)
	var failed []string
	for i, h := range attachHooks {
		if results[i] == errUnusedHook {
			continue
		}
		if results[i] != nil {
			failed = append(failed, results[i].Error())
			continue
		}
		plan.fast[h.name] = true
		if btfOK[i] {
			plan.btf[h.name] = true
		}
	}
	failed = dropFtraceBusyHooks(plan, spec, busy, failed)
	plan.reason = fmt.Sprintf("probed in %v", time.Since(start).Round(time.Millisecond))
	if len(failed) > 0 {
		plan.reason += fmt.Sprintf("; not attachable: %v", failed)
	}
	if !plan.anyFast() {
		plan.mode = AttachTracepoint
	}
	return plan
}

// normalizeAttachMode takes the requested attach mode, auto when empty or unknown
func normalizeAttachMode(mode string) string {
	mode = strings.TrimSpace(strings.ToLower(mode))
	switch mode {
	case "", AttachAuto:
		mode = AttachAuto
	case AttachTrampoline, AttachTracepoint:
	default:
		log.Warnf("the attach mode %q is not one of auto, trampoline, tracepoint: auto", mode)
		mode = AttachAuto
	}
	return mode
}

// attachPrecondition is why no twin is probed at all in the mode on this host, "" when the twins are probed
func attachPrecondition(mode string, env planEnv) string {
	if mode == AttachTracepoint {
		return reasonAttachModeTracepoint
	}
	if env.goarch != goarchAMD64 {
		return "the trampoline programs read the x86_64 registers"
	}
	if err := env.kernelBTF(); err != nil {
		return fmt.Sprintf("no kernel BTF: %v", err)
	}
	if mode == AttachAuto {
		if preemptible, why := env.preemptible(); preemptible {
			return "the kernel may preempt a trampoline program (" + why + "): the per CPU scratch of " +
				"the programs is only safe without preemption, as the tracepoints and kprobes run them"
		}
	}
	if _, err := env.kernelFunc("__x64_sys_read", ""); err != nil {
		return "the kernel has no __x64_sys_read"
	}
	return ""
}

// probeAttachHooks probes the twin of every hook not in unused: results holds the error of each hook (errUnusedHook
// for the unused ones), btfOK whether its BTF-typed raw tracepoint attaches
func probeAttachHooks(spec *ebpf.CollectionSpec, unused map[string]bool, env planEnv) (results []error, btfOK []bool) {
	// (the probes in parallel: the detach of a trampoline waits for an RCU grace period)
	results = make([]error, len(attachHooks))
	btfOK = make([]bool, len(attachHooks))
	var wg sync.WaitGroup
	for i, h := range attachHooks {
		if unused[h.name] {
			results[i] = errUnusedHook
			continue
		}
		if h.argStruct != "" {
			fn, err := env.kernelFunc(h.name, hookModules[h.name])
			if err == nil {
				err = funcArgIsStructPointer(fn, h.argIndex, h.argStruct)
			}
			if err != nil {
				results[i] = fmt.Errorf("%s: %v", h.fast[0], err)
				continue
			}
		}
		wg.Add(1)
		go func(i int, h attachHook) {
			defer wg.Done()
			// the BTF-typed raw tracepoint first; the raw tracepoint where it does not attach
			if h.btf != "" {
				if p := spec.Programs[h.btf]; p != nil && env.probe(p, "") == nil {
					btfOK[i] = true
					return
				}
			}
			for _, name := range h.fast {
				p := spec.Programs[name]
				if p == nil {
					results[i] = fmt.Errorf("%s: not in the object", name)
					return
				}
				if err := env.probe(p, h.raw); err != nil {
					results[i] = fmt.Errorf("%s: %v", name, err)
					return
				}
			}
		}(i, h)
	}
	wg.Wait()
	return results, btfOK
}

// dropFtraceBusyHooks takes the hooks whose function is already busy in ftrace out of the twins of the plan, adding
// why to failed.
// A function that ftrace already calls something for (another tool's kprobe or trampoline) keeps the kprobe: a second
// kind of ftrace user on one function sends its every call through the ftrace list function, which tests every
// registered ftrace user (measured on 6.12: some 200 ns a call), while the kprobes of all tools share one user
func dropFtraceBusyHooks(plan *attachPlan, spec *ebpf.CollectionSpec, busy map[string]bool, failed []string) []string {
	if len(busy) == 0 {
		return failed
	}
	for _, h := range attachHooks {
		if !plan.fast[h.name] || h.raw != "" {
			continue
		}
		for _, name := range h.fast {
			if p := spec.Programs[name]; p != nil && busy[p.AttachTo] {
				delete(plan.fast, h.name)
				delete(plan.btf, h.name)
				failed = append(failed, fmt.Sprintf("%s: %s is already traced through ftrace", name, p.AttachTo))
				break
			}
		}
	}
	return failed
}

// errUnusedHook marks a hook of attachPlan.unused in the probe results
var errUnusedHook = errors.New("not used")

// probeTwin loads a program that does nothing for the attach point of a twin and attaches it once: the twin attaches
// there as well (the attach of a trampoline needs the function in the kernel BTF, traceable by ftrace, and the direct
// calls of ftrace)
func probeTwin(spec *ebpf.ProgramSpec, raw string) error {
	probe := &ebpf.ProgramSpec{
		Name:         "attach_probe",
		Type:         spec.Type,
		AttachType:   spec.AttachType,
		AttachTo:     spec.AttachTo,
		License:      bpfLicense,
		Instructions: probeInstructions(spec),
	}
	prog, err := ebpf.NewProgram(probe)
	if err != nil {
		return err
	}
	defer prog.Close()
	var l link.Link
	if raw != "" {
		l, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: raw, Program: prog})
	} else {
		l, err = link.AttachTracing(link.TracingOptions{Program: prog})
	}
	if err != nil {
		return err
	}
	return l.Close()
}

// ftraceBusyFunctions are the functions ftrace calls something for at the moment (tracefs enabled_functions), nil when
// it cannot be read
func ftraceBusyFunctions() map[string]bool {
	for _, path := range []string{"/sys/kernel/tracing/enabled_functions", "/sys/kernel/debug/tracing/enabled_functions"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		busy := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || !strings.HasPrefix(f[1], "(") {
				continue
			}
			// "<func> (<users>) <flags> ...": a function that only BPF trampolines use ("(1) R D ...", one direct
			// user: all BPF programs of a function share its trampoline) adds no ftrace user of another kind
			direct := false
			for _, flag := range f[2:] {
				if strings.Contains(flag, ":") {
					break
				}
				direct = direct || flag == "D"
			}
			if f[1] == "(1)" && direct {
				continue
			}
			busy[f[0]] = true
		}
		return busy
	}
	return nil
}

// probeInstructions reads the context of a twin as the twin reads it, so that the probe fails to load where the twin
// would: the arguments it reads, and the user registers behind the argument of a syscall wrapper (the kernel BTF of
// some wrappers only has a declaration of struct pt_regs, 5.10 for those of net/socket.c, and the verifier refuses the
// argument then). A raw tracepoint reads nothing that could fail.
func probeInstructions(spec *ebpf.ProgramSpec) asm.Instructions {
	var insns asm.Instructions
	if spec.Type == ebpf.Tracing {
		switch {
		case strings.HasPrefix(spec.AttachTo, x64SyscallPrefix) && spec.AttachType == ebpf.AttachTraceFEntry:
			// regs = ctx[0]; regs->orig_ax
			insns = append(insns, asm.LoadMem(asm.R2, asm.R1, 0, asm.DWord), asm.LoadMem(asm.R3, asm.R2, 120, asm.DWord))
		case strings.HasPrefix(spec.AttachTo, x64SyscallPrefix):
			// the return value behind the one argument
			insns = append(insns, asm.LoadMem(asm.R2, asm.R1, 8, asm.DWord))
		default:
			if slot, ok := twinArgSlot[spec.Name]; ok {
				insns = append(insns, asm.LoadMem(asm.R2, asm.R1, int16(slot*8), asm.DWord))
			}
		}
	}
	return append(insns, asm.Mov.Imm(asm.R0, 0), asm.Return())
}

// twinArgSlot is the argument the fentry twin of a kprobe reads
//
//nolint:goconst // the BPF program names, as the C sources spell them
var twinArgSlot = map[string]int{
	"fentry_security_socket_recvmsg": 3,
	// (the sk_buff)
	"tp_btf_skb_copy_datagram_iovec": 0,
	"fentry_tcp_sendmsg":             0,
	"fentry_nf_confirm":              2,
	// (its return value)
	"fexit_nf_conntrack_confirm": 1,
}

const (
	// preemptRT is the uname version flag of a PREEMPT_RT kernel
	preemptRT = "PREEMPT_RT"
	// preemptModeNone and preemptModeVoluntary are the modes of a PREEMPT_DYNAMIC kernel that do not preempt kernel code
	preemptModeNone      = "none"
	preemptModeVoluntary = "voluntary"
)

// trampolinePreemptible tells whether a trampoline program may be preempted on this kernel. The tracepoints and
// kprobes run a program with preemption off; a trampoline only keeps it on its CPU (migrate_disable), which until 5.11
// disabled preemption, and since then only does where the kernel does not preempt kernel code: a preemptible build
// (CONFIG_PREEMPT, PREEMPT_RT, PREEMPT_DYNAMIC in the full or lazy mode) could switch to another task in the middle of a
// program, whose programs then use the same per CPU scratch and batch on that CPU.
func trampolinePreemptible() (preemptible bool, why string) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return true, fmt.Sprintf("uname: %v", err)
	}
	release := string(bytes.TrimRight(uts.Release[:], "\x00"))
	version := string(bytes.TrimRight(uts.Version[:], "\x00"))
	return preemptibleFrom(release, version, preemptDynamicMode, cmdlinePreempt)
}

// preemptibleFrom is trampolinePreemptible for a kernel release and version (uname), with the current mode of a
// PREEMPT_DYNAMIC kernel and the preempt= of the command line read by the functions given
func preemptibleFrom(release, version string, dynamicMode func() (string, error), cmdline func() string) (preemptible bool, why string) {
	if kernelBefore(release, 5, 11) {
		return false, ""
	}
	flags := map[string]bool{}
	for _, f := range strings.Fields(version) {
		flags[f] = true
	}
	switch {
	case flags[preemptRT]:
		return true, preemptRT
	case flags["PREEMPT_DYNAMIC"]:
		if m, err := dynamicMode(); err == nil {
			if m == preemptModeNone || m == preemptModeVoluntary {
				return false, ""
			}
			return true, "PREEMPT_DYNAMIC in mode " + m
		}
		if m := cmdline(); m == preemptModeNone || m == preemptModeVoluntary {
			return false, ""
		}
		return true, "PREEMPT_DYNAMIC in an unknown mode (no /sys/kernel/debug/sched/preempt, no preempt= of the command line)"
	case flags["PREEMPT"], flags["PREEMPT_LAZY"]:
		return true, "a preemptible kernel"
	}
	return false, ""
}

// preemptDynamicMode reads the current mode of a PREEMPT_DYNAMIC kernel ("none (voluntary) full")
func preemptDynamicMode() (string, error) {
	data, err := os.ReadFile("/sys/kernel/debug/sched/preempt")
	if err != nil {
		return "", err
	}
	return parsePreemptMode(string(data))
}

// parsePreemptMode takes the current mode, the one in parentheses, of /sys/kernel/debug/sched/preempt
func parsePreemptMode(data string) (string, error) {
	for _, f := range strings.Fields(data) {
		if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
			return strings.Trim(f, "()"), nil
		}
	}
	return "", errors.New("no current mode")
}

func cmdlinePreempt() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	return parseCmdlinePreempt(string(data))
}

// parseCmdlinePreempt takes the value of preempt= of a kernel command line, "" without one
func parseCmdlinePreempt(data string) string {
	for _, f := range strings.Fields(data) {
		if strings.HasPrefix(f, "preempt=") {
			return strings.TrimPrefix(f, "preempt=")
		}
	}
	return ""
}

// kernelBefore tells whether a release ("6.12.110+") is before major.minor
func kernelBefore(release string, major, minor int) bool {
	num := func(s string) int {
		end := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
		if end >= 0 {
			s = s[:end]
		}
		n, _ := strconv.Atoi(s)
		return n
	}
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, mi := num(parts[0]), num(parts[1])
	return ma < major || (ma == major && mi < minor)
}

// applyAttachPlan turns the programs of the side of each hook that is not used into stubs, and names the syscall
// wrappers of the kernel
func applyAttachPlan(spec *ebpf.CollectionSpec, plan *attachPlan) {
	// a classic program is a stub when every hook that uses it has its twin (accept and accept4 share theirs)
	slowUsed := map[string]bool{}
	for _, h := range attachHooks {
		if !plan.fast[h.name] && !plan.unused[h.name] {
			for _, name := range h.slow {
				slowUsed[name] = true
			}
		}
	}
	for i := range attachHooks {
		stubUnusedSide(spec, plan, &attachHooks[i], slowUsed)
	}
	if plan.syscallPrefix != "" && plan.syscallPrefix != x64SyscallPrefix {
		for _, p := range spec.Programs {
			if p.Type == ebpf.Tracing && strings.HasPrefix(p.AttachTo, x64SyscallPrefix) {
				p.AttachTo = plan.syscallPrefix + strings.TrimPrefix(p.AttachTo, x64SyscallPrefix)
			}
		}
	}
}

// stubUnusedSide turns the programs of the side of the hook that the plan does not use into stubs (a classic program
// only when no hook of slowUsed uses it)
func stubUnusedSide(spec *ebpf.CollectionSpec, plan *attachPlan, h *attachHook, slowUsed map[string]bool) {
	if plan.unused[h.name] {
		// neither side attaches
		for _, name := range h.slow {
			if !slowUsed[name] {
				stubProgram(spec.Programs[name])
			}
		}
		for _, name := range append(append([]string{}, h.fast...), h.btf) {
			stubProgram(spec.Programs[name])
		}
		return
	}
	if plan.fast[h.name] {
		for _, name := range h.slow {
			if !slowUsed[name] {
				stubProgram(spec.Programs[name])
			}
		}
		if h.btf != "" {
			if btfSpec := spec.Programs[h.btf]; plan.btf[h.name] && btfSpec != nil && len(h.fast) > 0 {
				// the BTF-typed raw tracepoint is loaded in place of the raw tracepoint twin (Loader.AddTracePointHook)
				spec.Programs[h.fast[0]] = btfSpec.Copy()
			}
			stubProgram(spec.Programs[h.btf])
		}
		return
	}
	for _, name := range h.fast {
		stubProgram(spec.Programs[name])
	}
	if h.btf != "" {
		stubProgram(spec.Programs[h.btf])
	}
}

// stubProgram makes a program one that loads anywhere and does nothing (it is never attached)
func stubProgram(p *ebpf.ProgramSpec) {
	if p == nil {
		return
	}
	p.Type = ebpf.SocketFilter
	p.AttachType = ebpf.AttachNone
	p.AttachTo = ""
	p.SectionName = "socket"
	p.Instructions = asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
}

// AttachMode is the attach the loader uses: tracepoint, or auto/trampoline when at least one hook uses its twin
func (l *Loader) AttachMode() string {
	return l.plan.mode
}

// UsesTwin tells whether the hook (a syscall name, a kprobe symbol or skb_copy_datagram_iovec) uses its twin
func (l *Loader) UsesTwin(hook string) bool {
	return l.plan.fast[hook]
}

// AddSyscall attaches the enter and exit programs of a syscall: fentry/fexit on its wrapper when the hook uses its
// twin, otherwise the tracepoints syscalls:sys_enter_<call> and sys_exit_<call>
func (l *Loader) AddSyscall(call string, tpEnter, tpExit, fentry, fexit *ebpf.Program) {
	if l.plan.fast[call] {
		if err := l.AddTracingOrError(fentry); err != nil {
			l.AppendError(fmt.Errorf("attach fentry of %s: %v", call, err))
		}
		if err := l.AddTracingOrError(fexit); err != nil {
			l.AppendError(fmt.Errorf("attach fexit of %s: %v", call, err))
		}
		return
	}
	l.AddTracePoint("syscalls", "sys_enter_"+call, tpEnter)
	l.AddTracePoint("syscalls", "sys_exit_"+call, tpExit)
}

// AddKprobeHook attaches the kprobe of a kernel function, or its fentry twin
func (l *Loader) AddKprobeHook(symbol string, kprobe, fentry *ebpf.Program) {
	if l.plan.fast[symbol] {
		if err := l.AddTracingOrError(fentry); err != nil {
			l.AppendError(fmt.Errorf("attach fentry of %s: %v", symbol, err))
		}
		return
	}
	l.AddLink(link.Kprobe, map[string]*ebpf.Program{symbol: kprobe})
}

// AddKprobeHookOrError is AddKprobeHook for a function the kernel may not have: the error is returned, not kept
func (l *Loader) AddKprobeHookOrError(symbol string, kprobe, fentry *ebpf.Program) error {
	if l.plan.fast[symbol] {
		return l.AddTracingOrError(fentry)
	}
	return l.AddLinkOrError(link.Kprobe, map[string]*ebpf.Program{symbol: kprobe})
}

// AddTracePointHook attaches a tracepoint program, or the raw tracepoint twin (which is the BTF-typed raw tracepoint
// program where the hook uses that)
func (l *Loader) AddTracePointHook(group, name string, tp, raw *ebpf.Program) {
	if l.plan.btf[name] {
		if err := l.AddTracingOrError(raw); err != nil {
			l.AppendError(fmt.Errorf("attach tp_btf %s: %v", name, err))
		}
		return
	}
	if l.plan.fast[name] {
		if err := l.AddRawTracePointOrError(name, raw); err != nil {
			l.AppendError(fmt.Errorf("attach raw tracepoint %s: %v", name, err))
		}
		return
	}
	l.AddTracePoint(group, name, tp)
}

// processMonitorHintSlots is PROCESS_MONITOR_HINT_SLOTS of bpf/accesslog/process/process.h
const processMonitorHintSlots = 65536

// processMonitorHintPos is PROCESS_MONITOR_HINT_POS: the slot holds the tgid with it while the tgid is monitored
const processMonitorHintPos = 0x80000000

// MonitorProcessHint sets the hint slot of a process to "maybe" (process_monitor_hint, bpf/accesslog/process/process.h),
// which must be done before the process is put into process_monitor_control: the programs take a process whose slot is
// unset for one that was never monitored
func MonitorProcessHint(hint *ebpf.Map, pid uint32) error {
	if hint == nil {
		return nil
	}
	slot := pid & (processMonitorHintSlots - 1)
	var v uint32
	if err := hint.Lookup(slot, &v); err == nil && v != 0 {
		return nil
	}
	return hint.Update(slot, uint32(1), ebpf.UpdateAny)
}

// ConfirmMonitorProcessHint puts the positive state of a process into its slot, once the process is in
// process_monitor_control: its enters skip the lookup of the map
func ConfirmMonitorProcessHint(hint *ebpf.Map, pid uint32) error {
	if hint == nil {
		return nil
	}
	return hint.Update(pid&(processMonitorHintSlots-1), pid|processMonitorHintPos, ebpf.UpdateAny)
}

// UnconfirmMonitorProcessHint turns the positive state of a process back to "maybe", which must be done before the
// process is deleted from process_monitor_control
func UnconfirmMonitorProcessHint(hint *ebpf.Map, pid uint32) error {
	if hint == nil {
		return nil
	}
	slot := pid & (processMonitorHintSlots - 1)
	var v uint32
	if err := hint.Lookup(slot, &v); err != nil || v != pid|processMonitorHintPos {
		return err
	}
	return hint.Update(slot, uint32(1), ebpf.UpdateAny)
}

// MonitorProcess makes the access log programs trace a process (its hint, process_monitor_control, the positive hint)
func (l *Loader) MonitorProcess(pid uint32) error {
	if err := MonitorProcessHint(l.ProcessMonitorHint, pid); err != nil {
		return err
	}
	if err := l.ProcessMonitorControl.Update(pid, uint32(1), ebpf.UpdateAny); err != nil {
		return err
	}
	return ConfirmMonitorProcessHint(l.ProcessMonitorHint, pid)
}

// UnmonitorProcess stops tracing a process (the positive hint first, then process_monitor_control)
func (l *Loader) UnmonitorProcess(pid uint32) error {
	if err := UnconfirmMonitorProcessHint(l.ProcessMonitorHint, pid); err != nil {
		return err
	}
	return l.ProcessMonitorControl.Delete(pid)
}
