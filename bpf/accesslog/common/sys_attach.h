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

#pragma once

// The trampoline attach. Every socket syscall the access log follows has a tracepoint pair
// (tracepoint/syscalls/sys_enter_<call>, sys_exit_<call>) and a trampoline pair (fentry/fexit on the syscall wrapper
// __x64_sys_<call>), and a few kprobes have a fentry twin; both run the same body. The loader (pkg/accesslog/bpf)
// attaches one of them: the trampolines where the kernel has them (BTF, x86_64, a kernel that runs them without
// preemption), the tracepoints otherwise and on 5.5 without BTF. As long as any syscall tracepoint is attached, every
// task of the host takes the slow path of the syscall entry and exit (TIF_SYSCALL_TRACEPOINT, perf_syscall_enter/exit
// with their perf buffer); a trampoline only runs for the calls of its function.
//
// A wrapper __x64_sys_<call>(const struct pt_regs *regs) gets the user registers of the syscall: the arguments are
// read from them as the tracepoint takes them (syscall_get_arguments: di, si, dx, r10, r8, r9), and the fexit program
// gets the return value the tracepoint gets (regs->ax as the wrapper returns it). The wrapper of a syscall is only
// called from the syscall table, as the tracepoint only fires for it. The tracepoints ignore the 32-bit syscalls
// (ARCH_TRACE_IGNORE_COMPAT_SYSCALLS): the ia32 ones have wrappers of their own (__ia32_sys_*), the x32 ones share
// most of the x64 wrappers and are told apart by the x32 bit of the syscall number, which the enter programs skip on;
// an exit program has nothing to do without its enter.

// the x86_64 struct pt_regs (arch/x86/include/asm/ptrace.h); the field offsets are the ABI, the verifier checks every
// load against the kernel's own type (a fentry argument is a typed kernel pointer, read without a helper)
struct sys_attach_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

// __X32_SYSCALL_BIT
#define SYS_ATTACH_X32_BIT 0x40000000UL

// the registers of the syscall whose wrapper a fentry program runs at, NULL for an x32 syscall (see above)
static __always_inline struct sys_attach_regs *sys_attach_regs(__u64 *ctx) {
    struct sys_attach_regs *regs = (struct sys_attach_regs *)ctx[0];
    if ((regs->orig_ax & SYS_ATTACH_X32_BIT) != 0) {
        return NULL;
    }
    return regs;
}

#define SYS_ARG0(regs) ((__u64)(regs)->di)
#define SYS_ARG1(regs) ((__u64)(regs)->si)
#define SYS_ARG2(regs) ((__u64)(regs)->dx)
#define SYS_ARG3(regs) ((__u64)(regs)->r10)
#define SYS_ARG4(regs) ((__u64)(regs)->r8)

// the return value a fexit program of a wrapper gets: behind its one argument
#define SYS_RET(ctx) ((long)(ctx)[1])

// The section names of the trampoline programs name the x86_64 wrappers (the object is built for x86_64); the loader
// rewrites the prefix when the kernel names them otherwise.
#define SYS_FENTRY(call) SEC("fentry/__x64_sys_" #call)
#define SYS_FEXIT(call) SEC("fexit/__x64_sys_" #call)

// the arguments of the syscall the tracepoint programs get
#define TP_ARG(ctx, n) ((__u64)((struct syscall_trace_enter *)(ctx))->args[n])
#define TP_RET(ctx) ((long)((struct syscall_trace_exit *)(ctx))->ret)
