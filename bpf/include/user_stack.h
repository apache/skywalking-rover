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

// Copy the user space registers and the raw user stack to the user space,
// then the stack could be unwound by the call frame information(.eh_frame) in the user space,
// it's used for the binaries/libraries which built without the frame pointer.
// It requires the kernel 5.5+(bpf_probe_read_user/kernel) and BTF(CO-RE of the task_struct),
// so it must only be used in the dedicated programs, the loader falls back to the frame pointer programs when loading failure.

#pragma once

#include "api.h"

#define USER_STACK_PAGE_SIZE 4096
// the max size of the copied user stack, must be 4 pages, see copy_user_stack
#define USER_STACK_MAX_SIZE (4 * USER_STACK_PAGE_SIZE)

struct user_stack_event {
    __s32 kernel_stack_id;
    __s32 user_stack_id;
    // the off cpu duration(nanoseconds), zero in the on cpu profiling
    __u64 deltas;
    __u64 pc;
    __u64 sp;
    __u64 fp;
    __u64 lr;
    __u32 stack_size;
    __u8 stack[USER_STACK_MAX_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct user_stack_event);
    __uint(max_entries, 1);
} user_stack_event_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} user_stack_events SEC(".maps");

static __always_inline struct user_stack_event* user_stack_event_buf() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&user_stack_event_buffer, &key);
}

// the program counter and stack pointer must be in the user address space,
// it's used to reject the wrong location of the user registers(such as the zero or the kernel data)
static __always_inline bool user_addr_valid(__u64 pc, __u64 sp, __u64 limit) {
    return pc != 0 && sp != 0 && pc < limit && sp < limit;
}

#if defined(bpf_target_x86)
// offsets of the registers in the "struct pt_regs"(x86_64), it's stable in all kernel versions
#define USER_REGS_SIZE 168
#define USER_REGS_BP 32
#define USER_REGS_IP 128
#define USER_REGS_CS 136
#define USER_REGS_SP 152
#define USER_REGS_SS 160
// the max user address with the 5-level paging
#define USER_ADDR_LIMIT (1ULL << 56)

static __always_inline bool user_regs_valid(__u64 cs, __u64 ss, __u64 ip, __u64 sp) {
    // the privilege level of the code/stack segment must be the user mode(ring 3)
    return (cs & 3) == 3 && (ss & 3) == 3 && user_addr_valid(ip, sp, USER_ADDR_LIMIT);
}

static __always_inline bool read_user_regs_from(struct user_stack_event *e, void *regs) {
    __u64 values[USER_REGS_SIZE / 8];
    if (bpf_probe_read_kernel(values, sizeof(values), regs) != 0 ||
            !user_regs_valid(values[USER_REGS_CS / 8], values[USER_REGS_SS / 8],
                values[USER_REGS_IP / 8], values[USER_REGS_SP / 8])) {
        return false;
    }
    e->pc = values[USER_REGS_IP / 8];
    e->sp = values[USER_REGS_SP / 8];
    e->fp = values[USER_REGS_BP / 8];
    return true;
}

// read the user registers from the perf event context, the context must be accessed directly
static __always_inline bool read_ctx_user_regs(struct user_stack_event *e, void *ctx) {
    if (!user_regs_valid(*(__u64 *)(ctx + USER_REGS_CS), *(__u64 *)(ctx + USER_REGS_SS),
            *(__u64 *)(ctx + USER_REGS_IP), *(__u64 *)(ctx + USER_REGS_SP))) {
        return false;
    }
    e->pc = *(__u64 *)(ctx + USER_REGS_IP);
    e->sp = *(__u64 *)(ctx + USER_REGS_SP);
    e->fp = *(__u64 *)(ctx + USER_REGS_BP);
    return true;
}

static __always_inline bool read_task_user_regs(struct user_stack_event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    void *stack = _KERNEL(task->stack);
    if (stack == NULL) {
        return false;
    }
    // the user registers are saved at the top of the kernel stack (task_pt_regs),
    // the THREAD_SIZE is 16KB(32KB when KASAN enabled), and padding 16 bytes when the FRED enabled
    if (read_user_regs_from(e, stack + 16384 - USER_REGS_SIZE)) {
        return true;
    }
    if (read_user_regs_from(e, stack + 16384 - 16 - USER_REGS_SIZE)) {
        return true;
    }
    if (read_user_regs_from(e, stack + 32768 - USER_REGS_SIZE)) {
        return true;
    }
    return read_user_regs_from(e, stack + 32768 - 16 - USER_REGS_SIZE);
}
#elif defined(bpf_target_arm64)
// offsets of the registers in the "struct user_pt_regs"(arm64), which is the head of the "struct pt_regs"
#define USER_REGS_HEAD_SIZE 272
#define USER_REGS_FP 232
#define USER_REGS_LR 240
#define USER_REGS_SP 248
#define USER_REGS_PC 256
#define USER_REGS_PSTATE 264

struct pt_regs___rover {
    __u64 regs[31];
} __attribute__((preserve_access_index));

// the max user address(52-bit virtual address)
#define USER_ADDR_LIMIT (1ULL << 52)

// the exception level must be EL0(user mode) and not the 32-bit mode,
// also check the addresses because the zeroed(unused) kernel stack also matches the pstate
static __always_inline bool user_regs_valid(__u64 pstate, __u64 pc, __u64 sp) {
    return (pstate & 0x1f) == 0 && user_addr_valid(pc, sp, USER_ADDR_LIMIT);
}

static __always_inline bool read_user_regs_from(struct user_stack_event *e, void *regs) {
    __u64 values[USER_REGS_HEAD_SIZE / 8];
    if (bpf_probe_read_kernel(values, sizeof(values), regs) != 0 ||
            !user_regs_valid(values[USER_REGS_PSTATE / 8], values[USER_REGS_PC / 8], values[USER_REGS_SP / 8])) {
        return false;
    }
    e->pc = values[USER_REGS_PC / 8];
    e->sp = values[USER_REGS_SP / 8];
    e->fp = values[USER_REGS_FP / 8];
    e->lr = values[USER_REGS_LR / 8];
    return true;
}

// read the user registers from the perf event context, the context must be accessed directly
static __always_inline bool read_ctx_user_regs(struct user_stack_event *e, void *ctx) {
    if (!user_regs_valid(*(__u64 *)(ctx + USER_REGS_PSTATE), *(__u64 *)(ctx + USER_REGS_PC),
            *(__u64 *)(ctx + USER_REGS_SP))) {
        return false;
    }
    e->pc = *(__u64 *)(ctx + USER_REGS_PC);
    e->sp = *(__u64 *)(ctx + USER_REGS_SP);
    e->fp = *(__u64 *)(ctx + USER_REGS_FP);
    e->lr = *(__u64 *)(ctx + USER_REGS_LR);
    return true;
}

static __always_inline bool read_task_user_regs(struct user_stack_event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    void *stack = _KERNEL(task->stack);
    if (stack == NULL) {
        return false;
    }
    // the user registers are saved at the top of the kernel stack (task_pt_regs),
    // the size of the "struct pt_regs" is different between the kernel versions
    __u32 regs_size = bpf_core_type_size(struct pt_regs___rover);
    // the THREAD_SIZE is 16KB, 32KB when KASAN enabled, and the page size(64KB) when using 64KB pages with VMAP stack
    if (read_user_regs_from(e, stack + 16384 - regs_size)) {
        return true;
    }
    if (read_user_regs_from(e, stack + 32768 - regs_size)) {
        return true;
    }
    return read_user_regs_from(e, stack + 65536 - regs_size);
}
#endif

// copy the user stack from the stack pointer, try to copy until the end of the page with the extra pages,
// because the read would be failure when the memory range is not all mapped(such as the top of the stack)
static __always_inline bool copy_user_stack(struct user_stack_event *e) {
    __u64 sp = e->sp;
    __u64 to_page_end = USER_STACK_PAGE_SIZE - (sp & (USER_STACK_PAGE_SIZE - 1));
    __u64 size;
#pragma unroll
    for (int pages = 3; pages >= 0; pages--) {
        size = to_page_end + pages * USER_STACK_PAGE_SIZE;
        if (bpf_probe_read_user(e->stack, size, (void *)sp) == 0) {
            e->stack_size = size;
            return true;
        }
    }
    return false;
}

// output the user stack event, returns true if the event has been sent to the user space
static __always_inline bool output_user_stack(void *ctx, struct user_stack_event *e) {
    if (!copy_user_stack(e)) {
        return false;
    }
    __u64 size = offsetof(struct user_stack_event, stack) + e->stack_size;
    if (size > sizeof(*e)) {
        return false;
    }
    return bpf_perf_event_output(ctx, &user_stack_events, BPF_F_CURRENT_CPU, e, size) == 0;
}
