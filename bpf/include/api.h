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

#ifndef __BPF_API__
#define __BPF_API__

// include linux relate bpf
#include <stddef.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define _KERNEL(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

typedef enum
{
    true=1, false=0
} bool;

struct thread_struct {
    // x86_64
	long unsigned int fsbase;
	// arm64
	struct {
        unsigned long	tp_value;	/* TLS register */
        unsigned long	tp2_value;
    } uw;
}  __attribute__((preserve_access_index));

struct task_struct {
	__u32 pid;
    __u32 tgid;
    struct thread_struct thread;
}  __attribute__((preserve_access_index));
#endif