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
#include <linux/bpf.h>

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

// Method Selection
#define SEC(name) \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")	    \
	__attribute__((section(name), used))				    \
	_Pragma("GCC diagnostic pop")					    \

// which reference what we need
struct pt_regs;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
static long (*bpf_get_stackid)(void *ctx, void *map, __u64 flags) = (void *) 27;

#endif