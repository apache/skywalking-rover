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

#include "api.h"

#define DATA_QUEUE(name, size)               \
	struct {                                    \
		__uint(type, BPF_MAP_TYPE_RINGBUF); \
		__uint(max_entries, size);          \
	} name SEC(".maps");                        \
	const void *rover_data_queue_##name __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 10240); // all events are less than 10KB
} rover_data_heap SEC(".maps");

static __always_inline void *rover_reserve_buf(void *map, __u64 size) {
	static const int zero = 0;

	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_ringbuf_reserve))
		return bpf_ringbuf_reserve(map, size, 0);

	return bpf_map_lookup_elem(&rover_data_heap, &zero);
}

static __always_inline void rover_discard_buf(void *buf)
{
	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_ringbuf_discard))
		bpf_ringbuf_discard(buf, 0);
}

static __always_inline long rover_submit_buf(void *ctx, void *map, void *buf, __u64 size) {
	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_ringbuf_submit)) {
		bpf_ringbuf_submit(buf, 0);
		return 0;
	}

	return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, buf, size);
}