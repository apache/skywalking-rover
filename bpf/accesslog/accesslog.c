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

#include <bpf/bpf_endian.h>
#include "api.h"
#include "syscall_reading.h"
#include "protocol_analyzer.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <asm/errno.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// process execution monitoring
#include "process/process.c"

// syscalls monitoring
#include "syscalls/connect.c"
#include "syscalls/transfer.c"
#include "syscalls/close.c"

// network l2-l4 monitoring
#include "l24/write_l4.c"
#include "l24/write_l3.c"
#include "l24/write_l2.c"
#include "l24/nf.c"
#include "l24/read_l4.c"
#include "l24/read_l3.c"
#include "l24/read_l2.c"

// tls monitoring
#include "tls/go_tls.c"
#include "tls/node_tls.c"
#include "tls/openssl.c"

// ambient istio
#include "ambient/ztunnel.c"