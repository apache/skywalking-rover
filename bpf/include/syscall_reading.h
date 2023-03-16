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

#if defined(bpf_target_x86)
#define SYSCALL_PARM_1(x) (_(PT_REGS_PARM1((struct pt_regs *)PT_REGS_PARM1(x))))
#define SYSCALL_PARM_2(x) (_(PT_REGS_PARM2((struct pt_regs *)PT_REGS_PARM1(x))))
#define SYSCALL_PARM_3(x) (_(PT_REGS_PARM3((struct pt_regs *)PT_REGS_PARM1(x))))
#define SYSCALL_PARM_4(x) (_(PT_REGS_PARM4((struct pt_regs *)PT_REGS_PARM1(x))))
#define SYSCALL_PARM_5(x) (_(PT_REGS_PARM5((struct pt_regs *)PT_REGS_PARM1(x))))
#else
#define SYSCALL_PARM_1(x) (PT_REGS_PARM1(x))
#define SYSCALL_PARM_2(x) (PT_REGS_PARM2(x))
#define SYSCALL_PARM_3(x) (PT_REGS_PARM3(x))
#define SYSCALL_PARM_4(x) (PT_REGS_PARM4(x))
#define SYSCALL_PARM_5(x) (PT_REGS_PARM5(x))
#endif