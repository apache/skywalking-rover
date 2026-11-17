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

// The protocols a build recognizes beyond HTTP/1.x and HTTP/2. protocol_analyzer.h includes it as
// <protocol_analyzer_ext.h>, so the include path decides which copy is used: an agent that recognizes
// more passes an include directory with its own copy, which the access log object searches first
// (BPF_ACCESSLOG_CFLAGS, pkg/accesslog/bpf/loader.go). Only the access log can be given another copy: the
// profiling objects always use this one, which recognizes nothing more.

// infer_extra_protocol is asked when the content is neither HTTP/1.x nor HTTP/2: it returns the message
// type (CONNECTION_MESSAGE_TYPE_*) and sets protocol when it recognizes the content
static __always_inline __u32 infer_extra_protocol(const char *buf, __u32 count, __u32 *protocol) {
    return CONNECTION_MESSAGE_TYPE_UNKNOWN;
}

// protocol_needs_reanalysis tells whether a connection of this known protocol still has its content
// analyzed on every socket call, because what it carries can turn out to be another protocol
static __always_inline bool protocol_needs_reanalysis(__u8 protocol) {
    return false;
}
