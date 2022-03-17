# Licensed to Apache Software Foundation (ASF) under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Apache Software Foundation (ASF) licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

.PHONY: generate
generate: export BPF_CLANG := $(CONTAINER_COMMAND_CLANG)
generate: export BPF_CFLAGS := $(CONTAINER_COMMAND_CFLAGS)
generate: export REPO_ROOT := /skywalking-rover
generate:
	cd ./ && go generate ./...

# Usually works for generate ebpf ELF file on Mac OS or windows
.PHONY: container-generate
container-generate: COMMAND=generate
container-generate: container-command