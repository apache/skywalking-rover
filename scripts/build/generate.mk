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
generate: export REPO_ROOT := $(REPODIR)
generate:
	@# the product hooks of the access log come from the include path an agent passes (BPF_ACCESSLOG_CFLAGS); a copy
	@# of them in bpf/accesslog/include (left by an older agent build) would silently replace the defaults of rover
	@for f in protocol_analyzer_ext.h connection_filter_rule.h; do \
		if [ -e $(REPODIR)/bpf/accesslog/include/$$f ]; then \
			echo "bpf/accesslog/include/$$f overrides the default bpf/include/$$f: remove it (an agent passes its hooks with BPF_ACCESSLOG_CFLAGS=-I<dir>)" >&2; \
			exit 1; \
		fi; \
	done
	cd ./ && TARGET=$(if $(findstring x86_64,$(shell uname -m)),amd64,arm64) go generate ./...

# Usually works for generate ebpf ELF file on Mac OS or windows
.PHONY: container-generate
container-generate: COMMAND=generate
container-generate: container-command