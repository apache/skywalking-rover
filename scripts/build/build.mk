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

BINARY = skywalking-rover

OUT_DIR = bin
GO_BUILD_FLAGS = -buildvcs=false -v
GO_BUILD_LDFLAGS = -X main.version=$(VERSION)

PLATFORMS := linux
ifeq ($(SYS_ARCH),x86_64)
  ARCH := amd64
else
  ARCH := arm64
endif
os = $(word 1, $@)

deps:
	$(GO_GET) -v -t -d ./...

.PHONY: $(PLATFORMS)
$(PLATFORMS): deps
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 GOOS=$(os) GOARCH=$(ARCH) $(GO_BUILD) $(GO_BUILD_FLAGS) -ldflags "$(GO_BUILD_LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-$(VERSION)-$(os)-$(ARCH) ./cmd

.PHONY: build
build: linux
