#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

VERSION ?= latest
HUB ?= apache
OUT_DIR = bin
BINARY = skywalking-rover

RELEASE_BIN = skywalking-rover-$(VERSION)-bin
RELEASE_SRC = skywalking-rover-$(VERSION)-src

SH = sh
GO = go
GIT = git
PROTOC = protoc
GO_PATH = $$($(GO) env GOPATH)
GO_BUILD = $(GO) build
GO_GET = $(GO) get
GO_TEST = $(GO) test
GO_LINT = $(GO_PATH)/bin/golangci-lint
GO_BUILD_FLAGS = -v
GO_BUILD_LDFLAGS = -X main.version=$(VERSION) -w -s
GO_TEST_LDFLAGS =

PLATFORMS := linux
os = $(word 1, $@)
ARCH = amd64

SHELL = /bin/bash

all: deps verify check

.PHONY: tools
tools:
	$(GO_LINT) version || curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GO_PATH)/bin v1.39.0

deps: tools
	$(GO_GET) -v -t -d ./...

.PHONY: lint
lint: tools
	$(GO_LINT) run -v --timeout 5m ./...

.PHONY: test
test: clean
	$(GO_TEST) -ldflags "$(GO_TEST_LDFLAGS)" ./... -coverprofile=coverage.txt -covermode=atomic

.PHONY: verify
verify: clean lint test

.PHONY: clean
clean: tools
	-rm -rf coverage.txt

.PHONY: check
check: clean
	$(GO) mod tidy > /dev/null
	@if [ ! -z "`git status -s`" ]; then \
		echo "Following files are not consistent with CI:"; \
		git status -s; \
		git diff; \
		exit 1; \
	fi
