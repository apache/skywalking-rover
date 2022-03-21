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

VERSION ?= latest

SHELL = /bin/bash

REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))/

OSNAME := $(if $(findstring Darwin,$(shell uname)),darwin,linux)

SH = sh
GO = go
GIT = git
GO_PATH = $$($(GO) env GOPATH)
GO_BUILD = $(GO) build
GO_GET = $(GO) get

CONTAINER_COMMAND_IMAGE ?= quay.io/cilium/ebpf-builder
CONTAINER_COMMAND_TAG ?= 1637058444
CONTAINER_COMMAND_CLANG ?= clang-13
CONTAINER_COMMAND_STRIP ?= llvm-strip-13
CONTAINER_COMMAND_CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CONTAINER_COMMAND_ENGINE ?= docker

.PHONY: clean
clean:
	-rm -rf coverage.txt

container-command:
	${CONTAINER_COMMAND_ENGINE} run --rm \
		-v "${REPODIR}":/skywalking-rover -w /skywalking-rover --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/skywalking-rover=." \
		--env HOME="/skywalking-rover" \
		"${CONTAINER_COMMAND_IMAGE}:${CONTAINER_COMMAND_TAG}" \
		make ${COMMAND}