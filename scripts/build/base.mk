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

HUB ?= apache
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

CONTAINER_COMMAND_IMAGE ?= $(HUB)/skywalking-rover-base
CONTAINER_COMMAND_TAG ?= v$(VERSION)
CONTAINER_COMMAND_CLANG ?= clang
CONTAINER_COMMAND_STRIP ?= llvm-strip
CONTAINER_COMMAND_CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CONTAINER_PLATFORMS ?= --platform linux/amd64,linux/arm64

SYS_ARCH := $(shell uname -m)

.PHONY: clean
clean:
	-rm -rf coverage.txt

build-base-container:
	docker build -t ${CONTAINER_COMMAND_IMAGE}:${CONTAINER_COMMAND_TAG} . -f docker/Dockerfile.base

build-base-container-with-multi-args-cleanup:
	docker stop registry && docker rm registry || true
	docker buildx rm skywalking_rover || true

build-base-container-with-multi-args: build-base-container-with-multi-args-cleanup
	docker run -d --name registry --network=host registry:2
	docker buildx create --use --driver-opt network=host --name skywalking_rover || true
	docker buildx build --push ${CONTAINER_PLATFORMS} -t localhost:5000/skywalking-rover-base:${CONTAINER_COMMAND_TAG} . -f docker/Dockerfile.base

container-command: build-base-container
	docker run --rm \
		-v "${REPODIR}":/skywalking-rover -w /skywalking-rover --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/skywalking-rover=." \
		--env HOME="/skywalking-rover" \
		"${CONTAINER_COMMAND_IMAGE}:${CONTAINER_COMMAND_TAG}" \
		make ${COMMAND}

container-ssh: build-base-container
	docker run --rm -it --platform linux/amd64 \
		-v $(pwd):/skywalking-rover -w /skywalking-rover --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/skywalking-rover=." \
		--env HOME="/skywalking-rover" \
		"localhost:5000/apache/skywalking-rover-base:vlatest" \
		/bin/bash