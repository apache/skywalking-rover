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

docker: PLATFORMS =
docker: LOAD_OR_PUSH = --load
docker: build-base-container
docker: BASE_IMAGE_NAME = ${CONTAINER_COMMAND_IMAGE}
docker.push: PLATFORMS = ${CONTAINER_PLATFORMS}
docker.push: LOAD_OR_PUSH = --push
docker.push: build-base-container-with-multi-args
docker.push: BASE_IMAGE_NAME = localhost:5000/skywalking-rover-base

docker docker.push:
	$(DOCKER_RULE)

define DOCKER_RULE
	docker buildx build ${PLATFORMS} ${LOAD_OR_PUSH} \
		--build-arg VERSION=$(VERSION) \
		--build-arg BASE_IMAGE=${BASE_IMAGE_NAME}:${CONTAINER_COMMAND_TAG} \
		-t $(HUB)/skywalking-rover:latest \
		-t $(HUB)/skywalking-rover:$(VERSION) --no-cache . -f docker/Dockerfile.build
	@$(MAKE) build-base-container-with-multi-args-cleanup
endef
