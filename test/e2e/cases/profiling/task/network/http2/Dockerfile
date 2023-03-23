# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.17

COPY http2/ /service

WORKDIR /
RUN apt update && apt install -y zip && \
    mkdir protoc && cd protoc && \
    curl -sL https://github.com/protocolbuffers/protobuf/releases/download/v21.5/protoc-21.5-linux-x86_64.zip -o protoc.zip && \
    unzip protoc.zip

WORKDIR /service

RUN go get -u google.golang.org/protobuf/cmd/protoc-gen-go@v1.26.0 && \
    go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0 && \
    go get google.golang.org/grpc/internal/transport@v1.44.0 && \
    /protoc/bin/protoc --go_out=. --go-grpc_out=. service.proto && \
    go build .

COPY base/ssl /usr/local/share/ca-certificates
RUN update-ca-certificates

CMD ["/service/test"]
