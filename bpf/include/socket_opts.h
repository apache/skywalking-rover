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

// the socket operation type
#define SOCKET_OPTS_TYPE_CONNECT    1
#define SOCKET_OPTS_TYPE_ACCEPT     2
#define SOCKET_OPTS_TYPE_CLOSE      3
#define SOCKET_OPTS_TYPE_SEND       4
#define SOCKET_OPTS_TYPE_SENDTO     5
#define SOCKET_OPTS_TYPE_SENDMSG    6
#define SOCKET_OPTS_TYPE_SENDMMSG   7
#define SOCKET_OPTS_TYPE_SENDFILE   8
#define SOCKET_OPTS_TYPE_WRITE      9
#define SOCKET_OPTS_TYPE_WRITEV     10
#define SOCKET_OPTS_TYPE_READ       11
#define SOCKET_OPTS_TYPE_READV      12
#define SOCKET_OPTS_TYPE_RECV       13
#define SOCKET_OPTS_TYPE_RECVFROM   14
#define SOCKET_OPTS_TYPE_RECVMSG    15
#define SOCKET_OPTS_TYPE_RECVMMSG   16
#define SOCKET_OPTS_TYPE_RESENT     17
#define SOCKET_OPTS_TYPE_SSL_WRITE  18
#define SOCKET_OPTS_TYPE_SSL_READ   19
#define SOCKET_OPTS_TYPE_GOTLS_WRITE 20
#define SOCKET_OPTS_TYPE_GOTLS_READ  21

// for protocol analyze need to read
#define MAX_PROTOCOL_SOCKET_READ_LENGTH 31
// for transmit to the user space
#define MAX_TRANSMIT_SOCKET_READ_LENGTH 2048

// unknown the connection type, not trigger the syscall connect,accept
#define AF_UNKNOWN 0xff

#define CONNECTION_ROLE_TYPE_UNKNOWN 0
#define CONNECTION_ROLE_TYPE_CLIENT 1
#define CONNECTION_ROLE_TYPE_SERVER 2

// data direction
#define SOCK_DATA_DIRECTION_INGRESS 1 //receive from
#define SOCK_DATA_DIRECTION_EGRESS 2  //write to
