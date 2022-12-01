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

package base

const (
	unknown = "unknown"
	http    = "http"
)

// ConnectionRole represents the role of the current process is the connection
// whether it's a server or a client, if it's not trigger the connection/accept request, then it's unknown
type ConnectionRole uint32

const (
	ConnectionRoleUnknown ConnectionRole = 0
	ConnectionRoleClient  ConnectionRole = 1
	ConnectionRoleServer  ConnectionRole = 2
)

func (r ConnectionRole) String() string {
	switch r {
	case ConnectionRoleClient:
		return "client"
	case ConnectionRoleServer:
		return "server"
	default:
		return unknown
	}
}

func (r ConnectionRole) Revert() ConnectionRole {
	switch r {
	case ConnectionRoleClient:
		return ConnectionRoleServer
	case ConnectionRoleServer:
		return ConnectionRoleClient
	default:
		return ConnectionRoleUnknown
	}
}

// SocketDataDirection indicates whether data is being written or receive
type SocketDataDirection uint8

const (
	SocketDataDirectionIngress SocketDataDirection = 1
	SocketDataDirectionEgress  SocketDataDirection = 2
)

func (d SocketDataDirection) String() string {
	switch d {
	case SocketDataDirectionIngress:
		return "inbound"
	case SocketDataDirectionEgress:
		return "outbound"
	default:
		return unknown
	}
}

// SocketDataStaticsType represents the stat type when read or write
type SocketDataStaticsType uint8

const (
	SocketDataStaticsTypeRTT     = 1
	SocketDataStaticsTypeExeTime = 2
)

type SocketExceptionOperationType uint32

const (
	SocketExceptionOperationRetransmit SocketExceptionOperationType = 1
	SocketExceptionOperationDrop       SocketExceptionOperationType = 2
)

type ConnectionProtocol uint8

const (
	ConnectionProtocolUnknown ConnectionProtocol = 0
	ConnectionProtocolHTTP    ConnectionProtocol = 1
	ConnectionProtocolHTTP2   ConnectionProtocol = 2
)

func (c ConnectionProtocol) String() string {
	switch c {
	case ConnectionProtocolUnknown:
		return unknown
	case ConnectionProtocolHTTP:
		return http
	case ConnectionProtocolHTTP2:
		return http
	default:
		return unknown
	}
}

type GoTLSArgsLocationType uint32

const (
	GoTLSArgsLocationTypeStack    GoTLSArgsLocationType = 1
	GoTLSArgsLocationTypeRegister GoTLSArgsLocationType = 2
)

type SocketMessageType uint8

const (
	SocketMessageTypeUnknown  SocketMessageType = 0
	SocketMessageTypeRequest  SocketMessageType = 1
	SocketMessageTypeResponse SocketMessageType = 2
)

func (m SocketMessageType) String() string {
	switch m {
	case SocketMessageTypeRequest:
		return "request"
	case SocketMessageTypeResponse:
		return "response"
	default:
		return unknown
	}
}
