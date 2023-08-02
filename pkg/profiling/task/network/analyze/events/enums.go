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

package events

import "fmt"

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

type SocketFunctionName uint8

const (
	SocketFunctionNameConnect    = 1
	SocketFunctionNameAccept     = 2
	SocketFunctionNameClose      = 3
	SocketFunctionNameSend       = 4
	SocketFunctionNameSendto     = 5
	SocketFunctionNameSendMsg    = 6
	SocketFunctionNameSendMMSg   = 7
	SocketFunctionNameSendFile   = 8
	SocketFunctionNameWrite      = 9
	SocketFunctionNameWritev     = 10
	SocketFunctionNameRead       = 11
	SocketFunctionNameReadv      = 12
	SocketFunctionNameRecv       = 13
	SocketFunctionNameRecvfrom   = 14
	SocketFunctionNameRecvMsg    = 15
	SocketFunctionNameRecvMMsg   = 16
	SocketFunctionNameResent     = 17
	SocketFunctionNameSslWrite   = 18
	SocketFunctionNameSslRead    = 19
	SocketFunctionNameGoTLSWrite = 20
	SocketFunctionNameGoTLSRead  = 21
)

// nolint
func (f SocketFunctionName) String() string {
	switch f {
	case SocketFunctionNameConnect:
		return "Connect"
	case SocketFunctionNameAccept:
		return "Accept"
	case SocketFunctionNameClose:
		return "Close"
	case SocketFunctionNameSend:
		return "Send"
	case SocketFunctionNameSendto:
		return "Sendto"
	case SocketFunctionNameSendMsg:
		return "SendMsg"
	case SocketFunctionNameSendMMSg:
		return "SendMMSg"
	case SocketFunctionNameSendFile:
		return "SendFile"
	case SocketFunctionNameWrite:
		return "Write"
	case SocketFunctionNameWritev:
		return "Writev"
	case SocketFunctionNameRead:
		return "Read"
	case SocketFunctionNameReadv:
		return "Readv"
	case SocketFunctionNameRecv:
		return "Recv"
	case SocketFunctionNameRecvfrom:
		return "Recvfrom"
	case SocketFunctionNameRecvMsg:
		return "RecvMsg"
	case SocketFunctionNameRecvMMsg:
		return "RecvMMsg"
	case SocketFunctionNameResent:
		return "Resent"
	case SocketFunctionNameSslWrite:
		return "SslWrite"
	case SocketFunctionNameSslRead:
		return "SslRead"
	case SocketFunctionNameGoTLSWrite:
		return "GoTLSWrite"
	case SocketFunctionNameGoTLSRead:
		return "GoTLSRead"
	default:
		return fmt.Sprintf("Unknown(%d)", f)
	}
}
