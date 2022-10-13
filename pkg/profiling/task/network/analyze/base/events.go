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

// SocketConnectEvent Socket have been connection/accept event
type SocketConnectEvent struct {
	ConID        uint64
	RandomID     uint64
	ExeTime      uint64
	NeedComplete uint32
	Pid          uint32
	FD           uint32
	FuncName     uint32

	// socket information if exists
	Role           ConnectionRole
	SocketFamily   uint32
	RemoteAddrV4   uint32
	RemoteAddrV6   [16]uint8
	RemoteAddrPort uint32
	LocalAddrV4    uint32
	LocalAddrV6    [16]uint8
	LocalAddrPort  uint32
}

type SocketCloseEvent struct {
	ConID    uint64
	RandomID uint64
	ExeTime  uint64
	Pid      uint32
	SocketFD uint32
	Role     ConnectionRole
	Protocol ConnectionProtocol
	IsSSL    uint32
	Fix      uint32

	SocketFamily   uint32
	RemoteAddrV4   uint32
	RemoteAddrV6   [16]uint8
	RemoteAddrPort uint32
	LocalAddrV4    uint32
	LocalAddrV6    [16]uint8
	LocalAddrPort  uint32
	Fix1           uint32

	WriteBytes   uint64
	WriteCount   uint64
	WriteExeTime uint64
	ReadBytes    uint64
	ReadCount    uint64
	ReadExeTime  uint64

	WriteRTTCount   uint64
	WriteRTTExeTime uint64
}
