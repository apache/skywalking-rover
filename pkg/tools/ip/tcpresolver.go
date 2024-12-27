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

package ip

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/tools/enums"

	processNet "github.com/shirou/gopsutil/net"
)

type SocketPair struct {
	Family   uint32
	Role     enums.ConnectionRole
	SrcIP    string
	SrcPort  uint16
	DestIP   string
	DestPort uint16

	NeedConnTrack bool
}

func (s *SocketPair) IsValid() bool {
	return s.Family != 0 && s.Role != enums.ConnectionRoleUnknown &&
		s.SrcIP != "" && s.SrcPort != 0 && s.DestIP != "" && s.DestPort != 0
}

func ParseSocket(pid, sockfd uint32) (*SocketPair, error) {
	connections, err := processNet.ConnectionsPid("tcp", int32(pid))
	if err != nil {
		return nil, fmt.Errorf("cannot get all connections from pid: %d", pid)
	}

	for _, connection := range connections {
		if connection.Fd == sockfd {
			return &SocketPair{
				Family:   connection.Family,
				SrcIP:    connection.Laddr.IP,
				SrcPort:  uint16(connection.Laddr.Port),
				DestIP:   connection.Raddr.IP,
				DestPort: uint16(connection.Raddr.Port),
			}, nil
		}
	}
	if log.Enable(logrus.DebugLevel) {
		existConnections := make([]uint32, 0)
		for _, conn := range connections {
			existConnections = append(existConnections, conn.Fd)
		}
		log.Debugf("total connection in the pid: %d, exist connections: %v", pid, existConnections)
	}
	return nil, fmt.Errorf("cannot found the connection, pid: %d, socket FD: %d", pid, sockfd)
}

func (s *SocketPair) String() string {
	return fmt.Sprintf("family: %d, role: %s, srcIP: %s, srcPort: %d, destIP: %s, destPort: %d",
		s.Family, s.Role.String(), s.SrcIP, s.SrcPort, s.DestIP, s.DestPort)
}
