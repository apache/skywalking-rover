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

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var (
	notBlankRegex = regexp.MustCompile(`\s+`)
	ipv4StrLen    = 8
	ipv6StrLen    = 32
)

type SocketPair struct {
	SrcIP    string
	SrcPort  uint16
	DestIP   string
	DestPort uint16
}

func ParseSocket(pid, sockfd uint32) (*SocketPair, error) {
	link := fmt.Sprintf("/proc/%d/fd/%d", pid, sockfd)
	dest, err := os.Readlink(host.GetFileInHost(link))
	if err != nil {
		return nil, fmt.Errorf("could not read the socket real link: %v", err)
	}
	if !strings.HasPrefix(dest, "socket:[") {
		return nil, fmt.Errorf("current file is not socket: %s", dest)
	}

	inode := strings.TrimSuffix(strings.TrimPrefix(dest, "socket:["), "]")
	var s *SocketPair
	s, err = foundAddressByFile(s, err, fmt.Sprintf(host.GetFileInHost("/proc/%d/net/tcp"), pid), inode)
	s, err = foundAddressByFile(s, err, fmt.Sprintf(host.GetFileInHost("/proc/%d/net/tcp6"), pid), inode)
	return s, err
}

func foundAddressByFile(s *SocketPair, exitedError error, filename, inode string) (*SocketPair, error) {
	if s != nil {
		return s, nil
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, multierror.Append(exitedError, err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1 : len(lines)-1] {
		source := notBlankRegex.Split(strings.TrimSpace(line), -1)
		if len(source) < 10 {
			continue
		}
		tcpINode := source[9]
		if tcpINode != inode {
			continue
		}

		// ignore local listenning records
		destIP, destPort, err := parseAddr(source[2])
		if err != nil {
			return nil, multierror.Append(exitedError, fmt.Errorf("parsing address in file failure: %s, error: %s", filename, err))
		}

		// source ip and port
		ip, port, err := parseAddr(source[1])
		if err != nil {
			return nil, multierror.Append(exitedError, fmt.Errorf("parsing address in file failure: %s, error: %s", filename, err))
		}

		return &SocketPair{
			SrcIP:    ip,
			SrcPort:  port,
			DestIP:   destIP,
			DestPort: destPort,
		}, nil
	}
	return nil, multierror.Append(exitedError, fmt.Errorf("could not found the socket: %s, in file: %s", inode, filename))
}

func parseAddr(str string) (ipAddr string, port uint16, err error) {
	fields := strings.Split(str, ":")
	if len(fields) < 2 {
		return "", 0, fmt.Errorf("netstat: not enough fields: %v", fields)
	}
	var ip net.IP
	switch len(fields[0]) {
	case ipv4StrLen:
		ip, err = parseIPv4(fields[0])
	case ipv6StrLen:
		ip, err = parseIPv6(fields[0])
	default:
		err = fmt.Errorf("netstat: bad formatted string: %v", fields[0])
	}
	if err != nil {
		return "", 0, err
	}
	v, err := strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	return ip.String(), uint16(v), nil
}

func parseIPv4(s string) (net.IP, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, uint32(v))
	return ip, nil
}

func parseIPv6(s string) (net.IP, error) {
	ip := make(net.IP, net.IPv6len)
	const grpLen = 4
	i, j := 0, 4
	for s != "" {
		grp := s[0:8]
		u, err := strconv.ParseUint(grp, 16, 32)
		binary.LittleEndian.PutUint32(ip[i:j], uint32(u))
		if err != nil {
			return nil, err
		}
		i, j = i+grpLen, j+grpLen
		s = s[8:]
	}
	return ip, nil
}
