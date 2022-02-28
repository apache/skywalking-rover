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

package tools

import (
	"fmt"
	"net"
	"os"
)

var (
	host *hostInfo
)

func init() {
	host = queryHostInfo()
}

// HostIPAddress IP address of machine
func HostIPAddress() string {
	return host.ipAddr
}

// Hostname of machine
func Hostname() string {
	return host.name
}

type hostInfo struct {
	// hostname
	name string
	// ip address
	ipAddr string
}

func queryHostInfo() *hostInfo {
	addr, err := localIPAddress0()
	if err != nil {
		panic(err)
	}
	name, err := hostname0()
	if err != nil {
		panic(err)
	}
	return &hostInfo{name: name, ipAddr: addr}
}

func hostname0() (string, error) {
	return os.Hostname()
}

func localIPAddress0() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	// handle err
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			// process IP address
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("IP not found")
}
