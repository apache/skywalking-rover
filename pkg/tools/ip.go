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

// DefaultHostIPAddress IP address of machine
func DefaultHostIPAddress() string {
	return host.defaultIPAddr
}

// HostIPAddressV4 found the IPV4 address from appoint net interface name
func HostIPAddressV4(name string) string {
	address := host.ipAddresses[name]
	if address == nil {
		return ""
	}
	return address.ipV4
}

// HostIPAddressV6 found the IPV6 address from appoint net interface name
func HostIPAddressV6(name string) string {
	address := host.ipAddresses[name]
	if address == nil {
		return ""
	}
	return address.ipV6
}

// IsLocalHostAddress is the address from local
func IsLocalHostAddress(address string) bool {
	for _, h := range host.ipAddresses {
		if h.ipV4 == address || h.ipV6 == address {
			return true
		}
	}
	return false
}

// Hostname of machine
func Hostname() string {
	return host.name
}

type hostInfo struct {
	// hostname
	name string
	// ip address
	ipAddresses   map[string]*hostIPAddress
	defaultIPAddr string
}

type hostIPAddress struct {
	ipV4 string
	ipV6 string
}

func queryHostInfo() *hostInfo {
	addresses, def, err := localIPAddress0()
	if err != nil {
		panic(err)
	}
	name, err := hostname0()
	if err != nil {
		panic(err)
	}
	return &hostInfo{name: name, ipAddresses: addresses, defaultIPAddr: def}
}

func hostname0() (string, error) {
	return os.Hostname()
}

func localIPAddress0() (ipAddresses map[string]*hostIPAddress, defAddr string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", err
	}
	// handle err
	ipAddresses = make(map[string]*hostIPAddress)
	var defV4, defV6 string
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, "", err
		}
		ipv4, ipv6 := analyzeIPAddresses(addrs)

		if ipv4 != "" || ipv6 != "" {
			if defV4 == "" {
				defV4 = ipv4
			}
			if defV6 == "" {
				defV6 = ipv6
			}
			ipAddresses[i.Name] = &hostIPAddress{ipV4: ipv4, ipV6: ipv6}
		}
	}

	if len(ipAddresses) == 0 {
		return nil, "", fmt.Errorf("not found")
	}

	if defV4 != "" {
		defAddr = defV4
	} else {
		defAddr = defV6
	}

	return ipAddresses, defAddr, nil
}

func analyzeIPAddresses(addrs []net.Addr) (ipv4, ipv6 string) {
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip.IsLoopback() {
			continue
		}
		if ip.To4() != nil {
			ipv4 = ip.To4().String()
		}
		if ip.To16() != nil {
			ipv6 = ip.To16().String()
		}
	}
	return ipv4, ipv6
}
