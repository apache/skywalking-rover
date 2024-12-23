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
	"net"
	"syscall"

	"github.com/florianl/go-conntrack"

	"github.com/apache/skywalking-rover/pkg/logger"

	"golang.org/x/sys/unix"
)

var log = logger.GetLogger("tools", "ip")

var numberStrategies = []struct {
	name  string
	proto uint8
}{{
	name:  "tcp",
	proto: syscall.IPPROTO_TCP,
}}

type ConnTrack struct {
	tracker *conntrack.Nfct
}

func NewConnTrack() (*ConnTrack, error) {
	nfct, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		return nil, err
	}
	return &ConnTrack{tracker: nfct}, nil
}

func (c *ConnTrack) UpdateRealPeerAddress(addr *SocketPair) bool {
	family := conntrack.IPv4
	if addr.Family == unix.AF_INET6 {
		family = conntrack.IPv6
	}

	tuple := c.parseSocketToTuple(addr)
	for _, info := range numberStrategies {
		tuple.Proto.Number = &(info.proto)

		// using get to query protocol
		session, e := c.tracker.Get(conntrack.Conntrack, family, conntrack.Con{Origin: tuple})
		if e != nil {
			// try to get the reply session, if the info not exists or from accept events, have error is normal
			log.Debugf("cannot get the conntrack session, type: %s, family: %d, origin src: %s:%d, origin dest: %s:%d, error: %v", info.name,
				family, tuple.Src, *tuple.Proto.SrcPort, tuple.Dst, *tuple.Proto.DstPort, e)
			continue
		}

		if res := c.filterValidateReply(session, tuple); res != nil {
			addr.DestIP = res.Src.String()
			return true
		}
	}
	return false
}

func (c *ConnTrack) parseSocketToTuple(addr *SocketPair) *conntrack.IPTuple {
	tcp := uint8(syscall.IPPROTO_TCP)
	srcIP := net.ParseIP(addr.SrcIP)
	dstIP := net.ParseIP(addr.DestIP)
	var srcPort, dstPort = addr.SrcPort, addr.DestPort
	return &conntrack.IPTuple{
		Src: &srcIP,
		Dst: &dstIP,
		Proto: &conntrack.ProtoTuple{
			Number:  &tcp,
			SrcPort: &srcPort,
			DstPort: &dstPort,
		},
	}
}

func (c *ConnTrack) ipTupleValid(t *conntrack.IPTuple) bool {
	if t == nil {
		return false
	}
	if t.Src == nil || t.Dst == nil || t.Proto == nil {
		return false
	}
	if t.Proto.SrcPort == nil || t.Proto.DstPort == nil {
		return false
	}
	return true
}

func (c *ConnTrack) ipTuplesEqual(a, b *conntrack.IPTuple) bool {
	return a.Src.Equal(*b.Src) && a.Dst.Equal(*b.Dst) && *a.Proto.SrcPort == *b.Proto.SrcPort && *a.Proto.DstPort == *b.Proto.DstPort
}

func (c *ConnTrack) filterValidateReply(sessions []conntrack.Con, origin *conntrack.IPTuple) (reply *conntrack.IPTuple) {
	for inx := range sessions {
		if !c.ipTupleValid(sessions[inx].Origin) || !c.ipTupleValid(sessions[inx].Reply) {
			continue
		}
		if c.ipTuplesEqual(origin, sessions[inx].Origin) {
			return sessions[inx].Reply
		}
	}
	return nil
}
