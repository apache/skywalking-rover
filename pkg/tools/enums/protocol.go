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

package enums

type ParseResult int

const (
	ParseResultSuccess ParseResult = iota
	ParseResultSkipPackage
)

type ConnectionProtocol uint8

const (
	ConnectionProtocolUnknown ConnectionProtocol = 0
	ConnectionProtocolHTTP    ConnectionProtocol = 1
	ConnectionProtocolHTTP2   ConnectionProtocol = 2
)

var connectionProtocolMap = make(map[ConnectionProtocol]string)

func init() {
	RegisterConnectionProtocolString(ConnectionProtocolHTTP, http)
	RegisterConnectionProtocolString(ConnectionProtocolHTTP2, http)
}

func RegisterConnectionProtocolString(protocol ConnectionProtocol, name string) {
	connectionProtocolMap[protocol] = name
}

func ConnectionProtocolString(protocol ConnectionProtocol) string {
	if name, ok := connectionProtocolMap[protocol]; ok {
		return name
	}
	return unknown
}
