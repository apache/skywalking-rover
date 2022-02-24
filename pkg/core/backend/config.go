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

package backend

type Config struct {
	Addr string `mapstructure:"addr"` // Server address
	// TLS settings
	EnableTLS          bool   `mapstructure:"enable_tls"`           // Enable TLS connect to server
	ClientPemPath      string `mapstructure:"client_pem_path"`      // The file path of client.pem. The config only works when opening the TLS switch.
	ClientKeyPath      string `mapstructure:"client_key_path"`      // The file path of client.key. The config only works when opening the TLS switch.
	CaPemPath          string `mapstructure:"ca_pem_path"`          // The file path oca.pem. The config only works when opening the TLS switch.
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"` // Controls whether a client verifies the server's certificate chain and host name.
	Authentication     string `mapstructure:"authentication"`       // The auth value when send request
	CheckPeriod        int    `mapstructure:"check_period"`         // How frequently to check the connection(second)
}
