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

package ssl

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type EnvoySymbolAddress struct {
	IsServerOffset uint64
}

func (r *Register) Envoy(envoySymbolAddrMap *ebpf.Map, sslWrite, sslWriteRet, sslRead, sslReadRet *ebpf.Program) {
	r.addHandler("Envoy", func() (bool, error) {
		moduleName := "/envoy"
		processModules, err := r.findModules(moduleName)
		if err != nil {
			return false, err
		}
		envoyModule := processModules[moduleName]
		if envoyModule == nil {
			return false, nil
		}
		var readSymbol, writeSymbol bool
		for _, sym := range envoyModule.Symbols {
			if sym.Name == "SSL_read" {
				readSymbol = true
			} else if sym.Name == "SSL_write" {
				writeSymbol = true
			}
		}
		if !readSymbol || !writeSymbol {
			log.Debugf("found the envoy process, but the ssl read or write symbol not exists, so ignore. read: %t, write: %t",
				readSymbol, writeSymbol)
			return false, nil
		}

		if envoySymbolAddrMap != nil {
			addr := &EnvoySymbolAddress{
				// for now the server field have fixed position
				// https://github.com/google/boringssl/blob/master/ssl/internal.h#L3734-L3812
				IsServerOffset: 164,
			}

			if err := envoySymbolAddrMap.Put(uint32(r.pid), addr); err != nil {
				return false, fmt.Errorf("setting the envoy symbol offsets failure, pid: %d, error: %v", r.pid, err)
			}
		}

		envoy := r.linker.OpenUProbeExeFile(envoyModule.Path)
		envoy.AddLink("SSL_write", sslWrite, sslWriteRet)
		envoy.AddLink("SSL_read", sslRead, sslReadRet)
		if e := r.linker.HasError(); e != nil {
			return false, e
		}
		return true, nil
	})
}
