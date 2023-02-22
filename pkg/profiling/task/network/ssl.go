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

package network

import (
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"
	"github.com/apache/skywalking-rover/pkg/tools/ssl"
)

func addSSLProcess(pid int, loader *bpf.Loader) error {
	register := ssl.NewSSLRegister(pid, loader.Linker)

	register.OpenSSL(loader.OpensslSymaddrMap, loader.OpensslWrite, loader.OpensslWriteRet, loader.OpensslRead, loader.OpensslReadRet)

	register.Envoy(nil, loader.OpensslWrite, loader.OpensslWriteRet, loader.OpensslRead, loader.OpensslReadRet)

	register.GoTLS(loader.GoTlsArgsSymaddrMap, loader.GoCasgstatus, loader.GoTlsWrite, loader.GoTlsWriteRet, loader.GoTlsRead, loader.GoTlsReadRet)

	register.Node(nil, loader.NodeTlsSymaddrMap, loader.OpensslWrite, loader.OpensslWriteRet, loader.OpensslRead, loader.OpensslReadRet,
		loader.NodeTlsRetSsl, loader.NodeTlsWrap, loader.NodeTlsWrapRet)

	return register.Execute()
}
