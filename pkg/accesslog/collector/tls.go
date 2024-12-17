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

package collector

import (
	"sync"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/ssl"
)

var tlsLog = logger.GetLogger("access_log", "collector", "tls")

var tlsCollectInstance = NewTLSCollector()

type TLSCollector struct {
	context            *common.AccessLogContext
	monitoredProcesses map[int32]bool
	linker             *btf.Linker
	mutex              sync.Mutex
}

func NewTLSCollector() *TLSCollector {
	return &TLSCollector{
		monitoredProcesses: make(map[int32]bool),
		linker:             btf.NewLinker(),
	}
}

func (c *TLSCollector) Start(_ *module.Manager, context *common.AccessLogContext) error {
	c.context = context
	context.ConnectionMgr.AddProcessListener(c)
	return nil
}

func (c *TLSCollector) Stop() {
	if err := c.linker.Close(); err != nil {
		tlsLog.Warnf("close linker failure, error: %v", err)
	}
	c.monitoredProcesses = make(map[int32]bool)
	c.linker = btf.NewLinker()
}

func (c *TLSCollector) OnNewProcessMonitoring(pid int32) {
	go func() {
		c.addProcess(pid)
	}()
}

func (c *TLSCollector) addProcess(pid int32) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, ok := c.monitoredProcesses[pid]; ok {
		return
	}
	c.monitoredProcesses[pid] = true

	register := ssl.NewSSLRegister(int(pid), c.linker)

	register.OpenSSL(c.context.BPF.OpensslSymaddrMap, c.context.BPF.OpensslWrite, c.context.BPF.OpensslWriteRet,
		c.context.BPF.OpensslRead, c.context.BPF.OpensslReadRet)

	register.Envoy(nil, c.context.BPF.OpensslWrite, c.context.BPF.OpensslWriteRet,
		c.context.BPF.OpensslRead, c.context.BPF.OpensslReadRet)

	register.GoTLS(c.context.BPF.GoTlsArgsSymaddrMap, c.context.BPF.GoTlsWrite, c.context.BPF.GoTlsWriteRet,
		c.context.BPF.GoTlsRead, c.context.BPF.GoTlsReadRet)

	register.Node(nil, c.context.BPF.NodeTlsSymaddrMap, c.context.BPF.OpensslWrite, c.context.BPF.OpensslWriteRet,
		c.context.BPF.OpensslRead, c.context.BPF.OpensslReadRet, c.context.BPF.NodeTlsRetSsl, c.context.BPF.NodeTlsWrap, c.context.BPF.NodeTlsWrapRet)

	if err := register.Execute(); err != nil {
		tlsLog.Errorf("register TLS failure, pid: %d, error: %v", pid, err)
		delete(c.monitoredProcesses, pid)
	}
}

func (c *TLSCollector) OnProcessRemoved(pid int32) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.monitoredProcesses, pid)
}
