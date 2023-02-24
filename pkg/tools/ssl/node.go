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
	"os/exec"
	"regexp"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
	"github.com/apache/skywalking-rover/pkg/tools/version"

	"github.com/cilium/ebpf"
)

var (
	nodeVersionRegex = regexp.MustCompile(`^node\.js/v(?P<Major>\d+)\.(?P<Minor>\d+)\.(?P<Patch>\d+)$`)
)

type NodeTLSSymbolAddress struct {
	TLSWrapStreamListenerOffset     uint32
	StreamListenerStreamOffset      uint32
	StreamBaseStreamResourceOffset  uint32
	LibuvStreamWrapStreamBaseOffset uint32
	LibuvStreamWrapStreamOffset     uint32
	UVStreamSIOWatcherOffset        uint32
	UVIOSFDOffset                   uint32
}

func (r *Register) Node(sslSymbolOffsetsMap, nodeTLSSymbolOffsetsMap *ebpf.Map,
	sslWrite, sslWriteRet, sslRead, sslReadRet,
	sslNew, tlsWrap, tlsWrapRet *ebpf.Program) {
	r.addHandler("Node", func() (bool, error) {
		libSSLModule, nodeModule, openSSLAttach, err := r.findNodeTLSModules()
		if err != nil {
			return false, err
		}
		if libSSLModule == nil || nodeModule == nil {
			return false, nil
		}
		v, err := r.getNodeVersion(nodeModule.Path)
		if err != nil {
			return false, err
		}
		log.Debugf("read the nodejs version, pid: %d, version: %s", r.pid, v)
		// openSSL symbol offsets
		if sslSymbolOffsetsMap != nil {
			config, err := r.buildOpenSSLSymAddrConfig(libSSLModule.Path)
			if err != nil {
				return false, err
			}
			if err := sslSymbolOffsetsMap.Put(uint32(r.pid), config); err != nil {
				return false, err
			}
		}
		if nodeTLSSymbolOffsetsMap != nil {
			config, err := r.findNodeTLSAddrConfig(v)
			if err != nil {
				return false, err
			}
			// setting the locations
			if err := nodeTLSSymbolOffsetsMap.Put(uint32(r.pid), config); err != nil {
				return false, fmt.Errorf("setting the node TLS location failure, pid: %d, error: %v", r.pid, err)
			}
		}
		libSSLLinker := r.linker.OpenUProbeExeFile(libSSLModule.Path)
		if openSSLAttach {
			libSSLLinker.AddLink("SSL_write", sslWrite, sslWriteRet)
			libSSLLinker.AddLink("SSL_read", sslRead, sslReadRet)
		}
		if e := r.nodeTLSRegisterProbes(v, libSSLLinker, nodeModule, sslNew, tlsWrap, tlsWrapRet); e != nil {
			return false, e
		}
		if e := r.linker.HasError(); e != nil {
			return false, e
		}
		return true, nil
	})
}

func (r *Register) getNodeVersion(p string) (*version.Version, error) {
	result, err := exec.Command("strings", p).Output()
	if err != nil {
		return nil, err
	}
	for _, d := range strings.Split(string(result), "\n") {
		versionInfo := nodeVersionRegex.FindStringSubmatch(strings.TrimSpace(d))
		if len(versionInfo) != 4 {
			continue
		}
		return version.Read(versionInfo[1], versionInfo[2], versionInfo[3])
	}

	return nil, fmt.Errorf("nodejs version is not found")
}

var nodeTLSAddrWithVersions = []struct {
	v    *version.Version
	conf *NodeTLSSymbolAddress
}{
	{version.Build(10, 19, 0), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(12, 3, 1), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(12, 16, 2), &NodeTLSSymbolAddress{0x0138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(13, 0, 0), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(13, 2, 0), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(13, 10, 1), &NodeTLSSymbolAddress{0x0140, 0x08, 0x00, 0x60, 0xa0, 0x88, 0x30}},
	{version.Build(14, 5, 0), &NodeTLSSymbolAddress{0x138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(15, 0, 0), &NodeTLSSymbolAddress{0x78, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
}

var nodeTLSProbeWithVersions = []struct {
	v *version.Version
	f func(uprobe *btf.UProbeExeFile, register *Register, nodeModule *profiling.Module, tlsWrap, tlsWrapRet *ebpf.Program)
}{
	{version.Build(10, 19, 0), func(uprobe *btf.UProbeExeFile, register *Register, nodeModule *profiling.Module, tlsWrap, tlsWrapRet *ebpf.Program) {
		uprobe.AddLinkWithSymbols(register.searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node7TLSWrapC2E"),
			tlsWrap, tlsWrapRet)
		uprobe.AddLinkWithSymbols(register.searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node7TLSWrap7ClearInE"),
			tlsWrap, tlsWrapRet)
		uprobe.AddLinkWithSymbols(register.searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node7TLSWrap8ClearOutE"),
			tlsWrap, tlsWrapRet)
	}},
	{version.Build(15, 0, 0), func(uprobe *btf.UProbeExeFile, register *Register, nodeModule *profiling.Module, tlsWrap, tlsWrapRet *ebpf.Program) {
		uprobe.AddLinkWithSymbols(register.searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node6crypto7TLSWrapC2E"),
			tlsWrap, tlsWrapRet)
		uprobe.AddLinkWithSymbols(register.searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node6crypto7TLSWrap7ClearInE"),
			tlsWrap, tlsWrapRet)
		uprobe.AddLinkWithSymbols(register.searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node6crypto7TLSWrap8ClearOutE"),
			tlsWrap, tlsWrapRet)
	}},
}

func (r *Register) findNodeTLSAddrConfig(v *version.Version) (*NodeTLSSymbolAddress, error) {
	var lastest *NodeTLSSymbolAddress
	for _, c := range nodeTLSAddrWithVersions {
		if v.GreaterOrEquals(c.v) {
			lastest = c.conf
		}
	}
	if lastest != nil {
		return lastest, nil
	}
	return nil, fmt.Errorf("could not support version: %s", v)
}

func (r *Register) findNodeTLSModules() (libSSLModule, nodeModule *profiling.Module, openSSLAttach bool, err error) {
	moduleName1, moduleName2, libsslName := "/nodejs", "/node", "libssl.so"
	processModules, err := r.findModules(moduleName1, moduleName2, libsslName)
	if err != nil {
		return nil, nil, false, err
	}
	nodeModule = processModules[moduleName1]
	libSSLModule = processModules[libsslName]
	if nodeModule == nil {
		nodeModule = processModules[moduleName2]
	}
	if nodeModule == nil {
		return nil, nil, false, nil
	}
	if libSSLModule == nil {
		if r.searchSymbolInModules([]*profiling.Module{nodeModule}, func(a, b string) bool {
			return a == b
		}, "SSL_read") == nil || r.searchSymbolInModules([]*profiling.Module{nodeModule}, func(a, b string) bool {
			return a == b
		}, "SSL_write") == nil {
			return nil, nil, false, nil
		}
		libSSLModule = nodeModule
		openSSLAttach = true
	}
	return
}

func (r *Register) nodeTLSRegisterProbes(v *version.Version, libSSLLinker *btf.UProbeExeFile, nodeModule *profiling.Module,
	sslNew, tlsWrap, tlsWrapRet *ebpf.Program) error {
	if sslNew != nil {
		libSSLLinker.AddLinkWithType("SSL_new", false, sslNew)
	}
	if tlsWrap != nil && tlsWrapRet != nil {
		var probeFunc func(uprobe *btf.UProbeExeFile, register *Register, nodeModule *profiling.Module, tlsWrap, tlsWrapRet *ebpf.Program)
		for _, c := range nodeTLSProbeWithVersions {
			if v.GreaterOrEquals(c.v) {
				probeFunc = c.f
			}
		}
		if probeFunc == nil {
			return fmt.Errorf("the version is not support to attach TLSWrap relate probes: %v, pid: %d", v, r.pid)
		}
		file := r.linker.OpenUProbeExeFile(nodeModule.Path)
		probeFunc(file, r, nodeModule, tlsWrap, tlsWrapRet)
	}

	return nil
}
