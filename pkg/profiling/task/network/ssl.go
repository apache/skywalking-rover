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
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/elf"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/path"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
	"github.com/apache/skywalking-rover/pkg/tools/version"
)

var (
	openSSLVersionRegex  = regexp.MustCompile(`^OpenSSL\s+(?P<Major>\d)\.(?P<Minor>\d)\.(?P<Fix>\d+)\w+`)
	goVersionRegex       = regexp.MustCompile(`^go(?P<Major>\d)\.(?P<Minor>\d+)`)
	goTLSWriteSymbol     = "crypto/tls.(*Conn).Write"
	goTLSReadSymbol      = "crypto/tls.(*Conn).Read"
	goTLSGIDStatusSymbol = "runtime.casgstatus"
	goTLSPollFDSymbol    = "internal/poll.FD"
	goTLSConnSymbol      = "crypto/tls.Conn"
	goTLSRuntimeG        = "runtime.g"
	nodeVersionRegex     = regexp.MustCompile(`^node\.js/v(?P<Major>\d+)\.(?P<Minor>\d+)\.(?P<Patch>\d+)$`)
)

type OpenSSLFdSymAddrConfigInBPF struct {
	BIOReadOffset  uint32
	BIOWriteOffset uint32
	FDOffset       uint32
}

func addSSLProcess(pid int, loader *bpf.Loader) error {
	modules, err := tools.ProcessModules(int32(pid))
	if err != nil {
		return fmt.Errorf("read process modules error: %d, error: %v", pid, err)
	}

	// openssl process
	if err1 := processOpenSSLProcess(pid, loader, modules); err1 != nil {
		return err1
	}

	// envoy with boring ssl
	if err1 := processEnvoyProcess(pid, loader, modules); err1 != nil {
		return err1
	}

	// GoTLS
	if err1 := processGoProcess(pid, loader, modules); err1 != nil {
		return err1
	}

	// Nodejs
	if err1 := processNodeProcess(pid, loader, modules); err1 != nil {
		return err1
	}

	return nil
}

func processOpenSSLProcess(pid int, loader *bpf.Loader, modules []*profiling.Module) error {
	var libcryptoName, libsslName = "libcrypto.so", "libssl.so"
	var libcryptoPath, libsslPath string
	processModules, err := findProcessModules(modules, libcryptoName, libsslName)
	if err != nil {
		return err
	}
	// the openssl not exists, so ignore
	if len(processModules) == 0 {
		return nil
	}
	if libcrypto := processModules[libcryptoName]; libcrypto != nil {
		libcryptoPath = libcrypto.Path
	}
	if libssl := processModules[libsslName]; libssl != nil {
		libsslPath = libssl.Path
	}
	if libcryptoPath == "" || libsslPath == "" {
		return fmt.Errorf("the OpenSSL library not complete, libcrypto: %s, libssl: %s", libcryptoPath, libsslPath)
	}

	// build the symbol address config and write to the bpf
	conf, err := buildSSLSymAddrConfig(libcryptoPath)
	if err != nil {
		return err
	}
	if err := loader.OpensslFdSymaddrFinder.Put(uint32(pid), conf); err != nil {
		return err
	}

	// attach the linker
	return processOpenSSLModule(loader, processModules[libsslName])
}

func processOpenSSLModule(loader *bpf.Loader, libSSLModule *profiling.Module) error {
	libSSLLinker := loader.OpenUProbeExeFile(libSSLModule.Path)
	libSSLLinker.AddLink("SSL_write", loader.OpensslWrite, loader.OpensslWriteRet)
	libSSLLinker.AddLink("SSL_read", loader.OpensslRead, loader.OpensslReadRet)
	return loader.HasError()
}

func processEnvoyProcess(_ int, loader *bpf.Loader, modules []*profiling.Module) error {
	moduleName := "/envoy"
	processModules, err := findProcessModules(modules, moduleName)
	if err != nil {
		return err
	}
	envoyModule := processModules[moduleName]
	if envoyModule == nil {
		return nil
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
		return nil
	}

	log.Debugf("found current module is envoy, so attach to the SSL read and write")

	// attach the linker
	libSSLLinker := loader.OpenUProbeExeFile(envoyModule.Path)
	libSSLLinker.AddLink("SSL_write", loader.OpensslWrite, loader.OpensslWriteRet)
	libSSLLinker.AddLink("SSL_read", loader.OpensslRead, loader.OpensslReadRet)
	return loader.HasError()
}

type SymbolLocation struct {
	Type   base.GoTLSArgsLocationType
	Offset uint32
}

type GoTLSSymbolAddresses struct {
	// net.Conn addresses
	FDSysFDOffset uint64
	TLSConnOffset uint64
	GIDOffset     uint64
	TCPConnOffset uint64

	// casgstatus(goroutine status change) function relate locations
	CasgStatusGPLoc     SymbolLocation
	CasgStatusNEWValLoc SymbolLocation

	// write function relate locations
	WriteConnectionLoc SymbolLocation
	WriteBufferLoc     SymbolLocation
	WriteRet0Loc       SymbolLocation
	WriteRet1Loc       SymbolLocation

	// write function relate locations
	ReadConnectionLoc SymbolLocation
	ReadBufferLoc     SymbolLocation
	ReadRet0Loc       SymbolLocation
	ReadRet1Loc       SymbolLocation
}

type GoStringInC struct {
	Ptr  uint64
	Size uint64
}

func processGoProcess(pid int, loader *bpf.Loader, modules []*profiling.Module) error {
	// check current process is go program
	buildVersionSymbol := searchSymbol(modules, func(a, b string) bool {
		return a == b
	}, "runtime.buildVersion")
	if buildVersionSymbol == nil {
		log.Debugf("current process is not Go program, so won't add the GoTLS protos. pid: %d", pid)
		return nil
	}
	pidExeFile := host.GetFileInHost(fmt.Sprintf("/proc/%d/exe", pid))
	elfFile, err := elf.NewFile(pidExeFile)
	if err != nil {
		return fmt.Errorf("read executable file error: %v", err)
	}
	defer elfFile.Close()

	v, err := getGoVersion(elfFile, buildVersionSymbol)
	if err != nil {
		return err
	}

	// generate symbol offsets
	symbolConfig, elfFile, err := generateGOTLSSymbolOffsets(modules, pid, elfFile, v)
	if err != nil {
		return err
	}
	if symbolConfig == nil || elfFile == nil {
		return nil
	}

	// setting the locations
	if err := loader.GoTlsArgsSymaddrMap.Put(uint32(pid), symbolConfig); err != nil {
		return fmt.Errorf("setting the Go TLS argument location failure, pid: %d, error: %v", pid, err)
	}

	// uprobes
	exeFile := loader.OpenUProbeExeFile(pidExeFile)
	exeFile.AddLinkWithType("runtime.casgstatus", true, loader.GoCasgstatus)
	exeFile.AddGoLink(goTLSWriteSymbol, loader.GoTlsWrite, loader.GoTlsWriteRet, elfFile)
	exeFile.AddGoLink(goTLSReadSymbol, loader.GoTlsRead, loader.GoTlsReadRet, elfFile)

	return loader.HasError()
}

func processNodeProcess(pid int, loader *bpf.Loader, modules []*profiling.Module) error {
	moduleName1, moduleName2, libsslName := "/nodejs", "/node", "libssl.so"
	processModules, err := findProcessModules(modules, moduleName1, moduleName2, libsslName)
	if err != nil {
		return err
	}
	nodeModule := processModules[moduleName1]
	libsslModule := processModules[libsslName]
	needsReAttachSSL := false
	if nodeModule == nil {
		nodeModule = processModules[moduleName2]
	}
	if nodeModule == nil {
		log.Debugf("current process is not nodejs program, so won't add the nodejs protos. pid: %d", pid)
		return nil
	}
	if libsslModule == nil {
		if searchSymbol([]*profiling.Module{nodeModule}, func(a, b string) bool {
			return a == b
		}, "SSL_read") == nil || searchSymbol([]*profiling.Module{nodeModule}, func(a, b string) bool {
			return a == b
		}, "SSL_write") == nil {
			log.Warnf("could not found the SSL_read/SSL_write under the nodejs program, so ignore. pid: %d", pid)
			return nil
		}
		libsslModule = nodeModule
		needsReAttachSSL = true
	}
	v, err := getNodeVersion(nodeModule.Path)
	if err != nil {
		return fmt.Errorf("read nodejs version failure, pid: %d, error: %v", pid, err)
	}
	log.Debugf("read the nodejs version, pid: %d, version: %s", pid, v)
	config, err := findNodeTLSAddrConfig(v)
	if err != nil {
		return err
	}
	// setting the locations
	if err := loader.NodeTlsSymaddrMap.Put(uint32(pid), config); err != nil {
		return fmt.Errorf("setting the node TLS location failure, pid: %d, error: %v", pid, err)
	}
	// register node tls
	if err := registerNodeTLSProbes(v, loader, nodeModule, libsslModule); err != nil {
		return fmt.Errorf("register node TLS probes failure, pid: %d, error: %v", pid, err)
	}
	// attach the OpenSSL Probe if needs
	if needsReAttachSSL {
		return processOpenSSLModule(loader, libsslModule)
	}
	return nil
}

var nodeTLSAddrWithVersions = []struct {
	v    *version.Version
	conf *NodeTLSAddrInBPF
}{
	{version.Build(10, 19, 0), &NodeTLSAddrInBPF{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(12, 3, 1), &NodeTLSAddrInBPF{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(12, 16, 2), &NodeTLSAddrInBPF{0x0138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(13, 0, 0), &NodeTLSAddrInBPF{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(13, 2, 0), &NodeTLSAddrInBPF{0x0130, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(13, 10, 1), &NodeTLSAddrInBPF{0x0140, 0x08, 0x00, 0x60, 0xa0, 0x88, 0x30}},
	{version.Build(14, 5, 0), &NodeTLSAddrInBPF{0x138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(15, 0, 0), &NodeTLSAddrInBPF{0x78, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
}

var nodeTLSProbeWithVersions = []struct {
	v *version.Version
	f func(uprobe *bpf.UProbeExeFile, bpf *bpf.Loader, nodeModule *profiling.Module)
}{
	{version.Build(10, 19, 0), func(uprobe *bpf.UProbeExeFile, bpf *bpf.Loader, nodeModule *profiling.Module) {
		uprobe.AddLinkWithSymbols(searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node7TLSWrapC2E"),
			bpf.NodeTlsWrap, bpf.NodeTlsWrapRet)
		uprobe.AddLinkWithSymbols(searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node7TLSWrap7ClearInE"),
			bpf.NodeTlsWrap, bpf.NodeTlsWrapRet)
		uprobe.AddLinkWithSymbols(searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node7TLSWrap8ClearOutE"),
			bpf.NodeTlsWrap, bpf.NodeTlsWrapRet)
	}},
	{version.Build(15, 0, 0), func(uprobe *bpf.UProbeExeFile, bpf *bpf.Loader, nodeModule *profiling.Module) {
		uprobe.AddLinkWithSymbols(searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node6crypto7TLSWrapC2E"),
			bpf.NodeTlsWrap, bpf.NodeTlsWrapRet)
		uprobe.AddLinkWithSymbols(searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node6crypto7TLSWrap7ClearInE"),
			bpf.NodeTlsWrap, bpf.NodeTlsWrapRet)
		uprobe.AddLinkWithSymbols(searchSymbolNames([]*profiling.Module{nodeModule}, strings.HasPrefix, "_ZN4node6crypto7TLSWrap8ClearOutE"),
			bpf.NodeTlsWrap, bpf.NodeTlsWrapRet)
	}},
}

type NodeTLSAddrInBPF struct {
	TLSWrapStreamListenerOffset     uint32
	StreamListenerStreamOffset      uint32
	StreamBaseStreamResourceOffset  uint32
	LibuvStreamWrapStreamBaseOffset uint32
	LibuvStreamWrapStreamOffset     uint32
	UVStreamSIOWatcherOffset        uint32
	UVIOSFDOffset                   uint32
}

func findNodeTLSAddrConfig(v *version.Version) (*NodeTLSAddrInBPF, error) {
	var lastest *NodeTLSAddrInBPF
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

func registerNodeTLSProbes(v *version.Version, loader *bpf.Loader, nodeModule, libSSLModule *profiling.Module) error {
	var probeFunc func(uprobe *bpf.UProbeExeFile, bpf *bpf.Loader, nodeModule *profiling.Module)
	for _, c := range nodeTLSProbeWithVersions {
		if v.GreaterOrEquals(c.v) {
			probeFunc = c.f
		}
	}
	if probeFunc == nil {
		return fmt.Errorf("the version is not support: %v", v)
	}
	file := loader.OpenUProbeExeFile(nodeModule.Path)
	probeFunc(file, loader, nodeModule)

	// find the SSL_new, and register
	file = loader.OpenUProbeExeFile(libSSLModule.Path)
	file.AddLinkWithType("SSL_new", false, loader.NodeTlsRetSsl)
	return loader.HasError()
}

func getNodeVersion(p string) (*version.Version, error) {
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

func getGoVersion(elfFile *elf.File, versionSymbol *profiling.Symbol) (*version.Version, error) {
	buffer, err := elfFile.ReadSymbolData(".data", versionSymbol.Location, versionSymbol.Size)
	if err != nil {
		return nil, fmt.Errorf("reading go version struct info failure: %v", err)
	}
	var t = GoStringInC{}
	buf := bytes.NewReader(buffer)
	err = binary.Read(buf, binary.LittleEndian, &t)
	if err != nil {
		return nil, fmt.Errorf("read the go structure failure: %v", err)
	}
	buffer, err = elfFile.ReadSymbolData(".data", t.Ptr, t.Size)
	if err != nil {
		return nil, fmt.Errorf("read the go version failure: %v", err)
	}

	// parse versions
	submatch := goVersionRegex.FindStringSubmatch(string(buffer))
	if len(submatch) != 3 {
		return nil, fmt.Errorf("the go version is failure to identify, version: %s", string(buffer))
	}
	return version.Read(submatch[1], submatch[2], "")
}

func generateGOTLSSymbolOffsets(modules []*profiling.Module, _ int, elfFile *elf.File, v *version.Version) (*GoTLSSymbolAddresses, *elf.File, error) {
	reader, err := elfFile.NewDwarfReader(
		goTLSReadSymbol, goTLSWriteSymbol, goTLSGIDStatusSymbol,
		goTLSPollFDSymbol, goTLSConnSymbol, goTLSRuntimeG)
	if err != nil {
		return nil, nil, err
	}

	symbolAddresses := &GoTLSSymbolAddresses{}

	sym := searchSymbol(modules, func(a, b string) bool {
		return a == b
	}, "go.itab.*net.TCPConn,net.Conn")
	if sym == nil {
		return nil, nil, fmt.Errorf("could found the tcp connection symbol")
	}
	symbolAddresses.TCPConnOffset = sym.Location

	readFunction := reader.GetFunction(goTLSReadSymbol)
	if readFunction == nil {
		log.Warnf("could not found the go tls read symbol: %s", goTLSReadSymbol)
		return nil, nil, nil
	}
	writeFunction := reader.GetFunction(goTLSWriteSymbol)
	if writeFunction == nil {
		log.Warnf("could not found the go tls write symbol: %s", goTLSWriteSymbol)
		return nil, nil, nil
	}
	gidStatusFunction := reader.GetFunction(goTLSGIDStatusSymbol)
	if gidStatusFunction == nil {
		log.Warnf("could not found the goid status change symbol: %s", goTLSGIDStatusSymbol)
		return nil, nil, nil
	}

	var retValArg0, retValArg1 = "~r1", "~r2"
	if v.Minor >= 18 {
		retValArg0, retValArg1 = "~r0", "~r1"
	}

	// build the symbols
	var assignError error
	// offset
	assignError = assignGoTLSStructureOffset(assignError, reader, goTLSPollFDSymbol, "Sysfd", &symbolAddresses.FDSysFDOffset)
	assignError = assignGoTLSStructureOffset(assignError, reader, goTLSConnSymbol, "conn", &symbolAddresses.TLSConnOffset)
	assignError = assignGoTLSStructureOffset(assignError, reader, goTLSRuntimeG, "goid", &symbolAddresses.GIDOffset)

	// gid status change
	assignError = assignGoTLSArgsLocation(assignError, gidStatusFunction, "gp", &symbolAddresses.CasgStatusGPLoc)
	assignError = assignGoTLSArgsLocation(assignError, gidStatusFunction, "newval", &symbolAddresses.CasgStatusNEWValLoc)

	// write
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, "c", &symbolAddresses.WriteConnectionLoc)
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, "b", &symbolAddresses.WriteBufferLoc)
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, retValArg0, &symbolAddresses.WriteRet0Loc)
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, retValArg1, &symbolAddresses.WriteRet1Loc)
	// read
	assignError = assignGoTLSArgsLocation(assignError, readFunction, "c", &symbolAddresses.ReadConnectionLoc)
	assignError = assignGoTLSArgsLocation(assignError, readFunction, "b", &symbolAddresses.ReadBufferLoc)
	assignError = assignGoTLSArgsLocation(assignError, readFunction, retValArg0, &symbolAddresses.ReadRet0Loc)
	assignError = assignGoTLSArgsLocation(assignError, readFunction, retValArg1, &symbolAddresses.ReadRet1Loc)

	return symbolAddresses, elfFile, assignError
}

func assignGoTLSStructureOffset(err error, reader *elf.DwarfReader, structName, fieldName string, dest *uint64) error {
	if err != nil {
		return err
	}
	structure := reader.GetStructure(structName)
	if structure == nil {
		return fmt.Errorf("the structure is not found, name: %s", structName)
	}
	field := structure.GetField(fieldName)
	if field == nil {
		return fmt.Errorf("the field is not found in structure, structure name: %s, field name: %s", structName, fieldName)
	}
	*dest = uint64(field.Offset)
	return nil
}

func assignGoTLSArgsLocation(err error, function *elf.FunctionInfo, argName string, dest *SymbolLocation) error {
	if err != nil {
		return err
	}
	var kSPOffset uint32 = 8
	args := function.Args(argName)
	if args == nil {
		return fmt.Errorf("the args is not found, function: %s, args name: %s", function.Name(), argName)
	}
	if args.Location.Type == elf.ArgLocationTypeStack {
		dest.Type = base.GoTLSArgsLocationTypeStack
		dest.Offset = uint32(args.Location.Offset) + kSPOffset
	} else if args.Location.Type == elf.ArgLocationTypeRegister {
		dest.Type = base.GoTLSArgsLocationTypeRegister
		dest.Offset = uint32(args.Location.Offset)
	} else {
		return fmt.Errorf("the location type is not support, function: %s, args name: %s, type: %d",
			function.Name(), argName, args.Location.Type)
	}
	return nil
}

func findProcessModules(modules []*profiling.Module, moduleNames ...string) (map[string]*profiling.Module, error) {
	result := make(map[string]*profiling.Module)
	for _, mod := range modules {
		for _, modName := range moduleNames {
			if strings.Contains(mod.Name, modName) {
				if !path.Exists(mod.Path) {
					return nil, fmt.Errorf("the module path not exists, path: %s", mod.Path)
				}
				result[modName] = mod
			}
		}
	}
	return result, nil
}

func buildSSLSymAddrConfig(libcryptoPath string) (*OpenSSLFdSymAddrConfigInBPF, error) {
	// using "strings" command to query the symbol in the libcrypto library
	result, err := exec.Command("strings", libcryptoPath).Output()
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Split(string(result), "\n") {
		submatch := openSSLVersionRegex.FindStringSubmatch(p)
		if len(submatch) != 4 {
			continue
		}
		major := submatch[1]
		mijor := submatch[2]
		fix := submatch[3]

		log.Debugf("found the libcrypto.so version: %s.%s.%s", major, mijor, fix)
		conf := &OpenSSLFdSymAddrConfigInBPF{}

		// must be number, already validate in the regex
		mijorVal, _ := strconv.Atoi(mijor)
		fixVal, _ := strconv.Atoi(fix)

		// max support version is 1.1.1
		if mijorVal > 1 || fixVal > 1 {
			return nil, fmt.Errorf("the fix version of the libcrypto is not support: %s.%s.%s", major, mijor, fix)
		}

		// bio offset
		// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093-L1111
		// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/ssl/ssl_local.h#L1068-L1083
		conf.BIOReadOffset = 16
		conf.BIOWriteOffset = 24
		// fd offset
		if (mijorVal == 0) || (mijorVal == 1 && fixVal == 0) {
			// 1.0.x || 1.1.0
			// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/crypto/bio/bio.h#L297-L306
			conf.FDOffset = 40
		} else {
			// 1.1.1
			// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h#L115-L125
			conf.FDOffset = 48
		}
		log.Debugf("the lobcrypto.so library symbol verson config, version: %s.%s.%s, bio offset: %d",
			major, mijor, fix, conf.FDOffset)
		return conf, nil
	}
	return nil, fmt.Errorf("could not fount the version of the libcrypto.so")
}

type stringVerify func(a, b string) bool

func searchSymbolNames(modules []*profiling.Module, verify stringVerify, values ...string) []string {
	list := searchSymbolList(modules, verify, values...)
	if len(list) > 0 {
		result := make([]string, 0)
		for _, i := range list {
			result = append(result, i.Name)
		}
		return result
	}
	return nil
}

func searchSymbol(modules []*profiling.Module, verify stringVerify, values ...string) *profiling.Symbol {
	list := searchSymbolList(modules, verify, values...)
	if len(list) > 0 {
		return list[0]
	}
	return nil
}

func searchSymbolList(modules []*profiling.Module, verify stringVerify, values ...string) []*profiling.Symbol {
	var result []*profiling.Symbol
	for _, mod := range modules {
		for _, s := range mod.Symbols {
			for _, validator := range values {
				if verify(s.Name, validator) {
					result = append(result, s)
				}
			}
		}
	}
	return result
}
