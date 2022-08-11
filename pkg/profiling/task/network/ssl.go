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

	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/elf"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/path"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
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
)

type OpenSSLFdSymAddrConfigInBPF struct {
	BIOReadOffset  uint32
	BIOWriteOffset uint32
	FDOffset       uint32
}

func addSSLProcess(pid int, bpf *bpfObjects, linker *Linker) error {
	modules, err := tools.ProcessModules(int32(pid))
	if err != nil {
		return fmt.Errorf("read process modules error: %d, error: %v", pid, err)
	}

	// openssl process
	if err1 := processOpenSSLProcess(pid, bpf, linker, modules); err1 != nil {
		return err1
	}

	// envoy with boring ssl
	if err1 := processEnvoyProcess(pid, bpf, linker, modules); err1 != nil {
		return err1
	}

	// GoTLS
	if err1 := processGoProcess(pid, bpf, linker, modules); err1 != nil {
		return err1
	}

	return nil
}

func processOpenSSLProcess(pid int, bpf *bpfObjects, linker *Linker, modules []*profiling.Module) error {
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
	if err := bpf.OpensslFdSymaddrFinder.Put(uint32(pid), conf); err != nil {
		return err
	}

	// attach the linker
	libSSLLinker := linker.OpenUProbeExeFile(libsslPath)
	libSSLLinker.AddLink("SSL_write", bpf.OpensslWrite, bpf.OpensslWriteRet)
	libSSLLinker.AddLink("SSL_read", bpf.OpensslRead, bpf.OpensslReadRet)
	return linker.HasError()
}

func processEnvoyProcess(_ int, bpf *bpfObjects, linker *Linker, modules []*profiling.Module) error {
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
	libSSLLinker := linker.OpenUProbeExeFile(envoyModule.Path)
	libSSLLinker.AddLink("SSL_write", bpf.OpensslWrite, bpf.OpensslWriteRet)
	libSSLLinker.AddLink("SSL_read", bpf.OpensslRead, bpf.OpensslReadRet)
	return linker.HasError()
}

type SymbolLocation struct {
	Type   GoTLSArgsLocationType
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

func processGoProcess(pid int, bpf *bpfObjects, linker *Linker, modules []*profiling.Module) error {
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

	_, minor, err := getGoVersion(elfFile, buildVersionSymbol)
	if err != nil {
		return err
	}

	// generate symbol offsets
	symbolConfig, elfFile, err := generateGOTLSSymbolOffsets(modules, pid, elfFile, minor)
	if err != nil {
		return err
	}
	if symbolConfig == nil || elfFile == nil {
		return nil
	}

	// setting the locations
	if err := bpf.GoTlsArgsSymaddrMap.Put(uint32(pid), symbolConfig); err != nil {
		return fmt.Errorf("setting the Go TLS argument location failure, pid: %d, error: %v", pid, err)
	}

	// uprobes
	exeFile := linker.OpenUProbeExeFile(pidExeFile)
	exeFile.AddLinkWithType("runtime.casgstatus", true, bpf.GoCasgstatus)
	exeFile.AddGoLink(goTLSWriteSymbol, bpf.GoTlsWrite, bpf.GoTlsWriteRet, elfFile)
	exeFile.AddGoLink(goTLSReadSymbol, bpf.GoTlsRead, bpf.GoTlsReadRet, elfFile)

	return linker.HasError()
}

func getGoVersion(elfFile *elf.File, versionSymbol *profiling.Symbol) (major, minor int, err error) {
	buffer, err := elfFile.ReadSymbolData(".data", versionSymbol.Location, versionSymbol.Size)
	if err != nil {
		return 0, 0, fmt.Errorf("reading go version struct info failure: %v", err)
	}
	var t = GoStringInC{}
	buf := bytes.NewReader(buffer)
	err = binary.Read(buf, binary.LittleEndian, &t)
	if err != nil {
		return 0, 0, fmt.Errorf("read the go structure failure: %v", err)
	}
	buffer, err = elfFile.ReadSymbolData(".data", t.Ptr, t.Size)
	if err != nil {
		return 0, 0, fmt.Errorf("read the go version failure: %v", err)
	}

	// parse versions
	submatch := goVersionRegex.FindStringSubmatch(string(buffer))
	if len(submatch) != 3 {
		return 0, 0, fmt.Errorf("the go version is failure to identify, version: %s", string(buffer))
	}
	major, err = strconv.Atoi(submatch[1])
	if err != nil {
		return 0, 0, fmt.Errorf("the marjor version is a number, version: %s", string(buffer))
	}
	minor, err = strconv.Atoi(submatch[2])
	if err != nil {
		return 0, 0, fmt.Errorf("the minor version is a number, version: %s", string(buffer))
	}

	return major, minor, nil
}

func generateGOTLSSymbolOffsets(modules []*profiling.Module, _ int, elfFile *elf.File, minorVersion int) (*GoTLSSymbolAddresses, *elf.File, error) {
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
	if minorVersion >= 18 {
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
		dest.Type = GoTLSArgsLocationTypeStack
		dest.Offset = uint32(args.Location.Offset) + kSPOffset
	} else if args.Location.Type == elf.ArgLocationTypeRegister {
		dest.Type = GoTLSArgsLocationTypeRegister
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

func searchSymbol(modules []*profiling.Module, verify stringVerify, values ...string) *profiling.Symbol {
	for _, mod := range modules {
		for _, s := range mod.Symbols {
			for _, validator := range values {
				if verify(s.Name, validator) {
					return s
				}
			}
		}
	}
	return nil
}
