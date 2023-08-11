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
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/elf"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
	"github.com/apache/skywalking-rover/pkg/tools/version"

	"github.com/cilium/ebpf"
)

var (
	goVersionRegex = regexp.MustCompile(`^go(?P<Major>\d)\.(?P<Minor>\d+)`)

	goTLSWriteSymbol     = "crypto/tls.(*Conn).Write"
	goTLSReadSymbol      = "crypto/tls.(*Conn).Read"
	goTLSGIDStatusSymbol = "runtime.casgstatus"
	goTLSPollFDSymbol    = "internal/poll.FD"
	goTLSConnSymbol      = "crypto/tls.Conn"
	goTLSRuntimeG        = "runtime.g"
)

type GoTLSArgsLocationType uint32

const (
	GoTLSArgsLocationTypeStack    GoTLSArgsLocationType = 1
	GoTLSArgsLocationTypeRegister GoTLSArgsLocationType = 2
)

type GoSymbolLocation struct {
	Type   GoTLSArgsLocationType
	Offset uint32
}

type GoTLSSymbolAddress struct {
	// net.Conn addresses
	FDSysFDOffset  uint64
	TLSConnOffset  uint64
	GIDOffset      uint64
	TCPConnOffset  uint64
	IsClientOffset uint64

	// write function relate locations
	WriteConnectionLoc GoSymbolLocation
	WriteBufferLoc     GoSymbolLocation
	WriteRet0Loc       GoSymbolLocation
	WriteRet1Loc       GoSymbolLocation

	// write function relate locations
	ReadConnectionLoc GoSymbolLocation
	ReadBufferLoc     GoSymbolLocation
	ReadRet0Loc       GoSymbolLocation
	ReadRet1Loc       GoSymbolLocation
}

func (r *Register) GoTLS(symbolAddrMap *ebpf.Map, write, writeRet, read, readRet *ebpf.Program) {
	r.addHandler("goTLS", func() (bool, error) {
		buildVersionSymbol := r.searchSymbolInModules(r.modules, func(a, b string) bool {
			return a == b
		}, "runtime.buildVersion")
		if buildVersionSymbol == nil {
			return false, nil
		}
		pidExeFile := host.GetFileInHost(fmt.Sprintf("/proc/%d/exe", r.pid))
		elfFile, err := elf.NewFile(pidExeFile)
		if err != nil {
			return false, fmt.Errorf("read executable file error: %v", err)
		}
		defer elfFile.Close()

		v, err := r.getGoVersion(elfFile, buildVersionSymbol)
		if err != nil {
			return false, err
		}

		offsets, err := r.generateGOTLSSymbolOffsets(r, elfFile, v)
		if err != nil {
			return false, err
		}
		if offsets == nil {
			return false, nil
		}

		// setting the locations
		if err := symbolAddrMap.Put(uint32(r.pid), offsets); err != nil {
			return false, fmt.Errorf("setting the Go TLS argument location failure, pid: %d, error: %v", r.pid, err)
		}

		exeFile := r.linker.OpenUProbeExeFile(pidExeFile)
		exeFile.AddGoLink(goTLSWriteSymbol, write, writeRet, elfFile)
		exeFile.AddGoLink(goTLSReadSymbol, read, readRet, elfFile)
		if e := r.linker.HasError(); e != nil {
			return false, e
		}

		return true, nil
	})
}

func (r *Register) getGoVersion(elfFile *elf.File, versionSymbol *profiling.Symbol) (ver *version.Version, err error) {
	defer func() {
		// if cannot getting version from symbol, then trying to get from strings command
		if ver == nil {
			ver, err = r.getGoVersionByStrings(elfFile.Path)
		}
	}()
	buffer, err := elfFile.ReadSymbolData(".data", versionSymbol.Location, versionSymbol.Size)
	if err != nil {
		return nil, fmt.Errorf("reading go version struct info failure: %v", err)
	}
	var t = goStringInC{}
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
	if ver, ok, err := r.gettingGoVersionFromString(string(buffer)); ok {
		return ver, err
	}
	return nil, fmt.Errorf("the go version is failure to identify, version: %s", string(buffer))
}

func (r *Register) getGoVersionByStrings(p string) (*version.Version, error) {
	result, err := exec.Command("strings", p).Output()
	if err != nil {
		return nil, err
	}
	for _, d := range strings.Split(string(result), "\n") {
		if v, ok, err := r.gettingGoVersionFromString(strings.TrimSpace(d)); ok {
			return v, err
		}
	}

	return nil, fmt.Errorf("go version is not found from strings")
}

func (r *Register) gettingGoVersionFromString(s string) (v *version.Version, success bool, err error) {
	submatch := goVersionRegex.FindStringSubmatch(s)
	if len(submatch) != 3 {
		return nil, false, nil
	}
	v, err = version.Read(submatch[1], submatch[2], "")
	return v, true, err
}

type goStringInC struct {
	Ptr  uint64
	Size uint64
}

func (r *Register) generateGOTLSSymbolOffsets(register *Register, elfFile *elf.File, v *version.Version) (*GoTLSSymbolAddress, error) {
	reader, err := elfFile.NewDwarfReader(
		goTLSReadSymbol, goTLSWriteSymbol, goTLSGIDStatusSymbol,
		goTLSPollFDSymbol, goTLSConnSymbol, goTLSRuntimeG)
	if err != nil {
		return nil, err
	}

	symbolAddresses := &GoTLSSymbolAddress{}

	sym := register.SearchSymbol(func(a, b string) bool {
		return a == b
	}, "go.itab.*net.TCPConn,net.Conn")
	if sym == nil {
		log.Warnf("could not found the tcp connection symbol: go.itab.*net.TCPConn,net.Conn")
		return nil, nil
	}
	symbolAddresses.TCPConnOffset = sym.Location

	readFunction := reader.GetFunction(goTLSReadSymbol)
	if readFunction == nil {
		log.Warnf("could not found the go tls read symbol: %s", goTLSReadSymbol)
		return nil, nil
	}
	writeFunction := reader.GetFunction(goTLSWriteSymbol)
	if writeFunction == nil {
		log.Warnf("could not found the go tls write symbol: %s", goTLSWriteSymbol)
		return nil, nil
	}
	gidStatusFunction := reader.GetFunction(goTLSGIDStatusSymbol)
	if gidStatusFunction == nil {
		log.Warnf("could not found the goid status change symbol: %s", goTLSGIDStatusSymbol)
		return nil, nil
	}

	var retValArg0, retValArg1 = "~r1", "~r2"
	if v.Minor >= 18 {
		retValArg0, retValArg1 = "~r0", "~r1"
	}

	// build the symbols
	var assignError error
	// offset
	assignError = r.assignGoTLSStructureOffset(assignError, reader, goTLSPollFDSymbol, "Sysfd", &symbolAddresses.FDSysFDOffset)
	assignError = r.assignGoTLSStructureOffset(assignError, reader, goTLSConnSymbol, "conn", &symbolAddresses.TLSConnOffset)
	assignError = r.assignGoTLSStructureOffset(assignError, reader, goTLSRuntimeG, "goid", &symbolAddresses.GIDOffset)
	assignError = r.assignGoTLSStructureOffset(assignError, reader, goTLSConnSymbol, "isClient", &symbolAddresses.IsClientOffset)

	// write
	assignError = r.assignGoTLSArgsLocation(assignError, writeFunction, "c", &symbolAddresses.WriteConnectionLoc)
	assignError = r.assignGoTLSArgsLocation(assignError, writeFunction, "b", &symbolAddresses.WriteBufferLoc)
	assignError = r.assignGoTLSArgsLocation(assignError, writeFunction, retValArg0, &symbolAddresses.WriteRet0Loc)
	assignError = r.assignGoTLSArgsLocation(assignError, writeFunction, retValArg1, &symbolAddresses.WriteRet1Loc)
	// read
	assignError = r.assignGoTLSArgsLocation(assignError, readFunction, "c", &symbolAddresses.ReadConnectionLoc)
	assignError = r.assignGoTLSArgsLocation(assignError, readFunction, "b", &symbolAddresses.ReadBufferLoc)
	assignError = r.assignGoTLSArgsLocation(assignError, readFunction, retValArg0, &symbolAddresses.ReadRet0Loc)
	assignError = r.assignGoTLSArgsLocation(assignError, readFunction, retValArg1, &symbolAddresses.ReadRet1Loc)

	return symbolAddresses, assignError
}

func (r *Register) assignGoTLSStructureOffset(err error, reader *elf.DwarfReader, structName, fieldName string, dest *uint64) error {
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

func (r *Register) assignGoTLSArgsLocation(err error, function *elf.FunctionInfo, argName string, dest *GoSymbolLocation) error {
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
