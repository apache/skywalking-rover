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

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/arch/x86/x86asm"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools"
	"github.com/apache/skywalking-rover/pkg/tools/elf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/hashicorp/go-multierror"
)

var log = logger.GetLogger("profiling", "task", "network", "bpf")

const defaultSymbolPrefix = "sys_"

type LinkFunc func(symbol string, prog *ebpf.Program, opts *link.KprobeOptions) (link.Link, error)
type RingBufferReader func(data interface{})

var syscallPrefix string

func init() {
	stat, err := tools.KernelFileProfilingStat()
	if err != nil {
		syscallPrefix = defaultSymbolPrefix
		return
	}
	var possiblePrefixes = []string{
		defaultSymbolPrefix,
		"__x64_sys_",
		"__x32_compat_sys_",
		"__ia32_compat_sys_",
		"__arm64_sys_",
		"__s390x_sys_",
		"__s390_sys_",
	}

	found := false
	for _, p := range possiblePrefixes {
		if stat.FindSymbolAddress(fmt.Sprintf("%sbpf", p)) != 0 {
			found = true
			syscallPrefix = p
			break
		}
	}
	if !found {
		syscallPrefix = "sys_"
	}
}

type Linker struct {
	closers   []io.Closer
	errors    error
	closeOnce sync.Once

	linkedUProbes map[string]bool
}

func NewLinker() *Linker {
	return &Linker{
		linkedUProbes: make(map[string]bool),
	}
}

type UProbeExeFile struct {
	addr     string
	found    bool
	linker   *Linker
	realFile *link.Executable
}

func (m *Linker) AddLink(linkF LinkFunc, symbolWithPrograms map[string]*ebpf.Program) {
	var lk link.Link
	var err error
	var realSym string
	for symbol, p := range symbolWithPrograms {
		lk, err = linkF(symbol, p, nil)
		if err == nil {
			realSym = symbol
			break
		}
	}
	if err != nil {
		symbolNames := make([]string, 0)
		for s := range symbolWithPrograms {
			symbolNames = append(symbolNames, s)
		}
		m.errors = multierror.Append(m.errors, fmt.Errorf("open %s error: %v", symbolNames, err))
	} else {
		log.Debugf("attach to the kprobe: %s", realSym)
		m.closers = append(m.closers, lk)
	}
}

func (m *Linker) AddSysCall(call string, enter, exit *ebpf.Program) {
	m.AddSysCallWithKProbe(call, link.Kprobe, enter)
	m.AddSysCallWithKProbe(call, link.Kretprobe, exit)
}

func (m *Linker) AddSysCallWithKProbe(call string, linkK LinkFunc, p *ebpf.Program) {
	kprobe, err := linkK(syscallPrefix+call, p, nil)

	if err != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("could not attach syscall with %s: %v", "sys_"+call, err))
	} else {
		log.Debugf("attach to the syscall: %s", syscallPrefix+call)
		m.closers = append(m.closers, kprobe)
	}
}

func (m *Linker) AddTracePoint(sys, name string, p *ebpf.Program) {
	l, e := link.Tracepoint(sys, name, p, nil)
	if e != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("open %s error: %v", name, e))
	} else {
		m.closers = append(m.closers, l)
	}
}

func (m *Linker) ReadEventAsync(emap *ebpf.Map, reader RingBufferReader, dataSupplier func() interface{}) {
	m.ReadEventAsyncWithBufferSize(emap, reader, os.Getpagesize(), dataSupplier)
}

func (m *Linker) ReadEventAsyncWithBufferSize(emap *ebpf.Map, reader RingBufferReader, perCPUBuffer int, dataSupplier func() interface{}) {
	rd, err := perf.NewReader(emap, perCPUBuffer)
	if err != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("open ring buffer error: %v", err))
		return
	}
	m.closers = append(m.closers, rd)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Warnf("read from %s ringbuffer error: %v", emap.String(), err)
				continue
			}

			if record.LostSamples != 0 {
				log.Warnf("perf event queue(%s) full, dropped %d samples", emap.String(), record.LostSamples)
				continue
			}

			data := dataSupplier()
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, data); err != nil {
				log.Warnf("parsing data from %s, raw size: %d, ringbuffer error: %v", emap.String(), len(record.RawSample), err)
				continue
			}

			reader(data)
		}
	}()
}

func (m *Linker) OpenUProbeExeFile(path string) *UProbeExeFile {
	executable, err := link.OpenExecutable(path)
	if err != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("cannot found the execute file: %s, error: %v", path, err))
		return &UProbeExeFile{
			found: false,
		}
	}

	return &UProbeExeFile{
		found:    true,
		addr:     path,
		linker:   m,
		realFile: executable,
	}
}

func (u *UProbeExeFile) AddLink(symbol string, enter, exit *ebpf.Program) {
	u.AddLinkWithType(symbol, true, enter)
	u.AddLinkWithType(symbol, false, exit)
}

func (u *UProbeExeFile) AddLinkWithSymbols(symbol []string, enter, exit *ebpf.Program) {
	for _, s := range symbol {
		u.AddLinkWithType(s, true, enter)
		u.AddLinkWithType(s, false, exit)
	}
}

func (u *UProbeExeFile) AddGoLink(symbol string, enter, exit *ebpf.Program, elfFile *elf.File) {
	u.AddGoLinkWithType(symbol, true, enter, elfFile)
	u.AddGoLinkWithType(symbol, false, exit, elfFile)
}

func (u *UProbeExeFile) AddLinkWithType(symbol string, enter bool, p *ebpf.Program) {
	if !u.found {
		return
	}
	lk, err := u.addLinkWithType0(symbol, enter, p, 0)
	if err != nil {
		u.linker.errors = multierror.Append(u.linker.errors, fmt.Errorf("file: %s, symbol: %s, type: %s, error: %v",
			u.addr, symbol, u.parseEnterOrExitString(enter), err))
	} else if lk != nil {
		log.Debugf("attach to the uprobe, file: %s, symbol: %s, type: %s", u.addr, symbol, u.parseEnterOrExitString(enter))
		u.linker.closers = append(u.linker.closers, lk)
	}
}

func (u *UProbeExeFile) addLinkWithType0(symbol string, enter bool, p *ebpf.Program, customizeAddress uint64) (link.Link, error) {
	// check already linked
	uprobeIdentity := fmt.Sprintf("%s_%s_%t_%d", u.addr, symbol, enter, customizeAddress)
	if u.linker.linkedUProbes[uprobeIdentity] {
		log.Debugf("the uprobe already attached, so ignored. file: %s, symbol: %s, type: %s", u.addr, symbol,
			u.parseEnterOrExitString(enter))
		return nil, nil
	}
	u.linker.linkedUProbes[uprobeIdentity] = true

	var fun func(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error)
	if enter {
		fun = u.realFile.Uprobe
	} else {
		fun = u.realFile.Uretprobe
	}

	var opts *link.UprobeOptions
	if customizeAddress > 0 {
		opts = &link.UprobeOptions{
			Address: customizeAddress,
		}
	}
	return fun(symbol, p, opts)
}

func (u *UProbeExeFile) AddGoLinkWithType(symbol string, enter bool, p *ebpf.Program, elfFile *elf.File) {
	// if is entered type of probe, then same with the other programs
	if enter {
		u.AddLinkWithType(symbol, enter, p)
		return
	}

	links, err := u.addGoExitLink0(symbol, p, elfFile)
	if err != nil {
		u.linker.errors = multierror.Append(u.linker.errors, fmt.Errorf("file: %s, symbol: %s, type: %s, error: %v",
			u.addr, symbol, u.parseEnterOrExitString(enter), err))
	} else {
		log.Debugf("attach to the go uprobe, file: %s, symbol: %s, type: %s", u.addr, symbol, u.parseEnterOrExitString(enter))
		for _, l := range links {
			u.linker.closers = append(u.linker.closers, l)
		}
	}
}

func (u *UProbeExeFile) addGoExitLink0(symbol string, p *ebpf.Program, elfFile *elf.File) ([]link.Link, error) {
	// find the symbol
	targetSymbol := elfFile.FindSymbol(symbol)
	if targetSymbol == nil {
		return nil, fmt.Errorf("could not found the symbol")
	}

	// find the symbol real data buffer
	buffer, err := elfFile.ReadSymbolData(".text", targetSymbol.Location, targetSymbol.Size)
	if err != nil {
		return nil, fmt.Errorf("reading symbol data error: %v", err)
	}

	// find the base addresses
	targetBaseAddress := elfFile.FindBaseAddressForAttach(targetSymbol.Location)
	if targetBaseAddress == 0 {
		return nil, fmt.Errorf("could not found the symbol base addresses")
	}

	// based on the base addresses and symbol data buffer
	// calculate all RET addresses
	// https://github.com/iovisor/bcc/issues/1320#issuecomment-407927542
	var addresses []uint64
	for i := 0; i < int(targetSymbol.Size); {
		inst, err := x86asm.Decode(buffer[i:], 64)
		if err != nil {
			return nil, fmt.Errorf("error decode the function data: %v", err)
		}

		if inst.Op == x86asm.RET {
			addresses = append(addresses, targetBaseAddress+uint64(i))
		}

		i += inst.Len
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("could not found any return addresses")
	}
	log.Debugf("found reuturn addresses of the symbol, symbol: %s, size: %d", symbol, len(addresses))

	var result []link.Link
	for _, address := range addresses {
		l, err := u.addLinkWithType0(symbol, true, p, address)
		if err != nil {
			return nil, err
		}
		result = append(result, l)
		log.Debugf("attach to the return probe of the go program, symbol: %s, addresses: %d", symbol, address)
	}
	return result, nil
}

func (u *UProbeExeFile) parseEnterOrExitString(enter bool) string {
	if enter {
		return "enter"
	}
	return "exit"
}

func (m *Linker) HasError() error {
	return m.errors
}

func (m *Linker) Close() error {
	var err error
	m.closeOnce.Do(func() {
		for _, l := range m.closers {
			if e := l.Close(); e != nil {
				err = multierror.Append(err, e)
			}
		}
	})
	return err
}
