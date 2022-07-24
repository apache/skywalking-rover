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
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/apache/skywalking-rover/pkg/tools"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/hashicorp/go-multierror"
)

const defaultSymbolPrefix = "sys_"

type LinkFunc func(symbol string, prog *ebpf.Program) (link.Link, error)
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
}

func (m *Linker) AddLink(linkF LinkFunc, p *ebpf.Program, trySymbolNames ...string) {
	var lk link.Link
	var err error
	for _, n := range trySymbolNames {
		lk, err = linkF(n, p)
		if err == nil {
			break
		}
	}
	if err != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("open %s error: %v", trySymbolNames, err))
	} else {
		m.closers = append(m.closers, lk)
	}
}

func (m *Linker) AddSysCall(call string, enter, exit *ebpf.Program) {
	m.AddSysCallWithKProbe(call, link.Kprobe, enter)
	m.AddSysCallWithKProbe(call, link.Kretprobe, exit)
}

func (m *Linker) AddSysCallWithKProbe(call string, linkK LinkFunc, p *ebpf.Program) {
	kprobe, err := linkK(syscallPrefix+call, p)

	if err != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("could not attach syscall with %s: %v", "sys_"+call, err))
	} else {
		log.Debugf("attach to the syscall: %s", syscallPrefix+call)
		m.closers = append(m.closers, kprobe)
	}
}

func (m *Linker) AddTracePoint(sys, name string, p *ebpf.Program) {
	l, e := link.Tracepoint(sys, name, p)
	if e != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("open %s error: %v", name, e))
	} else {
		m.closers = append(m.closers, l)
	}
}

func (m *Linker) ReadEventAsync(emap *ebpf.Map, reader RingBufferReader, dataSupplier func() interface{}) {
	rd, err := perf.NewReader(emap, os.Getpagesize())
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
