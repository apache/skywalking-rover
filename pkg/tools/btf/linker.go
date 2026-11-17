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

package btf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"github.com/apache/skywalking-rover/pkg/tools/elf"
	"github.com/apache/skywalking-rover/pkg/tools/process"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/hashicorp/go-multierror"
)

const defaultSymbolPrefix = "sys_"

type LinkFunc func(symbol string, prog *ebpf.Program, opts *link.KprobeOptions) (link.Link, error)
type RingBufferReader func(data interface{})

var syscallPrefix string

func init() {
	stat, err := process.KernelFileProfilingStat()
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
		syscallPrefix = defaultSymbolPrefix
	}
}

type Linker struct {
	closers   []io.Closer
	errors    error
	closeOnce sync.Once

	linkedUProbes map[string]bool
	linkMutex     sync.Mutex

	// queueReader is how the rings of the event queues are read, see SetEventQueueReaderOptions
	queueReader EventQueueReaderOptions
}

// EventQueueReaderOptions control how an EventQueue reads its perf rings. The zero value reads every
// event as it arrives and hands it to its partition on its own, which is what the other readers do.
type EventQueueReaderOptions struct {
	// WakeupEvents wakes the reader once a per CPU ring holds this many events instead of for every event;
	// the rings are flushed every FlushPeriod, so no event waits longer than that. 0 wakes for every event.
	WakeupEvents int
	// FlushPeriod is how often the rings are flushed when WakeupEvents is set, and the longest a partial
	// batch waits when the ring never runs empty; defaultReaderFlushPeriod when 0
	FlushPeriod time.Duration
	// BatchSize hands the events to the partitions in batches of up to this many, collected until the ring
	// is drained or FlushPeriod has passed, instead of one by one. 0 or 1 hands them one by one.
	BatchSize int
}

const defaultReaderFlushPeriod = time.Second

// SetEventQueueReaderOptions sets how the event queues started from now on read their rings
func (m *Linker) SetEventQueueReaderOptions(o EventQueueReaderOptions) {
	m.queueReader = o
}

// readerOptions is how one perf ring is read
type readerOptions struct {
	wakeupEvents int
	flushPeriod  time.Duration
	// drained is called whenever every event the ring held has been handed over
	drained func()
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
	if e := m.AddLinkOrError(linkF, symbolWithPrograms); e != nil {
		m.AppendError(e)
	}
}

func (m *Linker) AddLinkOrError(linkF LinkFunc, symbolWithPrograms map[string]*ebpf.Program) error {
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
		return fmt.Errorf("open %s error: %v", symbolNames, err)
	}
	log.Debugf("attach to the kprobe: %s", realSym)
	m.addCloser(lk)
	return nil
}

func (m *Linker) AddSysCall(call string, enter, exit *ebpf.Program) {
	m.AddSysCallWithKProbe(call, link.Kprobe, enter)
	m.AddSysCallWithKProbe(call, link.Kretprobe, exit)
}

func (m *Linker) AddSysCallWithKProbe(call string, linkK LinkFunc, p *ebpf.Program) {
	if p == nil {
		return
	}
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	kprobe, err := linkK(syscallPrefix+call, p, nil)

	if err != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("could not attach syscall with %s: %v", defaultSymbolPrefix+call, err))
	} else {
		log.Debugf("attach to the syscall: %s", syscallPrefix+call)
		m.closers = append(m.closers, kprobe)
	}
}

func (m *Linker) AddTracePoint(sys, name string, p *ebpf.Program) {
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	l, e := link.Tracepoint(sys, name, p, nil)
	if e != nil {
		m.errors = multierror.Append(m.errors, fmt.Errorf("open %s error: %v", name, e))
	} else {
		log.Debugf("attach to the tracepoint: sys: %s, name: %s", sys, name)
		m.closers = append(m.closers, l)
	}
}

// AddTracePointOrError is AddTracePoint for a tracepoint that may not attach: the error is returned, not kept
func (m *Linker) AddTracePointOrError(sys, name string, p *ebpf.Program) error {
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	l, err := link.Tracepoint(sys, name, p, nil)
	if err != nil {
		return fmt.Errorf("open %s/%s error: %v", sys, name, err)
	}
	m.closers = append(m.closers, l)
	return nil
}

// AddTracingOrError attaches a fentry/fexit program at the function it was loaded for (a BPF trampoline)
func (m *Linker) AddTracingOrError(p *ebpf.Program) error {
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	l, err := link.AttachTracing(link.TracingOptions{Program: p})
	if err != nil {
		return err
	}
	m.closers = append(m.closers, l)
	return nil
}

// AddRawTracePointOrError attaches a raw tracepoint program
func (m *Linker) AddRawTracePointOrError(name string, p *ebpf.Program) error {
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: p})
	if err != nil {
		return err
	}
	m.closers = append(m.closers, l)
	return nil
}

// AppendError keeps an error for HasError
func (m *Linker) AppendError(err error) {
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	m.errors = multierror.Append(m.errors, err)
}

func (m *Linker) ReadEventAsync(emap *ebpf.Map, bufReader RingBufferReader, dataSupplier func() interface{}) {
	m.ReadEventAsyncWithBufferSize(emap, bufReader, os.Getpagesize(), 1, dataSupplier)
}

// ReadEventAsyncWithBufferSize reads the ring with one goroutine. parallels is deprecated: the library
// serializes the reads of a ring, so more than one reader only costs a hand-off per event and delivers the
// events of a connection out of order.
func (m *Linker) ReadEventAsyncWithBufferSize(emap *ebpf.Map, bufReader RingBufferReader, perCPUBuffer,
	parallels int, dataSupplier func() interface{}) {
	m.readEventAsync(emap, bufReader, perCPUBuffer, parallels, dataSupplier, readerOptions{})
}

var warnParallelsOnce sync.Once

func (m *Linker) readEventAsync(emap *ebpf.Map, bufReader RingBufferReader, perCPUBuffer,
	parallels int, dataSupplier func() interface{}, opts readerOptions) {
	if parallels > 1 {
		warnParallelsOnce.Do(func() {
			log.Warnf("parse_parallels %d is ignored: every ring is read by one goroutine, the library serializes the reads", parallels)
		})
	}
	rd, err := perf.NewReaderWithOptions(emap, perCPUBuffer, perf.ReaderOptions{WakeupEvents: opts.wakeupEvents})
	if err != nil {
		m.AppendError(fmt.Errorf("open ring buffer error: %v", err))
		return
	}
	m.addCloser(rd)

	// the sizing event is only measured, never delivered: it must be given back or it holds one
	// pooled buffer and one unit of the event accounting for the lifetime of the process
	sizingEvent := dataSupplier()
	recordBuilder := newPerfRecordBuilder(sizingEvent)
	discardEvent(sizingEvent)
	if opts.flushPeriod <= 0 {
		opts.flushPeriod = defaultReaderFlushPeriod
	}
	if opts.wakeupEvents > 0 {
		// a ring is only woken up for every wakeupEvents events: flush it periodically, so the events of
		// little traffic are delivered within the flush period
		go func() {
			ticker := time.NewTicker(opts.flushPeriod)
			defer ticker.Stop()
			for range ticker.C {
				if err := rd.Flush(); err != nil {
					if errors.Is(err, perf.ErrClosed) || errors.Is(err, os.ErrClosed) {
						return
					}
					// a flush that fails for another reason is tried again the next period: the events of little
					// traffic would wait for the wakeup count otherwise
					log.Debugf("flush the ring of %s error: %v", emap.String(), err)
				}
			}
		}()
	}
	m.asyncReadEvent(rd, emap, recordBuilder, dataSupplier, bufReader, opts.drained, opts.flushPeriod)
}

// drainClock bounds how long the events handed over since the last drain may wait when the ring never
// runs empty: tick tells every drainClockCheckEvery events that it is worth asking expired
type drainClock struct {
	period time.Duration
	last   time.Time
	events int
}

const drainClockCheckEvery = 64

func (c *drainClock) tick() bool {
	c.events++
	return c.events%drainClockCheckEvery == 0
}

func (c *drainClock) expired(now time.Time) bool {
	return now.Sub(c.last) >= c.period
}

func (c *drainClock) reset(now time.Time) {
	c.last = now
	c.events = 0
}

// asyncReadEvent reads the ring and hands every event to bufReader. With drained (batching), it reads on
// without blocking while the ring holds events, and calls drained once it is empty, before it blocks
// again, and at least every maxDelay while it never runs empty.
//
//nolint:gocyclo,funlen // the per-event read loop of the ring, its cases are the outcomes of one read
func (m *Linker) asyncReadEvent(rd *perf.Reader, emap *ebpf.Map, recordPool *perfRecordBuilder,
	dataSupplier func() interface{}, bufReader RingBufferReader, drained func(), maxDelay time.Duration) {
	batching := drained != nil
	go func() {
		clock := &drainClock{period: maxDelay, last: time.Now()}
		// the events of the ring are parsed one after another by this goroutine only, and no event keeps
		// the reader, so one reader serves all of them
		sampleReader := &BytesReader{}
		mapName := emap.String()
		handOver := func(now time.Time) {
			drained()
			clock.reset(now)
		}
		// the deadline of a read that must not block: the reader returns what the rings hold, then
		// os.ErrDeadlineExceeded
		past := time.Unix(1, 0)
		blocking, deadlineBlocking := true, true
		for {
			if batching && blocking != deadlineBlocking {
				if blocking {
					rd.SetDeadline(time.Time{})
				} else {
					rd.SetDeadline(past)
				}
				deadlineBlocking = blocking
			}
			record := recordPool.GetRecord()
			err := rd.ReadInto(record)
			if err != nil {
				recordPool.PutRecord(record)
				if errors.Is(err, perf.ErrClosed) {
					if batching {
						drained()
					}
					return
				}
				if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, perf.ErrFlushed) {
					// every event the rings held has been read
					if batching {
						handOver(time.Now())
						blocking = true
					}
					continue
				}
				log.Warnf("read from %s ringbuffer error: %v", emap.String(), err)
				continue
			}
			blocking = false

			if record.LostSamples != 0 {
				// accumulate and report in an aggregated, periodic summary instead of logging
				// every burst on its own (see lostsamples.go).
				recordLostSamples(mapName, record.LostSamples)
				recordPool.PutRecord(record)
				continue
			}

			// a batch of several events (per-CPU batching of HTTP/2 call records): each one is routed on its own
			if splitSample(mapName, record.RawSample, bufReader) {
				recordPool.PutRecord(record)
				if batching && clock.tick() {
					if now := time.Now(); clock.expired(now) {
						handOver(now)
					}
				}
				continue
			}

			var data interface{}
			if shed, supply := shedSample(mapName, record.RawSample); shed {
				// sent without its data under memory pressure: what a refused event is, without the copy,
				// and what it still says of its call goes on when the consumer takes it
				recordDroppedByLimit(mapName, record.RawSample)
				if supply != nil {
					data = supply()
				}
				if data == nil {
					recordPool.PutRecord(record)
					continue
				}
			} else if data = dataSupplier(); data == nil {
				// the consumer refused the event (e.g. the memory protection of the socket data buffers is active)
				recordDroppedByLimit(mapName, record.RawSample)
				recordPool.PutRecord(record)
				continue
			}
			if r, ok := data.(EventReader); ok {
				sampleReader.Reset(record.RawSample)
				r.ReadFrom(sampleReader)
				if readErr := sampleReader.HasError(); readErr != nil {
					log.Warnf("parsing data from %s, raw size: %d, ringbuffer error: %v", emap.String(), len(record.RawSample), readErr)
					lossEpoch.Add(1) // the event is lost to the consumers
					discardEvent(data)
					recordPool.PutRecord(record)
					continue
				}
			} else {
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, data); err != nil {
					log.Warnf("parsing data from %s, raw size: %d, ringbuffer error: %v", emap.String(), len(record.RawSample), err)
					lossEpoch.Add(1) // the event is lost to the consumers
					discardEvent(data)
					recordPool.PutRecord(record)
					continue
				}
			}

			bufReader(data)

			recordPool.PutRecord(record)
			// the rings may never run empty under steady traffic: hand over what waits at least every maxDelay
			if batching && clock.tick() {
				if now := time.Now(); clock.expired(now) {
					handOver(now)
				}
			}
		}
	}()
}

func (m *Linker) OpenUProbeExeFile(path string) *UProbeExeFile {
	executable, err := link.OpenExecutable(path)
	if err != nil {
		m.AppendError(fmt.Errorf("cannot found the execute file: %s, error: %v", path, err))
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

// Found reports whether the executable was opened successfully. When it is false the AddLink*
// calls are silent no-ops, so a caller that must not proceed(e.g. arm a BPF gate) without a real
// uprobe attached should check this instead of assuming AddLink succeeded.
func (u *UProbeExeFile) Found() bool {
	return u.found
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
	if p == nil {
		return
	}
	lk, err := u.addLinkWithType0(symbol, enter, p, 0)
	if err != nil {
		u.linker.AppendError(fmt.Errorf("file: %s, symbol: %s, type: %s, error: %v",
			u.addr, symbol, u.parseEnterOrExitString(enter), err))
	} else if lk != nil {
		log.Debugf("attach to the uprobe, file: %s, symbol: %s, type: %s", u.addr, symbol, u.parseEnterOrExitString(enter))
		u.linker.addCloser(lk)
	}
}

// AddEnterLinkReturningCloser attaches the ENTER uprobe like AddLinkWithType but RETURNS the
// created link instead of only accumulating it into the linker's shared closers, so the caller
// owns its lifetime and can detach THIS uprobe on its own(e.g. the ztunnel identity probe when it
// proves the offsets are unavailable) without tearing down the whole loader. Because the link is
// not in the shared closers, the caller is responsible for closing it. Returns (nil, nil) when the
// executable was not opened or the program is nil.
func (u *UProbeExeFile) AddEnterLinkReturningCloser(symbol string, p *ebpf.Program) (io.Closer, error) {
	if !u.found || p == nil {
		return nil, nil
	}
	lk, err := u.addLinkWithType0(symbol, true, p, 0)
	if err != nil {
		return nil, err
	}
	if lk == nil {
		return nil, nil
	}
	return lk, nil
}

func (u *UProbeExeFile) addLinkWithType0(symbol string, enter bool, p *ebpf.Program, customizeAddress uint64) (link.Link, error) {
	u.linker.linkMutex.Lock()
	defer u.linker.linkMutex.Unlock()
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
			Offset: customizeAddress,
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
		u.linker.AppendError(fmt.Errorf("file: %s, symbol: %s, type: %s, error: %v",
			u.addr, symbol, u.parseEnterOrExitString(enter), err))
	} else {
		log.Debugf("attach to the go uprobe, file: %s, symbol: %s, type: %s", u.addr, symbol, u.parseEnterOrExitString(enter))
		for _, l := range links {
			u.linker.addCloser(l)
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

	// based on the base addresses and symbol data buffer
	// calculate all RET addresses
	// https://github.com/iovisor/bcc/issues/1320#issuecomment-407927542
	var addresses []uint64
	for i := 0; i < int(targetSymbol.Size); {
		var instLen int
		if runtime.GOARCH == "arm64" {
			inst, err := arm64asm.Decode(buffer[i:])
			if err != nil {
				i += 4
				continue
			}

			if inst.Op == arm64asm.RET {
				addresses = append(addresses, uint64(i))
			}

			instLen = 4
		} else {
			inst, err := x86asm.Decode(buffer[i:], 64)
			if err != nil {
				return nil, fmt.Errorf("error decode the function data: %v", err)
			}

			if inst.Op == x86asm.RET {
				addresses = append(addresses, uint64(i))
			}

			instLen = inst.Len
		}

		i += instLen
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

// addCloser keeps what Close closes; the uprobes of a process may attach while a reader opens
func (m *Linker) addCloser(c io.Closer) {
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	m.closers = append(m.closers, c)
}

func (m *Linker) HasError() error {
	m.linkMutex.Lock()
	defer m.linkMutex.Unlock()
	return m.errors
}

func (m *Linker) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.linkMutex.Lock()
		closers := m.closers
		m.linkMutex.Unlock()
		for _, l := range closers {
			if e := l.Close(); e != nil {
				err = multierror.Append(err, e)
			}
		}
	})
	return err
}

type perfRecordBuilder struct {
	dataSize int
	pool     sync.Pool
}

// EventDiscarder is implemented by an event that holds a resource the reader must give back when it
// drops the event instead of delivering it, such as the pooled buffer of a socket data event.
type EventDiscarder interface {
	Discard()
}

// discardEvent gives back whatever an undelivered event holds
func discardEvent(data interface{}) {
	if discarder, ok := data.(EventDiscarder); ok {
		discarder.Discard()
	}
}

func newPerfRecordBuilder(data interface{}) *perfRecordBuilder {
	// added 8 bytes means fix some event not aligned
	var size = binary.Size(data) + 8
	if r, ok := data.(EventReader); ok {
		reader := newSizeCalcReader()
		r.ReadFrom(reader)
		size = reader.Size() + 8
	}

	builder := &perfRecordBuilder{
		dataSize: size,
	}
	builder.pool.New = func() any {
		return &perf.Record{RawSample: make([]byte, 0, builder.dataSize)}
	}
	return builder
}

func (p *perfRecordBuilder) GetRecord() *perf.Record {
	return p.pool.Get().(*perf.Record)
}

func (p *perfRecordBuilder) PutRecord(r *perf.Record) {
	p.pool.Put(r)
}
