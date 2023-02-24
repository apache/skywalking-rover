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
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// nolint
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf $REPO_ROOT/bpf/profiling/continuous/network.c -- -I$REPO_ROOT/bpf/include -D__TARGET_ARCH_x86

var log = logger.GetLogger("profiling", "continuous", "checker", "network", "bpf")

var locker sync.Mutex
var bpf *bpfObjects
var bpfLinker *btf.Linker
var monitoringProcesses map[int32]*monitoringProcessInfo
var notifiers []EventNotify

func init() {
	monitoringProcesses = make(map[int32]*monitoringProcessInfo)
}

type BufferEvent interface {
	Pid() int32
	RequestURI() string
	IsResponseError() bool
	Duration() time.Duration
	StartTime() time.Time
}

type EventNotify interface {
	ReceiveBufferEvent(event BufferEvent)
}

func AddEventNotify(notify EventNotify) {
	notifiers = append(notifiers, notify)
}

// AddWatchProcess add the process to monitoring with from source
// BPF would be start automatically
func AddWatchProcess(pid int32, from string) error {
	if e := startBPFIfNeed(); e != nil {
		return e
	}

	// adding to the cache
	monitoring := monitoringProcesses[pid]
	if monitoring == nil {
		monitoring = newMonitoringProcessInfo(pid)
		monitoringProcesses[pid] = monitoring
	}

	// start monitoring process
	if e := monitoring.AddSource(from); e != nil {
		// remove the source if add failure
		if deleteProcess, _ := monitoring.RemoveSource(from); deleteProcess {
			delete(monitoringProcesses, pid)
		}
		return e
	}
	return nil
}

// RemoveWatchProcess remove the process to monitoring with from source
// if no process is monitoring, the BPF would be stopped
func RemoveWatchProcess(pid int32, from string) error {
	defer func() {
		if err := shutdownBPFIfNoProcesses(); err != nil {
			log.Warnf("shutdown the BPF failure: %v", err)
		}
	}()
	monitoring := monitoringProcesses[pid]
	if monitoring == nil {
		return nil
	}

	deleteProcess, err := monitoring.RemoveSource(from)
	if deleteProcess {
		delete(monitoringProcesses, pid)
	}
	return err
}

func ForceShutdownBPF() error {
	// shutdown all processes
	var err error
	for _, p := range monitoringProcesses {
		if e := p.Shutdown(); e != nil {
			err = multierror.Append(err, e)
		}
	}
	// shutdown the main BPF
	monitoringProcesses = make(map[int32]*monitoringProcessInfo)
	if e := shutdownBPF(); e != nil {
		err = multierror.Append(err, e)
	}
	return err
}

// start the BPF program if contains process that needs monitor
func startBPFIfNeed() error {
	locker.Lock()
	defer locker.Unlock()

	if bpf != nil {
		return nil
	}

	bpf = &bpfObjects{}
	if err := loadBpfObjects(bpf, btf.GetEBPFCollectionOptionsIfNeed()); err != nil {
		return err
	}
	bpfLinker = btf.NewLinker()
	bpfLinker.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_sendmsg": bpf.TcpSendmsg})
	bpfLinker.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_recvmsg": bpf.TcpRecvmsg})
	bpfLinker.AddLink(link.Kretprobe, map[string]*ebpf.Program{"tcp_recvmsg": bpf.RetTcpRecvmsg})

	reader := newNetworkBufferReader(func(event BufferEvent) {
		for _, n := range notifiers {
			n.ReceiveBufferEvent(event)
		}
	})
	bpfLinker.ReadEventAsyncWithBufferSize(bpf.SocketBufferSendQueue, reader.Read, os.Getpagesize()*100, reader.BufferDataBPFSupplier)

	if err := bpfLinker.HasError(); err != nil {
		_ = bpfLinker.Close()
		_ = bpf.Close()
		bpf = nil
		bpfLinker = nil
		return err
	}
	return nil
}

// shutdown the BPF program if we don't contain any process need to be monitored
func shutdownBPFIfNoProcesses() error {
	// if still contains monitoring process then the BPF should not be stopped
	if len(monitoringProcesses) != 0 {
		return nil
	}
	return shutdownBPF()
}

func shutdownBPF() error {
	locker.Lock()
	defer locker.Unlock()

	if bpf == nil {
		return nil
	}
	// if still contains monitoring process then the BPF should not be stopped
	if len(monitoringProcesses) != 0 {
		return nil
	}

	var err error
	if e := bpfLinker.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	if e := bpf.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	bpf = nil
	return err
}
