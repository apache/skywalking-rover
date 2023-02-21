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
var monitoringProcesses map[int32]map[string]bool
var notifiers []EventNotify

func init() {
	monitoringProcesses = make(map[int32]map[string]bool)
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

	// first, update to the monitor control
	if e := bpf.ProcessMonitorControl.Update(uint32(pid), uint32(1), ebpf.UpdateAny); e != nil {
		// if add failure, then check the BPF should be shutdown or not
		_ = shutdownBPFIfNoProcesses()
		return e
	}

	// then, add to the monitoring cache
	monitoring := monitoringProcesses[pid]
	if monitoring == nil {
		monitoring = make(map[string]bool)
		monitoringProcesses[pid] = monitoring
	}

	monitoring[from] = true
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

	delete(monitoring, from)
	shouldRemoveMonitor := false
	if len(monitoringProcesses[pid]) == 0 {
		delete(monitoringProcesses, pid)
		shouldRemoveMonitor = true
	}

	if shouldRemoveMonitor {
		if err := bpf.ProcessMonitorControl.Delete(uint32(pid)); err != nil {
			return err
		}
	}
	return nil
}

func ForceShutdownBPF() error {
	return shutdownBPF()
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
	bpfLinker.ReadEventAsync(bpf.SocketBufferSendQueue, reader.Read, reader.BufferDataBPFSupplier)

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
