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

package common

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/telemetry"
)

// The idle kick of the per-CPU batches of h2c call records (bpf/accesslog/common/h2c_batch.h).
//
// A batch is sent when it is full, before a full upload of the connection with records in it, and at a
// close; a CPU whose connections went quiet would keep its records. So a goroutine locked to each CPU of the
// agent's allowed set writes one byte to a pipe of its own, at once and then every second: the BPF write
// probe recognises the agent's tgid and that fd, marks the CPU it runs on as kickable, flushes that CPU's
// buffer, and does not record the write. A CPU only batches once its kick has run (h2c_batch_is_kickable),
// so a CPU that cannot be pinned and kicked never leaves records waiting. The period matches the sender's
// flush period, so it adds at most about a second to the delivery and changes no reported value; it is below
// the 3s the parser waits for a missing call.
//
// The kick needs the host pid namespace, because the tgid the BPF side sees is the host one: without it
// (no hostPID) the batching is left off, so no records are produced that the kick would have to flush.
const h2cBatchKickPeriod = time.Second

// the highest CPU index the affinity set can hold (unix.CPUSet is 1024 bits)
const maxAffinityCPUs = 1024

var h2cBatchKicks atomic.Int64

func init() {
	telemetry.Register("rover_h2c_batch_kicks_total",
		"Idle kicks the agent sent to the CPUs holding per-CPU batches of h2c call records",
		telemetry.Counter, func() float64 { return float64(h2cBatchKicks.Load()) })
}

// startH2CBatchKick is the setup-time entry; the agent keeps the kick for its lifetime
func startH2CBatchKick(loader *bpf.Loader) error {
	_, err := StartH2CBatchKick(loader)
	if err == nil {
		// a record waits in its CPU's batch for up to a kick period
		deliveryDelayKick.Store(int64(h2cBatchKickPeriod))
	}
	return err
}

// The longest a socket call can reach the analysis after a call of its connection that returned after it, by
// what delays it: its record waits in a per-CPU batch for up to the kick period, a ring that is not woken up for
// every event is read at least every flush period, and the reader hands over a partial batch of events at least
// every flush period
var deliveryDelayKick, deliveryDelayReader atomic.Int64

// H2CDeliveryDelayBound is the longest a socket call can reach the analysis after a call of its connection that
// returned after it, as the agent is set up (0 before the set up): what the HTTP/2 parser waits at least for a
// missing earlier call before it gives it up
func H2CDeliveryDelayBound() time.Duration {
	return time.Duration(deliveryDelayKick.Load() + deliveryDelayReader.Load())
}

// StartH2CBatchKick opens the kick pipe, tells the BPF side the agent's tgid and the pipe's write fd, and
// starts a goroutine locked to each CPU of the agent's allowed set that kicks it at once and then every
// period. It fails (so batching is left off) when the agent is not in the host pid namespace, or when a CPU
// in the allowed set cannot be pinned, because then that CPU's batches could wait without a kick to flush
// them. stop ends it and turns the kick off on the BPF side; the agent does not call it, the tests do.
func StartH2CBatchKick(loader *bpf.Loader) (stop func(), err error) {
	if loader.H2cBatchMap == nil || loader.BatchKickTgid == nil || loader.BatchKickFd == nil {
		return nil, fmt.Errorf("the BPF side has no kick")
	}
	if hostNS, err := inHostPIDNamespace(); err == nil && !hostNS {
		return nil, fmt.Errorf("the agent is not in the host pid namespace (needs hostPID); the batch kick is disabled")
	}
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		return nil, fmt.Errorf("read the cpu affinity: %v", err)
	}
	var cpus []int
	for c := 0; c < maxAffinityCPUs; c++ {
		if allowed.IsSet(c) {
			cpus = append(cpus, c)
		}
	}
	if len(cpus) == 0 {
		return nil, fmt.Errorf("the cpu affinity set is empty")
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() { _, _ = io.Copy(io.Discard, reader) }() // the pipe must never fill and block a kick
	// the agent runs in the host pid namespace (checked above), so its pid is the tgid the BPF side sees
	if err := loader.BatchKickTgid.Set(uint32(os.Getpid())); err != nil {
		_ = writer.Close()
		_ = reader.Close()
		return nil, err
	}
	if err := loader.BatchKickFd.Set(uint32(writer.Fd())); err != nil {
		_ = writer.Close()
		_ = reader.Close()
		return nil, err
	}

	done := make(chan struct{})
	pinned := make(chan bool, len(cpus))
	var wg sync.WaitGroup
	for _, cpu := range cpus {
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			h2cBatchKickCPU(cpu, done, writer, pinned)
		}(cpu)
	}
	cleanup := func() {
		close(done)
		wg.Wait()
		_ = loader.BatchKickFd.Set(uint32(0))
		_ = writer.Close()
		_ = reader.Close()
	}
	// every allowed CPU must pin; one that cannot would keep its batches without a kick to flush them
	for range cpus {
		if !<-pinned {
			cleanup()
			return nil, fmt.Errorf("cannot pin a kick goroutine to an allowed cpu; the batch kick is disabled")
		}
	}
	log.Infof("the per-CPU h2c call batches are kicked every %s on %d CPUs (tgid %d, fd %d)", h2cBatchKickPeriod,
		len(cpus), os.Getpid(), writer.Fd())
	return cleanup, nil
}

// h2cBatchKickCPU locks itself to an OS thread bound to the CPU and writes a byte to the kick pipe at once,
// then every period, so the write runs on that CPU where the BPF write probe flushes the CPU's batch. It reports on
// pinned whether it could bind to the CPU.
func h2cBatchKickCPU(cpu int, done <-chan struct{}, writer *os.File, pinned chan<- bool) {
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		log.Warnf("cannot bind the h2c batch kick to CPU %d (%v); the batch kick is disabled so its batches do not wait", cpu, err)
		pinned <- false
		return
	}
	pinned <- true
	one := []byte{1}
	ticker := time.NewTicker(h2cBatchKickPeriod)
	defer ticker.Stop()
	for {
		// the write runs on this CPU: it marks the CPU kickable (so it starts batching) and flushes its batch
		if _, err := writer.Write(one); err == nil {
			h2cBatchKicks.Add(1)
		}
		select {
		case <-done:
			return
		case <-ticker.C:
		}
	}
}

// inHostPIDNamespace tells whether the agent shares the host's pid namespace (hostPID). It compares its own
// pid namespace with the one of pid 1 seen through the host /proc the agent mounts. When that cannot be read
// (no host /proc mapping) the answer is left unknown (an error): the caller then proceeds, and the kickable
// gate still keeps a wrong-tgid kick from ever turning batching on.
func inHostPIDNamespace() (bool, error) {
	self, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return false, err
	}
	hostInit, err := os.Readlink(host.GetHostProcInHost("1/ns/pid"))
	if err != nil {
		return false, err
	}
	return self == hostInit, nil
}
