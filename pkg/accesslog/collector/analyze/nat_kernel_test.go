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

package analyze

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

// The NAT address of a connect (skywalking-rover/bpf/accesslog/syscalls/connect_conntrack.c and
// skywalking-rover/pkg/accesslog/bpf/nat.go). TestNATConnectRemote sets up a "Service": a DNAT of 127.0.0.2:80 to a
// backend listener at 127.0.0.3:18080 in the nat OUTPUT hook (nft or iptables, or rules installed before the run with
// -nat.ready), connects to the Service and reads the connect event the programs send: its conntrack upstream must be the
// backend. It runs with each NAT hook mode (access_log.bpf.nat_hook) and logs what each one reports; auto and its
// fallback without trampolines (kprobe) must resolve the backend, the legacy hooks are only reported (on 6.12 they
// never see the NAT).

var natReady = flag.Bool("nat.ready", false, "the DNAT of TestNATConnectRemote is installed already")

const (
	natServiceAddr = "127.0.0.2:80"
	natBackendIP   = "127.0.0.3"
	natBackendPort = 18080
)

// natSetup installs the DNAT, or skips the test when it cannot
func natSetup(t *testing.T) {
	t.Helper()
	if *natReady {
		return
	}
	rules := fmt.Sprintf(`table ip spm_test_nat {
	chain output {
		type nat hook output priority -100; policy accept;
		ip daddr 127.0.0.2 tcp dport 80 dnat to %s:%d
	}
}
`, natBackendIP, natBackendPort)
	if nft, err := exec.LookPath("nft"); err == nil {
		cmd := exec.Command(nft, "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("nft: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command(nft, "delete", "table", "ip", "spm_test_nat").Run() })
		return
	}
	if ipt, err := exec.LookPath("iptables"); err == nil {
		rule := []string{"-t", "nat", "OUTPUT", "-d", "127.0.0.2", "-p", "tcp", "--dport", "80", "-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", natBackendIP, natBackendPort)}
		add := append([]string{"-t", "nat", "-A"}, rule[2:]...)
		if out, err := exec.Command(ipt, add...).CombinedOutput(); err != nil {
			t.Skipf("iptables: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command(ipt, append([]string{"-t", "nat", "-D"}, rule[2:]...)...).Run() })
		return
	}
	t.Skip("no nft or iptables to install the DNAT, and no -nat.ready")
}

type natResult struct {
	remote   string
	upstream string
	plan     string
	// the runs of the NAT programs (bpf_stats) over the connect, the close and the half second after each
	runs string
}

// natConnect loads the programs with the NAT mode given, connects to the Service and returns what the connect event says
func natConnect(t *testing.T, mode string) natResult { //nolint:funlen // it loads the BPF, sets its switches, runs the traffic and reads the events in one place, all sharing the loader and the reader
	t.Helper()
	loader, err := bpf.NewLoaderWithOptions(bpf.LoaderOptions{NATHook: mode})
	if err != nil {
		t.Fatal(err)
	}
	defer loader.Close()
	if err := loader.MonitorProcess(uint32(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	loader.AddSyscall("connect", loader.TracepointEnterConnect, loader.TracepointExitConnect, loader.FentryEnterConnect, loader.FexitExitConnect)
	loader.AddSyscall("close", loader.TracepointEnterClose, loader.TracepointExitClose, loader.FentryEnterClose, loader.FexitExitClose)
	loader.AddLink(link.Kprobe, map[string]*ebpf.Program{"tcp_connect": loader.TcpConnect})
	if err := loader.HasError(); err != nil {
		t.Fatal(err)
	}
	natErr := loader.AddNATHooks()
	reader, err := perf.NewReader(loader.SocketConnectionEventQueue, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connects []*events.SocketConnectEvent
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			record, err := reader.Read()
			if err != nil {
				return
			}
			e := &events.SocketConnectEvent{}
			e.ReadFrom(btf.NewReader(record.RawSample))
			mu.Lock()
			connects = append(connects, e)
			mu.Unlock()
		}
	}()

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", natBackendIP, natBackendPort))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	conn, err := net.DialTimeout("tcp", natServiceAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect to the Service %s: %v", natServiceAddr, err)
	}
	local := conn.LocalAddr().(*net.TCPAddr)
	if peer := conn.RemoteAddr().String(); peer != natServiceAddr {
		t.Logf("the socket peer is %s", peer)
	}
	time.Sleep(500 * time.Millisecond)
	_ = conn.Close()
	time.Sleep(500 * time.Millisecond)
	_ = reader.Close()
	<-done

	res := natResult{plan: loader.NATHookPlan()}
	var runs []string
	for name, p := range map[string]*ebpf.Program{"nf_confirm": loader.NfConfirm, "fentry_nf_confirm": loader.FentryNfConfirm,
		"nf_conntrack_hash_insert": loader.NfConntrackHashInsert, "fexit_nf_conntrack_confirm": loader.FexitNfConntrackConfirm,
		"kprobe_nf_conntrack_confirm": loader.KprobeNfConntrackConfirm} {
		if stats, err := p.Stats(); err == nil && stats.RunCount > 0 {
			runs = append(runs, fmt.Sprintf("%s=%d", name, stats.RunCount))
		}
	}
	res.runs = strings.Join(runs, " ")
	if natErr != nil {
		res.plan += fmt.Sprintf(" (attach: %v)", natErr)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, e := range connects {
		if e.PID != uint32(os.Getpid()) || e.FuncName != 1 || uint16(e.LocalAddrPort) != uint16(local.Port) {
			continue
		}
		res.remote = fmt.Sprintf("%s:%d", ipv4(e.RemoteAddrV4), e.RemoteAddrPort)
		if e.ConnTrackUpstreamPort != 0 {
			res.upstream = fmt.Sprintf("%s:%d", ipv4(uint32(e.ConnTrackUpstreamIPl)), e.ConnTrackUpstreamPort)
		}
	}
	return res
}

func ipv4(v uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IP(b).String()
}

func TestNATConnectRemote(t *testing.T) {
	requireBPF(t)
	natSetup(t)
	if stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME)); err == nil {
		defer stats.Close()
	}
	want := fmt.Sprintf("%s:%d", natBackendIP, natBackendPort)
	for _, mode := range []string{"legacy", "kprobe", "auto"} {
		res := natConnect(t, mode)
		resolved := res.upstream == want
		t.Logf("NAT hook %s: connect event remote %s, conntrack upstream %q, resolved=%t; plan %s; program runs: %s",
			mode, res.remote, res.upstream, resolved, res.plan, res.runs)
		if res.remote == "" {
			t.Errorf("NAT hook %s: no connect event of the test connection", mode)
		}
		if mode != "legacy" && !resolved {
			t.Errorf("NAT hook %s: the conntrack upstream is %q, want the backend %s", mode, res.upstream, want)
		}
	}
}
