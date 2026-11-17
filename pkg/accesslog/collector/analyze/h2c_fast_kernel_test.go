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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"

	"github.com/apache/skywalking-rover/pkg/accesslog/bpf"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	aclevents "github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

// The scripted exchange of the h2c follower (h2cFastTraffic): one traced loopback connection whose calls take every
// kind of the fast path of the follower (h2c_fast_call in skywalking-rover/bpf/accesslog/syscalls/h2c.h) and of its
// generic path. h2cFastRun runs it on a loader and gives what it produced as comparable lines (everything but the
// times, the connection ids and the ports, which differ between two connections); TestAttachModeSameOutput
// compares the runs of the attach modes.

// h2cFastOutput is what one run produced, as comparable lines
type h2cFastOutput struct {
	events    []string
	summaries []string
}

// h2cFastSession is the scripted exchange: every write is one socket call that the reads that follow find whole, and
// every read is one socket call of the size it asks for
type h2cFastSession struct {
	t              *testing.T
	server, client *net.TCPConn
}

func (s *h2cFastSession) write(c *net.TCPConn, data ...[]byte) {
	if _, err := c.Write(bytes.Join(data, nil)); err != nil {
		s.t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
}

// writev writes the parts as the iov entries of one writev call
func (s *h2cFastSession) writev(c *net.TCPConn, parts ...[]byte) {
	raw, err := c.SyscallConn()
	if err != nil {
		s.t.Fatal(err)
	}
	var werr error
	if err := raw.Write(func(fd uintptr) bool {
		_, werr = unix.Writev(int(fd), parts)
		return true
	}); err != nil {
		s.t.Fatal(err)
	}
	if werr != nil {
		s.t.Fatal(werr)
	}
	time.Sleep(20 * time.Millisecond)
}

func (s *h2cFastSession) read(c *net.TCPConn, sizes ...int) {
	for _, size := range sizes {
		if _, err := io.ReadFull(c, make([]byte, size)); err != nil {
			s.t.Fatal(err)
		}
	}
}

func h2cFastData(stream uint32, flags http2.Flags, n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i*7 + int(stream))
	}
	return h2cFrame(http2.FrameData, flags, stream, payload)
}

// h2cFastTraffic is the script: control frames written and read alone and in pairs (B), a lone control frame header
// (held), requests and responses on three streams with their DATA frames written whole, through writev and read in
// every shape the follower knows (a lone header, a header with the start of the payload, the payload in pieces, a
// piece that ends the frame), a PADDED frame, streams interleaved, END_STREAM frames
func h2cFastTraffic(t *testing.T) (serverPort uint16) { //nolint:funlen // one scripted traffic scenario, kept in one piece so its steps read in order
	server, client := h2cTCPPair(t)
	serverPort = uint16(server.LocalAddr().(*net.TCPAddr).Port)
	s := &h2cFastSession{t: t, server: server, client: client}
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()
	settings := h2cFrame(http2.FrameSettings, 0, 0, nil)
	settingsAck := h2cFrame(http2.FrameSettings, http2.FlagSettingsAck, 0, nil)
	window := func(stream uint32) []byte { return h2cFrame(http2.FrameWindowUpdate, 0, stream, []byte{0, 0, 0x40, 0}) }
	ping := h2cFrame(http2.FramePing, 0, 0, make([]byte, 8))
	headers := func(stream uint32, end bool) []byte {
		flags := http2.FlagHeadersEndHeaders
		if end {
			flags |= http2.FlagHeadersEndStream
		}
		return h2cFrame(http2.FrameHeaders, flags, stream, h2cStaticRequest("/fast"))
	}

	// the preface and the settings both ways
	s.write(client, []byte(http2.ClientPreface), settings)
	s.read(server, len(http2.ClientPreface), 9)
	s.write(server, settings, settingsAck)
	s.read(client, 9, 9)
	s.write(client, settingsAck)
	s.read(server, 9)

	// unused frames, alone, in pairs, and a header read alone (held, then its payload)
	for i := 0; i < 4; i++ {
		s.write(client, window(0))
		s.read(server, 13)
		s.write(server, window(1), window(0))
		s.read(client, 26)
	}
	s.write(client, ping)
	s.read(server, 17)
	s.write(client, window(0))
	s.read(server, 9, 4)
	// lone headers held and their payloads read alone, as Go's framer reads every frame: a PING and a stream
	// WINDOW_UPDATE, then a held header whose next call is more than its payload (the held header is uploaded)
	for i := 0; i < 3; i++ {
		s.write(client, ping)
		s.read(server, 9, 8)
		s.write(client, window(1))
		s.read(server, 9, 4)
	}
	s.write(client, window(0), ping)
	s.read(server, 9, 21)

	// requests with bodies on streams 1 and 3: whole DATA frames, the server reads them in every shape
	s.write(client, headers(1, false))
	s.read(server, 9, len(headers(1, false))-9)
	s.write(client, headers(3, false))
	s.read(server, 9, len(headers(3, false))-9)
	for i := 0; i < 3; i++ {
		s.write(client, h2cFastData(1, 0, 16384))
		s.read(server, 9, 4096, 4096, 4096, 4096)
		s.write(server, window(1), window(0))
		s.read(client, 26)
	}
	for i := 0; i < 2; i++ {
		s.write(client, h2cFastData(1, 0, 8192))
		s.read(server, 9+100, 1000, 7092)
	}
	// a frame through writev (its header alone in the first iov entry), then stream 3 in between
	d := h2cFastData(1, 0, 6000)
	s.writev(client, d[:9], d[9:])
	s.read(server, 9, 3000, 3000)
	s.write(client, h2cFastData(3, 0, 5000))
	s.read(server, 9, 5000)
	s.write(client, h2cFastData(1, 0, 5000))
	s.read(server, 5009)
	// a frame written as its header alone and its payload in two writes (the writes inside the payload)
	d = h2cFastData(1, 0, 7000)
	s.write(client, d[:9])
	s.write(client, d[9:3009])
	s.write(client, d[3009:])
	s.read(server, 9, 7000)
	// a PADDED frame, then the last frames with END_STREAM
	padded := h2cFrame(http2.FrameData, http2.FlagDataPadded, 1, append([]byte{4}, make([]byte, 1004)...))
	s.write(client, padded)
	s.read(server, 9, 500, 505)
	s.write(client, h2cFastData(1, http2.FlagDataEndStream, 3000))
	s.read(server, 9, 1000, 2000)
	s.write(client, h2cFastData(3, http2.FlagDataEndStream, 3000))
	s.read(server, 3009)

	// responses: the server writes whole frames, the client reads a header with the start of the payload and the
	// rest in pieces, as Go's client does, and whole frames
	for _, stream := range []uint32{1, 3} {
		resp := h2cFrame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, stream, []byte{0x88})
		s.write(server, resp)
		s.read(client, len(resp))
		for i := 0; i < 4; i++ {
			s.write(server, h2cFastData(stream, 0, 16384))
			s.read(client, 4096, 4096, 4096, 4096, 9)
			s.write(client, window(stream), window(0))
			s.read(server, 26)
		}
		for i := 0; i < 2; i++ {
			s.write(server, h2cFastData(stream, 0, 2000))
			s.read(client, 2009)
		}
		s.write(server, h2cFastData(stream, http2.FlagDataEndStream, 4000))
		s.read(client, 9+1000, 3000)
	}
	// a request without a body and its response, then a stream of many small frames read whole
	s.write(client, headers(5, true))
	s.read(server, len(headers(5, true)))
	s.write(server, h2cFrame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 5, []byte{0x88}))
	s.read(client, 10)
	for i := 0; i < 20; i++ {
		s.write(server, h2cFastData(5, 0, 300))
		s.read(client, 309)
	}
	s.write(server, h2cFastData(5, http2.FlagDataEndStream, 300))
	s.read(client, 309)
	return serverPort
}

func h2cFastRun(t *testing.T, loader *bpf.Loader) *h2cFastOutput { //nolint:funlen // it loads the BPF, sets its switches, runs the traffic and reads the events in one place, all sharing the loader and the reader
	t.Helper()
	set := func(v *ebpf.Variable, value interface{}) {
		if err := v.Set(value); err != nil {
			t.Fatalf("set %v: %v", v, err)
		}
	}
	for _, v := range []*ebpf.Variable{loader.DropH2cUnusedFrame, loader.SkipH2cDataPayload, loader.BatchH2cRecords,
		loader.SummarizeH2cPayload} {
		// set back to what it was
		var before uint32
		if err := v.Get(&before); err != nil {
			t.Fatal(err)
		}
		set(v, uint32(1))
		defer set(v, before) //nolint:gocritic // every switch is set back when the run ends
	}
	set(loader.BootTimeUnixNs, uint64(host.BootTime.UnixNano()))
	h2cClearMap(t, loader.H2cStreamMap)
	h2cClearMap(t, loader.ActiveConnectionMap)
	// the data ids of the connection's fds start from nothing in both runs
	h2cClearMap(t, loader.SocketDataIdGenerateMap)
	if err := loader.H2cSumEpochMap.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	reader, err := perf.NewReader(loader.SocketDataUploadQueue, 64<<20)
	if err != nil {
		t.Fatalf("perf reader: %v", err)
	}
	var mu sync.Mutex
	var events []*aclevents.SocketDataUploadEvent
	var records []bool
	var summaries []*aclevents.H2CSummary
	var received int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			record, err := reader.Read()
			if err != nil {
				return
			}
			mu.Lock()
			received++
			if record.LostSamples > 0 {
				t.Errorf("%d perf samples lost", record.LostSamples)
			}
			if aclevents.IsBatchRecord(record.RawSample) {
				for i := 0; i < aclevents.BatchRecordCount(record.RawSample); i++ {
					if sum, ok := aclevents.DecodeBatchSummary(record.RawSample, i); ok {
						summaries = append(summaries, sum)
						continue
					}
					e := &aclevents.SocketDataUploadEvent{}
					if aclevents.DecodeBatchRecordInto(e, record.RawSample, i, nil) {
						events = append(events, e)
						records = append(records, true)
					}
				}
			} else if len(record.RawSample) > 0 {
				e := &aclevents.SocketDataUploadEvent{}
				e.ReadFrom(btf.NewReader(record.RawSample))
				events = append(events, e)
				records = append(records, false)
			}
			mu.Unlock()
		}
	}()
	stopKick, err := common.StartH2CBatchKick(loader)
	if err != nil {
		t.Fatalf("start the kick: %v", err)
	}
	// a summary never crosses a wall clock minute (the run then rekeys it): the run, a few seconds, starts early in one
	for time.Now().Second() > 40 {
		time.Sleep(time.Second)
	}
	serverPort := h2cFastTraffic(t)
	for {
		mu.Lock()
		n := received
		mu.Unlock()
		time.Sleep(1500 * time.Millisecond)
		mu.Lock()
		quiet := n == received
		mu.Unlock()
		if quiet {
			break
		}
	}
	stopKick()
	_ = reader.Close()
	<-done

	// the summaries BPF did not send (the user space drains them): taken out of the map
	key := make([]byte, aclevents.SummaryKeySize)
	value := make([]byte, aclevents.SummaryValueSize)
	var keys [][]byte
	for it := loader.H2cSumMap.Iterate(); it.Next(&key, &value); {
		sum := &aclevents.H2CSummary{}
		aclevents.DecodeSummaryKey(sum, key)
		aclevents.DecodeSummaryValue(sum, value)
		sum.Reason = 0xff
		summaries = append(summaries, sum)
		keys = append(keys, append([]byte(nil), key...))
	}
	for _, k := range keys {
		if err := loader.H2cSumMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
	}

	out := &h2cFastOutput{}
	// the two endpoints of the run are told apart by the port of the server; the connection ids, the random ids and
	// the ports differ from run to run
	role := func(local, remote uint16) string {
		switch {
		case local == serverPort:
			return "server"
		case remote == serverPort:
			return "client"
		}
		return fmt.Sprintf("other(%d-%d)", local, remote)
	}
	for i, e := range events {
		out.events = append(out.events, fmt.Sprintf("%s d=%d id=%d prev=%d seq=%d record=%t proto=%d total=%d len=%d skipped=%d "+
			"reduce=%d finished=%d frames=%d first=%d inflight=%d sum=%d/%d/%d l4=%d/%d func=%d ssl=%d span=%d data=%x",
			role(e.LocalPort, e.RemotePort), e.Direction0, e.DataID0, e.PrevDataID0, e.Sequence0, records[i], e.Protocol0,
			e.TotalSize0, e.DataLen, e.PayloadSkipped0, e.HaveReduce, e.Finished, e.H2CFrames0, e.FirstFrameOff, e.InFlight,
			e.SumBefore, e.SumStream, e.SumFrames, e.L4PackageCount, e.L4TotalPackageSize, e.FunctionName, e.SSL, e.DataIDSpan,
			e.BufferData()))
	}
	for _, sum := range summaries {
		out.summaries = append(out.summaries, fmt.Sprintf("%s d=%d stream=%d reason=%d epoch=%d ids=%d-%d bytes=%d l4=%d/%d "+
			"calls=%d func=%d ssl=%d gen=%d", role(sum.LocalPort, sum.RemotePort), sum.Direction0, sum.StreamID, sum.Reason,
			sum.Epoch, sum.FirstDataID0, sum.LastDataID0, sum.Bytes, sum.L4PackageCount, sum.L4TotalPackageSize, sum.Calls,
			sum.FunctionName, sum.SSL, sum.Gen))
	}
	sort.Strings(out.events)
	sort.Strings(out.summaries)
	return out
}

func h2cFastCompare(t *testing.T, what string, off, on []string) {
	t.Helper()
	if len(off) != len(on) {
		t.Errorf("%s: %d in the first run, %d in the second", what, len(off), len(on))
	}
	shown := 0
	for i := 0; i < len(off) || i < len(on); i++ {
		var a, b string
		if i < len(off) {
			a = off[i]
		}
		if i < len(on) {
			b = on[i]
		}
		if a != b && shown < 10 {
			t.Errorf("%s %d:\n first:  %s\n second: %s", what, i, a, b)
			shown++
		}
	}
}
