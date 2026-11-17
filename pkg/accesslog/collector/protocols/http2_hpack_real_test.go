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

package protocols

// Real HTTP/2 implementations: their bytes are recorded by a TCP proxy in front of a Go h2c server (the reads of
// the proxy are the socket calls, the client side is ingress) and fed to the parser, whose streams must match
// what the server handled. Go's net/http + x/net/http2 and grpc-go always run; curl, nghttp, Python h2 and Node
// run when they are installed.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

type h2RecordedCall struct {
	d    enums.SocketDataDirection
	data []byte
}

// h2RecordingProxy forwards TCP connections to a backend and records every read of both sides, in the order
// they returned, per connection
type h2RecordingProxy struct {
	ln      net.Listener
	backend string
	mu      sync.Mutex
	conns   [][]h2RecordedCall
	wg      sync.WaitGroup
}

func newH2RecordingProxy(t *testing.T, backend string) *h2RecordingProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &h2RecordingProxy{ln: ln, backend: backend}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *h2RecordingProxy) addr() string { return p.ln.Addr().String() }

func (p *h2RecordingProxy) serve() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		server, err := net.Dial("tcp", p.backend)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.mu.Lock()
		id := len(p.conns)
		p.conns = append(p.conns, nil)
		p.mu.Unlock()
		p.wg.Add(2)
		go p.pipe(id, client, server, enums.SocketDataDirectionIngress)
		go p.pipe(id, server, client, enums.SocketDataDirectionEgress)
	}
}

func (p *h2RecordingProxy) pipe(id int, from, to net.Conn, d enums.SocketDataDirection) {
	defer p.wg.Done()
	buf := make([]byte, 64<<10)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			p.mu.Lock()
			p.conns[id] = append(p.conns[id], h2RecordedCall{d: d, data: append([]byte(nil), buf[:n]...)})
			// written under the lock: the peer cannot answer before the call is recorded
			_, werr := to.Write(buf[:n])
			p.mu.Unlock()
			if werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if tcp, ok := to.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	} else {
		_ = to.Close()
	}
}

// parse feeds every recorded connection to a parser and returns the streams as "METHOD path status [body]"
func (p *h2RecordingProxy) parse(t *testing.T, withBody bool) (streams []string, calls int) {
	t.Helper()
	p.mu.Lock()
	conns := p.conns
	p.mu.Unlock()
	for i, recorded := range conns {
		c := newHTTP2TestConn(t)
		for j, call := range recorded {
			c.feed(call.d, call.data, 16384)
			if j%7 == 0 {
				c.analyze()
			}
		}
		calls += len(recorded)
		c.analyze()
		m := c.metrics()
		if m.DecodeErrors != 0 || m.FramingErrors != 0 || m.headerDesync[hpIn] || m.headerDesync[hpOut] {
			t.Errorf("connection %d: decodeErr=%d framingErr=%d desync=%v/%v", i, m.DecodeErrors, m.FramingErrors,
				m.headerDesync[hpIn], m.headerDesync[hpOut])
		}
		for _, s := range c.analyzer.streams {
			line := fmt.Sprintf("%s %s %d", s.req[":method"], s.req[":path"], s.status)
			if withBody {
				line += fmt.Sprintf(" %d", s.reqBody)
			}
			streams = append(streams, line)
		}
	}
	sort.Strings(streams)
	return streams, calls
}

// h2TestServer is a Go h2c server that records what it handled as "METHOD path status body"
type h2TestServer struct {
	addr    string
	mu      sync.Mutex
	handled []string
}

//nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
func newH2TestServer(t *testing.T, conf *http2.Server) *h2TestServer {
	s := &h2TestServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status := 200
		if strings.HasPrefix(r.URL.Path, "/status/") {
			status, _ = strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
		}
		if strings.HasPrefix(r.URL.Path, "/bigresp") {
			w.Header().Set("x-big-response", strings.Repeat("R", 30000))
		}
		if strings.HasPrefix(r.URL.Path, "/trailers") {
			w.Header().Set("Trailer", "X-Resp-Trailer")
		}
		w.Header().Set("x-echo", r.Header.Get("x-i"))
		w.WriteHeader(status)
		if status != 204 && status != 304 {
			_, _ = w.Write([]byte(strings.Repeat("b", len(body)%97+1)))
		}
		if strings.HasPrefix(r.URL.Path, "/trailers") {
			w.Header().Set("X-Resp-Trailer", "done")
		}
		s.mu.Lock()
		s.handled = append(s.handled, fmt.Sprintf("%s %s %d %d", r.Method, r.URL.Path, status, len(body)))
		s.mu.Unlock()
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h2c.NewHandler(handler, conf), ReadHeaderTimeout: 10 * time.Second} //nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	s.addr = ln.Addr().String()
	return s
}

func (s *h2TestServer) expected(withBody bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.handled))
	for _, h := range s.handled {
		if !withBody {
			h = h[:strings.LastIndexByte(h, ' ')]
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func compareH2(t *testing.T, name string, got, want []string, calls int) {
	t.Helper()
	if len(want) == 0 {
		t.Fatalf("%s: the server handled nothing", name)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s: parsed %d streams, server handled %d\n got: %q\nwant: %q", name, len(got), len(want), got, want)
	}
	t.Logf("%s: %d streams in %d socket calls parsed as handled", name, len(got), calls)
}

// TestHTTP2RealGoClient: Go's x/net/http2 transport (h2c prior knowledge) against Go's server, concurrent
// requests with header blocks up to 30KB (one frame: the Go server allows 1MB frames), response headers above
// 16KB (CONTINUATION frames towards the client), request and response trailers, small and default tables
func TestHTTP2RealGoClient(t *testing.T) {
	// (the server's decoder table is left at its default: Go's server applies a smaller one before the client saw
	// its SETTINGS and fails the connection with COMPRESSION_ERROR, which is about Go, not about the parser)
	for _, table := range []uint32{64, 4096} {
		t.Run(fmt.Sprintf("table=%d", table), func(t *testing.T) {
			//nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
			server := newH2TestServer(t, &http2.Server{MaxEncoderHeaderTableSize: table})
			proxy := newH2RecordingProxy(t, server.addr)
			//nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
			tr := &http2.Transport{AllowHTTP: true, MaxDecoderHeaderTableSize: table, MaxEncoderHeaderTableSize: 8192,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}}
			client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
			var wg sync.WaitGroup
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					rnd := rand.New(rand.NewSource(int64(g)))
					for i := 0; i < 25; i++ {
						paths := []string{"/api/a", "/status/404", "/bigresp", "/trailers", "/status/503", "/api/b"}
						path := paths[rnd.Intn(len(paths))]
						method, body := "GET", ""
						if i%2 == 1 {
							method, body = "POST", strings.Repeat("p", rnd.Intn(3000))
						}
						req, _ := http.NewRequest(method, fmt.Sprintf("http://%s%s?g=%d&i=%d", proxy.addr(), path, g, i), strings.NewReader(body))
						req.Header.Set("x-i", strings.Repeat(strconv.Itoa(i), rnd.Intn(30000)))
						req.Header.Set("authorization", "secret-"+strconv.Itoa(g))
						if i%5 == 0 && method == "POST" {
							req.Trailer = http.Header{"X-Req-Trailer": {"t"}}
						}
						resp, err := client.Do(req)
						if err != nil {
							t.Errorf("request: %v", err)
							return
						}
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
				}(g)
			}
			wg.Wait()
			tr.CloseIdleConnections() //nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
			time.Sleep(200 * time.Millisecond)
			got, calls := proxy.parse(t, true)
			compareH2(t, "go", got, server.expected(true), calls)
		})
	}
}

// TestHTTP2RealGRPC: grpc-go client and server (health service): unary calls with metadata of varying size,
// trailers, and trailers-only responses (an unknown service answers NotFound in a single HEADERS frame)
func TestHTTP2RealGRPC(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var handled []string
	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		mu.Lock()
		handled = append(handled, "POST "+info.FullMethod+" 200")
		mu.Unlock()
		return h(ctx, req)
	}))
	hs := health.NewServer()
	hs.SetServingStatus("known", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()
	proxy := newH2RecordingProxy(t, ln.Addr().String())

	conn, err := grpc.NewClient("passthrough:///"+proxy.addr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := healthpb.NewHealthClient(conn)
	rnd := rand.New(rand.NewSource(3))
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				mu.Lock()
				size := rnd.Intn(5000)
				mu.Unlock()
				ctx := metadata.AppendToOutgoingContext(context.Background(), "x-meta", strings.Repeat("m", size), "sw8", fmt.Sprintf("1-%d-%d", g, i))
				service := "known"
				if i%4 == 0 {
					service = "unknown"
				}
				_, _ = client.Check(ctx, &healthpb.HealthCheckRequest{Service: service})
			}
		}(g)
	}
	wg.Wait()
	_ = conn.Close()
	time.Sleep(200 * time.Millisecond)
	got, calls := proxy.parse(t, false)
	mu.Lock()
	want := append([]string(nil), handled...)
	mu.Unlock()
	sort.Strings(want)
	compareH2(t, "grpc-go", got, want, calls)
}

func requireTool(t *testing.T, name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return path
}

func runTool(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// TestHTTP2RealExternalClients: curl (libcurl + nghttp2), nghttp (nghttp2 with RFC 7540 priorities and a
// SETTINGS_HEADER_TABLE_SIZE of 0 and 100), Python h2/hpack (never indexed fields, a small table) and Node's
// http2 module, each against Go's h2c server
func TestHTTP2RealExternalClients(t *testing.T) {
	big := strings.Repeat("H", 20000)
	t.Run("curl", func(t *testing.T) {
		curl := requireTool(t, "curl")
		//nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
		server := newH2TestServer(t, &http2.Server{})
		proxy := newH2RecordingProxy(t, server.addr)
		args := []string{"-s", "-o", "/dev/null", "--http2-prior-knowledge", "-H", "x-big: " + big, "-H", "authorization: Bearer x"}
		for i := 0; i < 10; i++ {
			args = append(args, fmt.Sprintf("http://%s/curl/%d?i=%d", proxy.addr(), i%3, i), fmt.Sprintf("http://%s/status/40%d", proxy.addr(), i%5))
		}
		runTool(t, curl, args...)
		runTool(t, curl, "-s", "-o", "/dev/null", "--http2-prior-knowledge", "-d", "payload", "-X", "PUT", "http://"+proxy.addr()+"/bigresp")
		time.Sleep(200 * time.Millisecond)
		got, calls := proxy.parse(t, true)
		compareH2(t, "curl", got, server.expected(true), calls)
	})
	t.Run("nghttp", func(t *testing.T) {
		nghttp := requireTool(t, "nghttp")
		//nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
		server := newH2TestServer(t, &http2.Server{})
		proxy := newH2RecordingProxy(t, server.addr)
		for _, table := range []string{"0", "100", "65536"} {
			args := []string{"-n", "-c", table, "-H", "x-big: " + big, "-H", "cookie: a=1; b=2"}
			for i := 0; i < 6; i++ {
				args = append(args, fmt.Sprintf("http://%s/ng/%d?i=%d", proxy.addr(), i%2, i), fmt.Sprintf("http://%s/trailers/%d", proxy.addr(), i))
			}
			runTool(t, nghttp, args...)
			runTool(t, nghttp, "-n", "-c", table, "-d", "/dev/null", "http://"+proxy.addr()+"/bigresp")
		}
		time.Sleep(200 * time.Millisecond)
		got, calls := proxy.parse(t, true)
		compareH2(t, "nghttp", got, server.expected(true), calls)
	})
	t.Run("python-h2", func(t *testing.T) {
		python := requireTool(t, "python3")
		if exec.Command(python, "-c", "import h2").Run() != nil {
			t.Skip("python h2 is not installed")
		}
		//nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
		server := newH2TestServer(t, &http2.Server{})
		proxy := newH2RecordingProxy(t, server.addr)
		script := filepath.Join(t.TempDir(), "client.py")
		_ = os.WriteFile(script, []byte(h2PythonClient), 0o600)
		host, port, _ := net.SplitHostPort(proxy.addr())
		runTool(t, python, script, host, port)
		time.Sleep(200 * time.Millisecond)
		got, calls := proxy.parse(t, true)
		compareH2(t, "python-h2", got, server.expected(true), calls)
	})
	t.Run("node", func(t *testing.T) {
		node := requireTool(t, "node")
		//nolint:staticcheck // the test drives the x/net HTTP/2 server and transport with their own HPACK table settings
		server := newH2TestServer(t, &http2.Server{})
		proxy := newH2RecordingProxy(t, server.addr)
		script := filepath.Join(t.TempDir(), "client.js")
		_ = os.WriteFile(script, []byte(h2NodeClient), 0o600)
		runTool(t, node, script, "http://"+proxy.addr())
		time.Sleep(200 * time.Millisecond)
		got, calls := proxy.parse(t, true)
		compareH2(t, "node", got, server.expected(true), calls)
	})
}

const h2PythonClient = `
import socket, sys
import h2.connection, h2.config, h2.events, h2.settings
from hpack import NeverIndexedHeaderTuple

s = socket.create_connection((sys.argv[1], int(sys.argv[2])))
c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
c.initiate_connection()
c.update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 256})
s.sendall(c.data_to_send())
for i in range(40):
    sid = c.get_next_available_stream_id()
    path = '/py/%d?i=%d' % (i % 3, i) if i % 7 else '/status/418'
    headers = [(':method', 'POST' if i % 2 else 'GET'), (':scheme', 'http'), (':path', path), (':authority', 'py.test'),
               NeverIndexedHeaderTuple('authorization', 'secret%d' % i), ('x-i', str(i) * (i * 40))]
    body = b'x' * (i * 10) if i % 2 else None
    c.send_headers(sid, headers, end_stream=body is None)
    if body is not None:
        c.send_data(sid, body, end_stream=True)
    s.sendall(c.data_to_send())
    done = False
    while not done:
        data = s.recv(65535)
        if not data:
            break
        for ev in c.receive_data(data):
            if isinstance(ev, h2.events.DataReceived):
                c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            if isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)) and ev.stream_id == sid:
                done = True
        s.sendall(c.data_to_send())
c.close_connection()
s.sendall(c.data_to_send())
s.close()
`

const h2NodeClient = `
const http2 = require('http2');
const c = http2.connect(process.argv[2], {settings: {headerTableSize: 128}});
const N = 40;
let n = 0;
for (let i = 0; i < N; i++) {
  const post = i % 2 === 1;
  const r = c.request({':method': post ? 'POST' : 'GET', ':path': i % 9 === 0 ? '/status/302' : '/node/' + (i % 3) + '?i=' + i,
    'x-i': 'v'.repeat(i * 30), 'authorization': 'tok' + i, 'cookie': 'c=' + i});
  r.on('response', () => {});
  r.resume();
  r.on('close', () => { if (++n === N) c.close(); });
  if (post) { r.end('b'.repeat(i)); } else { r.end(); }
}
`
