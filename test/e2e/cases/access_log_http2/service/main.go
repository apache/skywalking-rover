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

// HTTP/2 access log e2e service.
//
// `-mode server` listens with:
//   - :8080 h2c (HTTP/2 cleartext with prior knowledge, HTTP/1.1 is accepted too)
//   - :9090 gRPC (plaintext): e2e.E2EService/{Unary,ServerStream,ClientStream,Fail}
//   - :8443 HTTP/2 over TLS (self signed certificate generated at start up, ALPN h2)
//
// `-mode client` keeps long lived connections to the server and calls every endpoint in a loop,
// so the access log must be parsed from the middle of HPACK-compressed, multiplexed connections.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// rawCodec lets the gRPC service exchange plain byte slices, so no generated protobuf code is needed.
type rawCodec struct{}

func (rawCodec) Marshal(v interface{}) ([]byte, error) {
	switch m := v.(type) {
	case *[]byte:
		return *m, nil
	case []byte:
		return m, nil
	}
	return nil, fmt.Errorf("rawCodec: unsupported type %T", v)
}

func (rawCodec) Unmarshal(data []byte, v interface{}) error {
	m, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec: unsupported type %T", v)
	}
	*m = append((*m)[:0], data...)
	return nil
}

func (rawCodec) Name() string { return "raw" }

const grpcServiceName = "e2e.E2EService"

type e2eServer struct{}

var grpcServiceDesc = grpc.ServiceDesc{
	ServiceName: grpcServiceName,
	HandlerType: (*interface{})(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Unary",
			Handler: func(_ interface{}, _ context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
				var in []byte
				if err := dec(&in); err != nil {
					return nil, err
				}
				out := []byte("unary:" + string(in))
				return &out, nil
			},
		},
		{
			MethodName: "Fail",
			Handler: func(_ interface{}, _ context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
				var in []byte
				if err := dec(&in); err != nil {
					return nil, err
				}
				// a trailers-only response with a non OK grpc-status
				return nil, status.Error(codes.NotFound, "not found: "+string(in))
			},
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ServerStream",
			ServerStreams: true,
			Handler: func(_ interface{}, stream grpc.ServerStream) error {
				var in []byte
				if err := stream.RecvMsg(&in); err != nil {
					return err
				}
				for i := 0; i < 5; i++ {
					out := []byte(fmt.Sprintf("stream:%d:%s", i, in))
					if err := stream.SendMsg(&out); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			StreamName:    "ClientStream",
			ClientStreams: true,
			Handler: func(_ interface{}, stream grpc.ServerStream) error {
				count := 0
				for {
					var in []byte
					if err := stream.RecvMsg(&in); err != nil {
						if err == io.EOF {
							out := []byte(fmt.Sprintf("received:%d", count))
							return stream.SendMsg(&out)
						}
						return err
					}
					count++
				}
			},
		},
	},
}

var payload = bytes.Repeat([]byte("x"), 1024)

func httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/h2c/items", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Protocol", r.Proto)
		_, _ = w.Write([]byte(`{"items":[`))
		_, _ = w.Write(payload)
		_, _ = w.Write([]byte(`]}`))
	})
	mux.HandleFunc("/h2c/missing", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	})
	mux.HandleFunc("/https/items", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	})
	return mux
}

func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "http2-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"http2-server", "http2-server.default", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}))
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

type ports struct {
	h2c, grpc, https string
}

func runServer(p ports) {
	go func() {
		srv := &http.Server{Addr: ":" + p.h2c, Handler: h2c.NewHandler(httpHandler(), &http2.Server{}), ReadHeaderTimeout: 30 * time.Second}
		log.Printf("h2c listening on :%s", p.h2c)
		log.Fatal(srv.ListenAndServe())
	}()
	go func() {
		srv := &http.Server{Addr: ":" + p.https, Handler: httpHandler(), ReadHeaderTimeout: 30 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert()}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}}
		log.Printf("https (h2) listening on :%s", p.https)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()
	listener, err := net.Listen("tcp", ":"+p.grpc)
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))
	server.RegisterService(&grpcServiceDesc, &e2eServer{})
	log.Printf("gRPC listening on :%s", p.grpc)
	log.Fatal(server.Serve(listener))
}

func runClient(target string, p ports, interval, startDelay time.Duration) {
	if startDelay > 0 {
		// the rover discovers a new process within a few seconds; HTTP/2 connections opened before it is
		// attached can never be parsed (the HPACK dynamic table is built from the first frames)
		log.Printf("waiting %s before opening connections", startDelay)
		time.Sleep(startDelay)
	}
	h2cClient := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	httpsClient := &http.Client{Transport: &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, // nolint:gosec
	}}
	conn, err := grpc.NewClient(target+":"+p.grpc, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	for i := 0; ; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		httpCall(h2cClient, http.MethodGet, "http://"+target+":"+p.h2c+"/h2c/items", nil)
		httpCall(h2cClient, http.MethodPost, "http://"+target+":"+p.h2c+"/h2c/items", payload)
		httpCall(h2cClient, http.MethodGet, "http://"+target+":"+p.h2c+"/h2c/missing", nil)
		httpCall(httpsClient, http.MethodGet, "https://"+target+":"+p.https+"/https/items", nil)

		var out []byte
		in := []byte(fmt.Sprintf("call-%d", i))
		if err := conn.Invoke(ctx, "/"+grpcServiceName+"/Unary", &in, &out); err != nil {
			log.Printf("unary failed: %v", err)
		}
		if err := conn.Invoke(ctx, "/"+grpcServiceName+"/Fail", &in, &out); status.Code(err) != codes.NotFound {
			log.Printf("fail should return NotFound, got: %v", err)
		}
		if stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "ServerStream", ServerStreams: true}, "/"+grpcServiceName+"/ServerStream"); err == nil {
			_ = stream.SendMsg(&in)
			_ = stream.CloseSend()
			for {
				var msg []byte
				if err := stream.RecvMsg(&msg); err != nil {
					break
				}
			}
		} else {
			log.Printf("server stream failed: %v", err)
		}
		if stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "ClientStream", ClientStreams: true}, "/"+grpcServiceName+"/ClientStream"); err == nil {
			for j := 0; j < 3; j++ {
				_ = stream.SendMsg(&in)
			}
			_ = stream.CloseSend()
			var msg []byte
			_ = stream.RecvMsg(&msg)
		} else {
			log.Printf("client stream failed: %v", err)
		}
		cancel()
		if i%50 == 0 {
			log.Printf("round %d done", i)
		}
		time.Sleep(interval)
	}
}

func httpCall(client *http.Client, method, url string, body []byte) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("%s %s: %v", method, url, err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s %s: %v", method, url, err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if !strings.HasPrefix(resp.Proto, "HTTP/2") {
		log.Printf("%s %s: unexpected protocol %s", method, url, resp.Proto)
	}
}

func main() {
	mode := flag.String("mode", "server", "server or client")
	target := flag.String("target", "http2-server", "server host (client mode)")
	interval := flag.Duration("interval", 200*time.Millisecond, "pause between client rounds")
	startDelay := flag.Duration("start-delay", 0, "wait before opening the first connection (client mode)")
	var p ports
	flag.StringVar(&p.h2c, "h2c-port", "8080", "h2c port")
	flag.StringVar(&p.grpc, "grpc-port", "9090", "gRPC port")
	flag.StringVar(&p.https, "https-port", "8443", "HTTP/2 over TLS port")
	flag.Parse()
	switch *mode {
	case "server":
		runServer(p)
	case "client":
		runClient(*target, p, *interval, *startDelay)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}
