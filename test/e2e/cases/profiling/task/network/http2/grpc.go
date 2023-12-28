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

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"test/service"
	"time"

	"google.golang.org/grpc/credentials"

	"google.golang.org/grpc"
)

var (
	httpPort = 8080
	gRPCPort = 9000
	gRPCConn *grpc.ClientConn
)

type Provider struct {
	service.UnimplementedServiceServer
}

func singleCall(w http.ResponseWriter, req *http.Request) {
	log.Printf("receive the single call request")
	if gRPCConn == nil {
		c, err := credentials.NewClientTLSFromFile("/ssl_data/proxy.crt", "proxy")
		if err != nil {
			log.Fatalf("credentials.NewClientTLSFromFile err: %v", err)
		}

		dial, err := grpc.Dial(fmt.Sprintf("proxy.default:%d", gRPCPort), grpc.WithTransportCredentials(c))
		if err != nil {
			log.Printf("init gRPC client failure: %v", err)
			_, _ = w.Write([]byte("error"))
			return
		}
		gRPCConn = dial
	}

	client := service.NewServiceClient(gRPCConn)
	resp, err := client.SingleCall(context.Background(), &service.CallRequest{})
	if err != nil {
		log.Printf("send single call request failure: %v", err)
		_, _ = w.Write([]byte("error"))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(resp.Message))
}

func (p *Provider) SingleCall(context.Context, *service.CallRequest) (*service.CallReply, error) {
	time.Sleep(time.Second * 2)
	return &service.CallReply{Message: "response success"}, nil
}

func main() {
	c, err := credentials.NewServerTLSFromFile("/ssl_data/service.crt", "/ssl_data/service.key")
	if err != nil {
		log.Fatalf("credentials.NewServerTLSFromFile err: %v", err)
	}
	server := grpc.NewServer(grpc.Creds(c))
	service.RegisterServiceServer(server, &Provider{})
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", gRPCPort))
	if err != nil {
		log.Fatalf("listen gRPC port failure: %v", err)
		return
	}
	go func() {
		if err := server.Serve(listen); err != nil {
			log.Fatalf("startup gRPC server failure")
		}
	}()

	http.HandleFunc("/singleCall", singleCall)
	err1 := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil)
	log.Fatal(err1)
}
