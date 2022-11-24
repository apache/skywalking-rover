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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/SkyAPM/go2sky"
	"github.com/SkyAPM/go2sky/reporter"

	"github.com/openzipkin/zipkin-go"
	zipkinhttp "github.com/openzipkin/zipkin-go/middleware/http"
	zipkin_reporter "github.com/openzipkin/zipkin-go/reporter/http"
)

var skyWalkingTracer *go2sky.Tracer
var zipkinTracer *zipkin.Tracer

func provider(w http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Second * 1)
	if req.URL.Query().Get("error") == "true" {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("service provider\n"))
}

func consumer(w http.ResponseWriter, req *http.Request) {
	typeData := req.URL.Query().Get("type")
	addr := "https://proxy/provider"
	if typeData == "notfound" {
		addr = "https://proxy/notfound"
	} else if typeData == "error" {
		addr = "https://proxy/provider?error=true"
	}

	request, err := http.NewRequest("GET", addr, nil)
	exitSpan, err := skyWalkingTracer.CreateExitSpan(req.Context(), "/provider", addr, func(headerKey, headerValue string) error {
		request.Header.Set(headerKey, headerValue)
		return nil
	})
	get, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Printf("send request error: %v", err)
	}
	all, err := ioutil.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		log.Printf("get response body error: %v", err)
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(all)
	exitSpan.End()
}

func providerZipkin(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	time.Sleep(time.Second * 2)
	_, _ = w.Write([]byte("service provider zipkin\n"))
}

func consumerZipkin(w http.ResponseWriter, req *http.Request) {
	addr := "https://proxy/provider-zipkin"
	request, err := http.NewRequest("GET", addr, nil)
	client, err := zipkinhttp.NewClient(zipkinTracer, zipkinhttp.ClientTrace(true))
	if err != nil {
		log.Fatalf("unable to create client: %+v\n", err)
	}
	get, err := client.Do(request)
	if err != nil {
		log.Printf("send request error: %v", err)
	}
	all, err := ioutil.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		log.Printf("get response body error: %v", err)
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(all)
}

func main() {
	// init skywalking tracer
	r, err := reporter.NewGRPCReporter(os.Getenv("OAP_BACKEND_ADDR"))
	if err != nil {
		log.Fatalf("new reporter error %v \n", err)
	}
	defer r.Close()
	skyWalkingTracer, err = go2sky.NewTracer("example", go2sky.WithReporter(r))
	if err != nil {
		log.Fatalf("init skyWalkingTracer failure: %v", err)
	}

	// init zipkin tracer
	zipkinReporter := zipkin_reporter.NewReporter(os.Getenv("ZIPKIN_BACKEND_ADDR"))
	// create our local service endpoint
	endpoint, err := zipkin.NewEndpoint("zipkin-service", "localhost:0")
	if err != nil {
		log.Fatalf("unable to create local endpoint: %+v\n", err)
	}
	// initialize our tracer
	zipkinTracer, err = zipkin.NewTracer(zipkinReporter, zipkin.WithLocalEndpoint(endpoint))
	if err != nil {
		log.Fatalf("unable to create tracer: %+v\n", err)
	}

	http.HandleFunc("/provider", provider)
	http.HandleFunc("/consumer", consumer)

	http.HandleFunc("/consumer-zipkin", consumerZipkin)
	http.HandleFunc("/provider-zipkin", providerZipkin)
	err = http.ListenAndServeTLS(":10443", "/ssl_data/service.crt", "/ssl_data/service.key", nil)
	log.Fatal(err)
}
