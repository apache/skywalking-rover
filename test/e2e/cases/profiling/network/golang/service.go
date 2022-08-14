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
)

func provider(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("service provider\n"))
}

func consumer(w http.ResponseWriter, req *http.Request) {
	addr := "https://proxy/provider"
	get, err := http.Get(addr)
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
	http.HandleFunc("/provider", provider)
	http.HandleFunc("/consumer", consumer)
	err := http.ListenAndServeTLS(":10443", "/ssl_data/service.crt", "/ssl_data/service.key", nil)
	log.Fatal(err)
}
