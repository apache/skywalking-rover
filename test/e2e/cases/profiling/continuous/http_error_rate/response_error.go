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
	"log"
	"math/rand"
	"net/http"
	"os"
)

func provider(w http.ResponseWriter, _ *http.Request) {
	if rand.Float64() > 0.5 {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("success"))
}

func main() {
	// force as http/1.1 server, we only support analyze http1 server for now
	os.Setenv("GODEBUG", "http2server=0")
	http.HandleFunc("/provider", provider)

	err := http.ListenAndServeTLS(":10443", "/ssl_data/service.crt", "/ssl_data/service.key", nil)
	log.Fatal(err)
}
