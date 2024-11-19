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

import v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

// TransformHTTPMethod transforms the http method to the v3.AccessLogHTTPProtocolRequestMethod
func TransformHTTPMethod(method string) v3.AccessLogHTTPProtocolRequestMethod {
	switch method {
	case "GET":
		return v3.AccessLogHTTPProtocolRequestMethod_Get
	case "POST":
		return v3.AccessLogHTTPProtocolRequestMethod_Post
	case "PUT":
		return v3.AccessLogHTTPProtocolRequestMethod_Put
	case "DELETE":
		return v3.AccessLogHTTPProtocolRequestMethod_Delete
	case "HEAD":
		return v3.AccessLogHTTPProtocolRequestMethod_Head
	case "OPTIONS":
		return v3.AccessLogHTTPProtocolRequestMethod_Options
	case "TRACE":
		return v3.AccessLogHTTPProtocolRequestMethod_Trace
	case "CONNECT":
		return v3.AccessLogHTTPProtocolRequestMethod_Connect
	case "PATCH":
		return v3.AccessLogHTTPProtocolRequestMethod_Patch
	}
	http1Log.Warnf("unknown http method: %s", method)
	return v3.AccessLogHTTPProtocolRequestMethod_Get
}
