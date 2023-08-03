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

package reader

import (
	"bufio"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/buffer"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/enums"
)

type Request struct {
	*MessageOpt
	original     *http.Request
	headerBuffer *buffer.Buffer
	bodyBuffer   *buffer.Buffer
}

func (r *Request) Headers() http.Header {
	return r.original.Header
}

func (r *Request) HeaderBuffer() *buffer.Buffer {
	return r.headerBuffer
}

func (r *Request) BodyBuffer() *buffer.Buffer {
	return r.bodyBuffer
}

func (r *Request) MinDataID() int {
	return int(r.headerBuffer.FirstSocketBuffer().DataID())
}

func (r *Request) Original() *http.Request {
	return r.original
}

//nolint
func ReadRequest(buf *buffer.Buffer, readBody bool) (*Request, enums.ParseResult, error) {
	bufReader := bufio.NewReader(buf)
	tp := textproto.NewReader(bufReader)
	req := &http.Request{}
	result := &Request{original: req}
	result.MessageOpt = &MessageOpt{result}

	headerStartPosition := buf.Position()
	line, err := tp.ReadLine()
	if err != nil {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("read request first lint failure: %v", err)
	}
	method, rest, ok1 := strings.Cut(line, " ")
	requestURI, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("the first line is not request: %s", line)
	}

	isRequest := false
	for _, m := range requestMethods {
		if method == m {
			isRequest = true
			break
		}
	}
	if !isRequest {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("is not request: %s", method)
	}
	major, minor, ok := http.ParseHTTPVersion(proto)
	if !ok {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("the protocol version cannot be identity: %s", proto)
	}
	justAuthority := req.Method == "CONNECT" && !strings.HasPrefix(requestURI, "/")
	if justAuthority {
		requestURI = "http://" + requestURI
	}
	uri, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return nil, enums.ParseResultSkipPackage, err
	}
	req.Method, req.URL, req.RequestURI = method, uri, requestURI
	req.Proto, req.ProtoMajor, req.ProtoMinor = proto, major, minor

	// header reader
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, enums.ParseResultSkipPackage, err
	}
	req.Header = http.Header(mimeHeader)

	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = req.Header.Get("Host")
	}

	result.buildHeaderBuffer(headerStartPosition, buf, bufReader)
	if readBody {
		if b, r, err := result.readFullBody(bufReader, buf); err != nil {
			return nil, enums.ParseResultSkipPackage, err
		} else if r != enums.ParseResultSuccess {
			return nil, r, nil
		} else {
			result.bodyBuffer = b
		}
	}

	return result, enums.ParseResultSuccess, nil
}

func (r *Request) buildHeaderBuffer(start *buffer.Position, buf *buffer.Buffer, bufReader *bufio.Reader) {
	endPosition := buf.OffsetPosition(-bufReader.Buffered())
	r.headerBuffer = buf.Slice(true, start, endPosition)
}

func (r *Request) readFullBody(bodyReader *bufio.Reader, original *buffer.Buffer) (*buffer.Buffer, enums.ParseResult, error) {
	length, err := r.appointedLength()
	if err != nil {
		return nil, enums.ParseResultSkipPackage, err
	} else if length > 0 {
		return r.checkBodyWithSize(original, bodyReader, length, true)
	}

	if r.isChunked() {
		return r.checkChunkedBody(original, bodyReader)
	}

	return r.readBodyUntilCurrentPackageFinished(original, bodyReader)
}
