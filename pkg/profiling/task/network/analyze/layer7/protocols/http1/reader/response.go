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
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

type Response struct {
	*MessageOpt
	req          *Request
	original     *http.Response
	headerBuffer *buffer.Buffer
	bodyBuffer   *buffer.Buffer
}

func (r *Response) Headers() http.Header {
	return r.original.Header
}

func (r *Response) HeaderBuffer() *buffer.Buffer {
	return r.headerBuffer
}

func (r *Response) BodyBuffer() *buffer.Buffer {
	return r.bodyBuffer
}

func (r *Response) Original() *http.Response {
	return r.original
}

func ReadResponse(req *Request, buf *buffer.Buffer, readBody bool) (*Response, enums.ParseResult, error) {
	bufReader := bufio.NewReader(buf)
	tp := textproto.NewReader(bufReader)
	resp := &http.Response{}
	result := &Response{original: resp, req: req}
	result.MessageOpt = &MessageOpt{result}

	headerStartPosition := buf.Position()
	line, err := tp.ReadLine()
	if err != nil {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("read response first line failure: %v", err)
	}
	indexByte := strings.IndexByte(line, ' ')
	if indexByte == -1 {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("parsing response error: %s", line)
	}
	resp.Proto = line[:indexByte]
	resp.Status = strings.TrimLeft(line[indexByte+1:], " ")
	statusCode := resp.Status
	if i := strings.IndexByte(resp.Status, ' '); i != -1 {
		statusCode = resp.Status[:i]
	}
	if len(statusCode) != 3 {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("parsing response status code failure: %v", statusCode)
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil || resp.StatusCode < 0 {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("status code not correct: %s", statusCode)
	}
	var ok bool
	if resp.ProtoMajor, resp.ProtoMinor, ok = http.ParseHTTPVersion(resp.Proto); !ok {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("parsing http version failure: %s", resp.Proto)
	}

	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		result.buildHeaderBuffer(headerStartPosition, buf, bufReader)
		return result, enums.ParseResultSuccess, nil
	}
	resp.Header = http.Header(mimeHeader)

	result.buildHeaderBuffer(headerStartPosition, buf, bufReader)
	if readBody {
		if b, r, err := result.readFullResponseBody(bufReader, buf); err != nil {
			return nil, enums.ParseResultSkipPackage, err
		} else if r != enums.ParseResultSuccess {
			return nil, r, nil
		} else {
			result.bodyBuffer = b
		}
	}

	return result, enums.ParseResultSuccess, nil
}

func (r *Response) buildHeaderBuffer(start *buffer.Position, buf *buffer.Buffer, bufReader *bufio.Reader) {
	endPosition := buf.OffsetPosition(-bufReader.Buffered())
	r.headerBuffer = buf.Slice(true, start, endPosition)
}

func (r *Response) readFullResponseBody(bodyReader *bufio.Reader, original *buffer.Buffer) (*buffer.Buffer, enums.ParseResult, error) {
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
