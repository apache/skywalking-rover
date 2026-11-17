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
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"
)

type fastTestEvent struct {
	dataID, prevDataID uint64
	seq                int
	start, finished    bool
	data               []byte
}

func (e *fastTestEvent) Protocol() enums.ConnectionProtocol { return enums.ConnectionProtocolHTTP }
func (e *fastTestEvent) GenerateConnectionID() string       { return "1" }
func (e *fastTestEvent) BufferData() []byte                 { return e.data }
func (e *fastTestEvent) TotalSize() uint64                  { return uint64(len(e.data)) }
func (e *fastTestEvent) Direction() enums.SocketDataDirection {
	return enums.SocketDataDirectionIngress
}
func (e *fastTestEvent) BufferStartPosition() int       { return 0 }
func (e *fastTestEvent) BufferLen() int                 { return len(e.data) }
func (e *fastTestEvent) DataID() uint64                 { return e.dataID }
func (e *fastTestEvent) PrevDataID() uint64             { return e.prevDataID }
func (e *fastTestEvent) DataSequence() int              { return e.seq }
func (e *fastTestEvent) IsStart() bool                  { return e.start }
func (e *fastTestEvent) IsFinished() bool               { return e.finished }
func (e *fastTestEvent) HaveReduceDataAfterChunk() bool { return false }
func (e *fastTestEvent) StartTime() uint64              { return e.dataID*10 + uint64(e.seq) }
func (e *fastTestEvent) EndTime() uint64                { return e.dataID*10 + uint64(e.seq) + 1 }
func (e *fastTestEvent) ReleaseBuffer() []byte          { return nil }

// buildFastTestBuffer splits the data into events: every byte of splits is one event, its low 6 bits
// (+1) are the size, the high bits pick a new socket call (00), the next chunk of the same call (01), a
// socket call that does not directly follow (10, the reader stops with ErrNotComplete there) or a
// large chunk of 512+ bytes (11). The rest of the data is the last event.
func buildFastTestBuffer(data, splits []byte) *buffer.Buffer {
	b := buffer.NewBuffer()
	var events []*fastTestEvent
	dataID, seq := uint64(0), 0
	add := func(chunk []byte, kind byte) {
		switch {
		case kind == 1 && len(events) > 0:
			events[len(events)-1].finished = false
			seq++
			events = append(events, &fastTestEvent{dataID: dataID, prevDataID: dataID - 1, seq: seq, finished: true, data: chunk})
			return
		case kind == 2:
			dataID += 2
		default:
			dataID++
		}
		seq = 0
		events = append(events, &fastTestEvent{dataID: dataID, prevDataID: dataID - 1, start: kind != 2, finished: true, data: chunk})
	}
	for _, s := range splits {
		if len(data) == 0 {
			break
		}
		size, kind := int(s&0x3f)+1, s>>6
		if kind == 3 {
			size, kind = 512+int(s&0x3f)*16, 0
		}
		if size > len(data) {
			size = len(data)
		}
		add(data[:size], kind)
		data = data[size:]
	}
	if len(data) > 0 {
		add(data, 0)
	}
	for _, e := range events {
		b.AppendDataEvent(e)
	}
	b.PrepareForReading()
	return b
}

// fastTestObservation is everything a user of the reader can observe of one parse step
type fastTestObservation struct {
	Panic        string
	Type         MessageType
	TypeErr      string
	Result       enums.ParseResult
	Err          string
	Request      *fastTestRequest
	Response     *fastTestResponse
	HeaderSize   int64
	BodySize     int64
	TotalSize    int
	StartTime    uint64
	EndTime      uint64
	Content      string
	ContentErr   string
	Position     string
	MinMaxDataID [2]int
	HasBody      bool
}

type fastTestRequest struct {
	Method, RequestURI, Proto, Host string
	ProtoMajor, ProtoMinor          int
	URL                             *url.URL
	Headers                         map[string][]string
	HeaderNil                       bool
}

type fastTestResponse struct {
	Status, Proto          string
	StatusCode             int
	ProtoMajor, ProtoMinor int
	Headers                map[string][]string
	HeaderNil              bool
}

func fastTestHeaders(h map[string][]string) map[string][]string {
	result := make(map[string][]string)
	for _, name := range fastHeaderNames {
		if v, ok := h[name]; ok {
			result[name] = v
		}
	}
	return result
}

func fastTestPosition(buf *buffer.Buffer) string {
	p := buf.Position()
	if !p.HasElement() {
		return fmt.Sprintf("none(%v)", p == nil)
	}
	return fmt.Sprintf("%d/%d/%d", p.DataID(), p.Seq(), p.Offset())
}

// fastTestRun parses the messages of the buffer one after the other as the analyzers do, and returns the
// observations of every step
func fastTestRun(r *Reader, buf *buffer.Buffer, readBody bool) (steps []fastTestObservation) {
	var lastRequest *Request
	for i := 0; i < 16; i++ {
		obs, req, stop := fastTestStep(r, buf, readBody, lastRequest)
		steps = append(steps, obs)
		if req != nil {
			lastRequest = req
		}
		if stop {
			return steps
		}
	}
	return steps
}

func fastTestStep(r *Reader, buf *buffer.Buffer, readBody bool, lastRequest *Request) (obs fastTestObservation, req *Request, stop bool) {
	defer func() {
		if p := recover(); p != nil {
			obs.Panic = fmt.Sprint(p)
			stop = true
		}
	}()
	obs.Position = fastTestPosition(buf)
	var err error
	obs.Type, err = r.IdentityMessageType(buf)
	if err != nil {
		obs.TypeErr = err.Error()
	}
	var message *MessageOpt
	switch obs.Type {
	case MessageTypeRequest:
		req, obs.Result, err = r.ReadRequest(buf, readBody)
		if req != nil {
			o := req.Original()
			obs.Request = &fastTestRequest{Method: o.Method, RequestURI: o.RequestURI, Proto: o.Proto, Host: o.Host,
				ProtoMajor: o.ProtoMajor, ProtoMinor: o.ProtoMinor, URL: o.URL,
				Headers: fastTestHeaders(o.Header), HeaderNil: o.Header == nil}
			obs.MinMaxDataID = [2]int{req.MinDataID(), req.MaxDataID()}
			message = req.MessageOpt
		}
	case MessageTypeResponse:
		var resp *Response
		resp, obs.Result, err = r.ReadResponse(lastRequest, buf, readBody)
		if resp != nil {
			o := resp.Original() //nolint:bodyclose // the response is parsed from captured socket data, it has no body to close
			obs.Response = &fastTestResponse{Status: o.Status, Proto: o.Proto, StatusCode: o.StatusCode,
				ProtoMajor: o.ProtoMajor, ProtoMinor: o.ProtoMinor, Headers: fastTestHeaders(o.Header), HeaderNil: o.Header == nil}
			obs.HasBody = resp.HasBody()
			message = resp.MessageOpt
		}
	default:
		return obs, nil, true
	}
	if err != nil {
		obs.Err = err.Error()
	}
	obs.Position += " -> " + fastTestPosition(buf)
	if message == nil {
		return obs, req, true
	}
	if message.HeaderBuffer() != nil {
		obs.HeaderSize = message.HeaderBuffer().DataSize()
		obs.StartTime = message.StartTime()
	}
	if message.BodyBuffer() != nil {
		obs.BodySize = message.BodyBuffer().DataSize()
		obs.TotalSize = message.ContentTotalSize()
		obs.EndTime = message.EndTime()
	}
	if message.HeaderBuffer() != nil && message.BodyBuffer() != nil {
		content, err := message.TransformReadableContent("utf-8", 0)
		obs.Content = content
		if err != nil {
			obs.ContentErr = err.Error()
		}
	}
	return obs, req, false
}

// fastTestCompare runs the fast reader and the textproto reader over the same input and fails on any
// difference of what a user of the reader observes
func fastTestCompare(t testing.TB, data, splits []byte, readBody bool) {
	fast := fastTestRun(NewReader(), buildFastTestBuffer(data, splits), readBody)
	reference := NewReader()
	reference.textprotoOnly = true
	expected := fastTestRun(reference, buildFastTestBuffer(data, splits), readBody)
	if !reflect.DeepEqual(fast, expected) {
		fastJSON, _ := json.Marshal(fast)
		expectedJSON, _ := json.Marshal(expected)
		t.Fatalf("the fast reader differs from textproto for %q (splits %v, read body %v):\nfast:      %s\ntextproto: %s",
			data, splits, readBody, fastJSON, expectedJSON)
	}
}

func fastTestGzip(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = io.WriteString(w, s)
	_ = w.Close()
	return b.String()
}

var fastTestSeeds = []string{
	"GET /api/users?id=1&name=x HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
	"POST /submit HTTP/1.1\r\nHost: svc:8080\r\nContent-Type: application/json\r\nContent-Length: 13\r\n" +
		"sw8: 1-MWYyZDRiZjQ3YmY3MTFlYWI3OTRhY2RlNDgwMDExMjI=-MWU3YzIwNGE3YmY3MTFlYWI4NThhY2RlNDgwMDExMjI=-0-c2VydmljZQ==-aW5zdGFuY2U=-L2FwcA==-MTI3LjAuMC4xOjgwODA=\r\n\r\n{\"a\":\"hello\"}",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html; charset=utf-8\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
	"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET /a HTTP/1.1\r\nHost: h\r\nb3: 80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n" +
		"X-B3-TraceId: 463ac35c9f6413ad48485a3953bb6124\r\nX-B3-SpanId: a2fb4a1d1a96d312\r\n\r\n",
	"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\nHTTP/1.0 304 Not Modified\r\n\r\n",
	"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: " +
		fmt.Sprint(len(fastTestGzip("compressed body"))) + "\r\n\r\n" + fastTestGzip("compressed body"),
	"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Length: 3\r\n\r\n\xe9t\xe9",
	"GET /fold HTTP/1.1\r\nHost: h\r\nX-Long: a\r\n  continued\r\n\r\n",
	"GET /lf HTTP/1.1\nHost: h\nContent-Length: 0\n\n",
	"GET /dup HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
	"GET /case HTTP/1.1\r\nhOsT:   spaced.example  \r\ncontent-LENGTH:2\r\nSW8:\t\r\n\r\nok",
	"GET /bad HTTP/1.1\r\nHost : h\r\n\r\n",
	"GET /bad HTTP/1.1\r\nNo-Colon\r\n\r\n",
	"GET /bad HTTP/1.1\r\n: empty-key\r\n\r\n",
	"GET /bad HTTP/1.1\r\nX-Ctl: a\x01b\r\n\r\n",
	"GET /bad HTTP/1.1\r\nX-Cr: a\rb\r\n\r\n",
	"GET /utf HTTP/1.1\r\nX-Utf: caf\xc3\xa9\r\nHost: h\r\n\r\n",
	"HTTP/1.1 200 OK\r\n Leading: space\r\n\r\n",
	"HTTP/1.1 500 Internal Server Error\r\nContent-Length: abc\r\n\r\n",
	"HTTP/1.1 404 Not Found\r\nContent-Length: -1\r\n\r\n",
	"HTTP/1.1 2000 OK\r\n\r\n",
	"HTTP/2.0 200 OK\r\n\r\n",
	"HTTP/1.1 200\r\n\r\n",
	"HTTP/1.1   201   Created\r\nContent-Length: 0\r\n\r\n",
	"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n",
	"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET http://proxy.example/x?y=1 HTTP/1.1\r\nHost: other\r\n\r\n",
	"GET /p%20ath/%E4%B8%AD?q=%zz HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET /bad%zz HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET /force? HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET //double/slash HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET /a;b=c,d@e:f!g*h'(i)~j HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET /x#frag HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET /x HTTP/1.1 extra\r\nHost: h\r\n\r\n",
	"GET /x HTTP/1.2\r\nHost: h\r\n\r\n",
	"GETX /x HTTP/1.1\r\n\r\n",
	"DELETE  /x HTTP/1.1\r\n\r\n",
	"HEAD /h HTTP/1.1\r\nHost: h\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n",
	"PUT /up HTTP/1.1\r\nHost: h\r\nContent-Length: 20\r\n\r\nshort",
	"PATCH /p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
	"TRACE /t HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n",
	"GET /incomplete HTTP/1.1\r\nHost: h\r\nX-Partial: abc",
	"GET /incomplete HTTP/1.1\r\nHost: h\r\n",
	"GET /x HTTP/1.1\r\n" + "X-Big: " + strings.Repeat("v", 5000) + "\r\nHost: h\r\n\r\n",
	"GET /" + strings.Repeat("p", 4200) + " HTTP/1.1\r\nHost: h\r\n\r\n",
	"GET /tab HTTP/1.1\r\nHost:\th\t\r\nX-Tab: a\tb\r\n\r\n",
	"GET /cr HTTP/1.1\r\r\nHost: h\r\n\r\n",
	"GET /nul HTTP/1.1\r\nHo\x00st: h\r\n\r\n",
	"GET /blank-cr HTTP/1.1\r\nHost: h\r\n\r\r\n\r\n",
	"\r\nGET /leading HTTP/1.1\r\n\r\n",
}

var fastTestSplits = [][]byte{
	nil,
	{0x3f},
	{0x05, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45},
	{0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f},
	{0x10, 0x90, 0x10},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0xc0, 0x41},
	{0x20, 0x81},
}

// TestFastReaderMatchesTextproto: the fast scanner must yield what textproto yields for every message,
// split into socket events in every way
func TestFastReaderMatchesTextproto(t *testing.T) {
	for _, seed := range fastTestSeeds {
		for _, splits := range fastTestSplits {
			for _, readBody := range []bool{true, false} {
				fastTestCompare(t, []byte(seed), splits, readBody)
			}
		}
		// every single split point
		for i := 1; i < len(seed) && i < 300; i++ {
			fastTestCompare(t, []byte(seed), fastTestSplitAt(i), true)
		}
	}
}

func fastTestSplitAt(n int) []byte {
	var splits []byte
	for n > 64 {
		splits = append(splits, 0x7f)
		n -= 64
	}
	return append(splits, byte(n-1))
}

// TestFastReaderTakesThePlainMessages: the plain messages must not fall back to textproto
func TestFastReaderTakesThePlainMessages(t *testing.T) {
	for _, s := range []string{fastTestSeeds[0], fastTestSeeds[2], fastTestSeeds[5], fastTestSeeds[12]} {
		if readRequestHeadFast(newPooledReaderFromBuffer(buildFastTestBuffer([]byte(s), nil))) == nil {
			t.Fatalf("the request fell back to textproto: %q", s)
		}
	}
	for _, s := range []string{fastTestSeeds[3], fastTestSeeds[7], fastTestSeeds[25]} {
		//nolint:bodyclose // the response is parsed from captured socket data, it has no body to close
		if readResponseHeadFast(newPooledReaderFromBuffer(buildFastTestBuffer([]byte(s), nil))) == nil {
			t.Fatalf("the response fell back to textproto: %q", s)
		}
	}
}

func FuzzHTTP1Reader(f *testing.F) {
	for _, seed := range fastTestSeeds {
		for i, splits := range fastTestSplits {
			f.Add([]byte(seed), splits, uint8(i))
		}
	}
	f.Fuzz(func(t *testing.T, data, splits []byte, mode uint8) {
		if len(data) > 16384 || len(splits) > 256 {
			return
		}
		fastTestCompare(t, data, splits, mode&1 == 0)
	})
}

// TestFastHeadersKeepTheTracingHeaders: every header the tracing context is analyzed from is kept by the fast
// scanner, or the access log would lose the context of the requests it scans
func TestFastHeadersKeepTheTracingHeaders(t *testing.T) {
	asked := map[string]bool{}
	_, _ = tracing.AnalyzeTracingContext(func(key string) string {
		asked[key] = true
		// a value for each one, so every header of every provider is asked for
		if key == tracing.HeaderSW8 || key == tracing.HeaderB3 {
			return ""
		}
		return "x"
	})
	for _, extra := range []string{tracing.HeaderSW8, tracing.HeaderB3, tracing.HeaderB3TraceID, tracing.HeaderB3SpanID} {
		asked[extra] = true
	}
	for key := range asked {
		kept := false
		for _, name := range fastHeaderNames {
			if name == http.CanonicalHeaderKey(key) {
				kept = true
			}
		}
		if !kept {
			t.Fatalf("the tracing header %s is not kept by the fast scanner", key)
		}
	}
}
