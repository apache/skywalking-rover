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
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/tracing"
)

// The fast header scanner parses the start line and the header lines of a message straight from the
// bufio buffer (bufio.Reader.ReadSlice, no copy of the lines) and keeps only the headers the agent reads
// (fastHeaderNames). It accepts only the plain shape of a message: every line it is not sure about makes
// it give up, and the message is parsed again from its start with net/textproto (readRequestHeadTextproto
// and readResponseHeadTextproto), so the results are those of textproto for every input.
//
// The bufio reader fills in the same way as with textproto (a fill happens only when the buffered data
// holds no complete line, from the same reader state), so the reading positions after the headers and
// the body reading behind them are the same as well.

// fastHeaderNames are the headers kept by the fast scanner, in their canonical form (http.Header keys).
// Every header a user of Message.Headers() reads must be listed here: Host (access log), the body framing
// (Content-Length, Transfer-Encoding), the body decoding of the profiling sampling (Content-Type,
// Content-Encoding), the tracing context (tracing.AnalyzeTracingContext) and the h2c upgrade of the access log (Upgrade,
// HTTP2-Settings: the HTTP/2 parser reads them from the request once its head bytes may have been released).
var fastHeaderNames = [...]string{
	hostHeader:             "Host",
	contentLengthHeader:    "Content-Length",
	transferEncodingHeader: "Transfer-Encoding",
	"Content-Type",
	"Content-Encoding",
	"Upgrade",
	http.CanonicalHeaderKey("HTTP2-Settings"),
	http.CanonicalHeaderKey(tracing.HeaderSW8),
	http.CanonicalHeaderKey(tracing.HeaderB3),
	http.CanonicalHeaderKey(tracing.HeaderB3TraceID),
	http.CanonicalHeaderKey(tracing.HeaderB3SpanID),
}

// maxFastKeptHeaders is the most header lines of fastHeaderNames the fast scanner keeps of a message,
// more go to textproto
const maxFastKeptHeaders = 16

// indexes of fastHeaderNames
const (
	hostHeader = iota
	contentLengthHeader
	transferEncodingHeader
)

// fastSingleHeaders must not repeat in a message for the fast scanner (the body framing), by index
var fastSingleHeaders = [len(fastHeaderNames)]bool{contentLengthHeader: true, transferEncodingHeader: true}

// pathSafeBytes are the bytes a request path keeps as they are in url.ParseRequestURI: no unescaping
// and no escaping difference (URL.RawPath stays empty)
var pathSafeBytes = func() (safe [256]bool) {
	for c := 0x21; c < 0x7f; c++ {
		if c == '%' || c == '?' {
			continue
		}
		p := "/" + string(rune(c))
		if (&url.URL{Path: p}).EscapedPath() == p {
			safe[c] = true
		}
	}
	return safe
}()

// rewindForTextproto moves the buffer back to the start of the message for the textproto parsing.
// Reading the buffer has no side effect besides the position, so the textproto parsing reads exactly
// what it would have read without the fast scanner.
func rewindForTextproto(buf *buffer.Buffer, start *buffer.Position, bufReader *bufio.Reader) {
	buf.SetPosition(start)
	bufReader.Reset(buf)
}

// readFastLine reads a complete line and elides the final \n or \r\n as bufio.Reader.ReadLine does.
// The line is only valid until the next read. False when the line is not complete in the buffer or
// longer than the bufio buffer (textproto handles these cases).
func readFastLine(bufReader *bufio.Reader) ([]byte, bool) {
	line, err := bufReader.ReadSlice('\n')
	if err != nil {
		return nil, false
	}
	line = line[:len(line)-1]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, true
}

// readRequestHeadFast is readRequestHeadTextproto for the plain requests, nil when the request has to be
// parsed by textproto
func readRequestHeadFast(bufReader *bufio.Reader) *http.Request {
	line, ok := readFastLine(bufReader)
	if !ok {
		return nil
	}
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 < 0 {
		return nil
	}
	method := fastRequestMethod(string(line[:sp1]))
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if method == "" || sp2 < 0 {
		return nil
	}
	proto, major, minor := fastHTTPVersion(rest[sp2+1:])
	if proto == "" {
		return nil
	}
	requestURI := string(rest[:sp2])
	uri := parseOriginFormURI(requestURI)
	if uri == nil {
		var err error
		if uri, err = url.ParseRequestURI(requestURI); err != nil {
			return nil
		}
	}
	header, host, ok := readHeadersFast(bufReader)
	if !ok {
		return nil
	}
	req := &http.Request{
		Method:     method,
		URL:        uri,
		RequestURI: requestURI,
		Proto:      proto,
		ProtoMajor: major,
		ProtoMinor: minor,
		Header:     header,
		Host:       uri.Host,
	}
	if req.Host == "" {
		req.Host = host
	}
	return req
}

// readResponseHeadFast is readResponseHeadTextproto for the plain responses, nil when the response has
// to be parsed by textproto
func readResponseHeadFast(bufReader *bufio.Reader) *http.Response {
	lineBytes, ok := readFastLine(bufReader)
	if !ok {
		return nil
	}
	sp := bytes.IndexByte(lineBytes, ' ')
	if sp < 0 {
		return nil
	}
	proto, major, minor := fastHTTPVersion(lineBytes[:sp])
	if proto == "" {
		return nil
	}
	status, code, err := parseStatus(string(lineBytes[sp+1:]))
	if err != nil {
		return nil
	}
	header, _, ok := readHeadersFast(bufReader)
	if !ok {
		return nil
	}
	return &http.Response{
		Status:     status,
		StatusCode: code,
		Proto:      proto,
		ProtoMajor: major,
		ProtoMinor: minor,
		Header:     header,
	}
}

// parseStatus parses the status of a response line, what follows the version and its space
func parseStatus(rest string) (status string, code int, err error) {
	status = strings.TrimLeft(rest, " ")
	statusCode := status
	if i := strings.IndexByte(status, ' '); i != -1 {
		statusCode = status[:i]
	}
	if len(statusCode) != 3 {
		return "", 0, fmt.Errorf("parsing response status code failure: %v", statusCode)
	}
	if code, err = strconv.Atoi(statusCode); err != nil || code < 0 {
		return "", 0, fmt.Errorf("status code not correct: %s", statusCode)
	}
	return status, code, nil
}

// fastRequestMethod returns the method (one of requestMethods), "" for any other
func fastRequestMethod(method string) string {
	for _, m := range requestMethods {
		if method == m {
			return m
		}
	}
	return ""
}

// fastHTTPVersion recognizes HTTP/1.1 and HTTP/1.0, proto is "" for any other version (textproto path)
func fastHTTPVersion(b []byte) (proto string, major, minor int) {
	switch string(b) {
	case "HTTP/1.1":
		return "HTTP/1.1", 1, 1
	case "HTTP/1.0":
		return "HTTP/1.0", 1, 0
	}
	return "", 0, 0
}

// parseOriginFormURI is url.ParseRequestURI for a plain origin-form request target: an absolute path
// of bytes that need no unescaping and an optional query. Nil for any other target.
func parseOriginFormURI(requestURI string) *url.URL {
	if len(requestURI) == 0 || requestURI[0] != '/' || (len(requestURI) > 1 && requestURI[1] == '/') {
		return nil
	}
	path, query := requestURI, ""
	if i := strings.IndexByte(requestURI, '?'); i >= 0 {
		if i == len(requestURI)-1 {
			// a single trailing '?' is URL.ForceQuery
			return nil
		}
		path, query = requestURI[:i], requestURI[i+1:]
		for j := 0; j < len(query); j++ {
			if c := query[j]; c <= ' ' || c >= 0x7f {
				return nil
			}
		}
	}
	for j := 0; j < len(path); j++ {
		if !pathSafeBytes[path[j]] {
			return nil
		}
	}
	return &url.URL{Path: path, RawQuery: query}
}

// readHeadersFast reads the header lines up to the blank line and keeps the fastHeaderNames, as
// textproto.Reader.ReadMIMEHeader would have them. False on anything unusual: an obs-fold continuation
// line, a key that is not a token (or with a space before the colon), a missing colon, a control or
// non-ASCII byte in a value (a CR without LF included), a repeated framing header, an incomplete or
// too long line. host is the first Host value.
func readHeadersFast(bufReader *bufio.Reader) (header http.Header, host string, ok bool) {
	// the kept values are collected in one scratch buffer (on the stack while it is small enough) and
	// turned into a single string at the end: one allocation for all values instead of one per value
	var scratchArray [512]byte
	var kept [maxFastKeptHeaders]struct {
		name, start, end int
	}
	scratch, keptCount, hostAt := scratchArray[:0], 0, -1
	for {
		line, ok := readFastLine(bufReader)
		if !ok {
			return nil, "", false
		}
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			// obs-fold (or a leading space on the first line)
			return nil, "", false
		}
		colon := -1
		for i, c := range line {
			if c == ':' {
				colon = i
				break
			}
			if !tokenBytes[c] {
				return nil, "", false
			}
		}
		if colon <= 0 {
			return nil, "", false
		}
		value := line[colon+1:]
		for _, c := range value {
			if (c < ' ' && c != '\t') || c >= 0x7f {
				return nil, "", false
			}
		}
		name := fastHeaderName(line[:colon])
		if name < 0 {
			continue
		}
		if keptCount == len(kept) {
			return nil, "", false
		}
		if fastSingleHeaders[name] {
			for i := 0; i < keptCount; i++ {
				if kept[i].name == name {
					return nil, "", false
				}
			}
		}
		if name == hostHeader && hostAt < 0 {
			hostAt = keptCount
		}
		start := len(scratch)
		scratch = append(scratch, trimSpaceAndTab(value)...)
		kept[keptCount].name, kept[keptCount].start, kept[keptCount].end = name, start, len(scratch)
		keptCount++
	}

	header = make(http.Header, keptCount)
	if keptCount == 0 {
		return header, "", true
	}
	all := string(scratch)
	// one backing array for the first values (most headers are single-valued), capacity 1 so an append
	// of a repeated header does not run into the value of another header
	values := make([]string, keptCount)
	for i := 0; i < keptCount; i++ {
		v, name := all[kept[i].start:kept[i].end], fastHeaderNames[kept[i].name]
		if existing, exists := header[name]; exists {
			header[name] = append(existing, v)
			continue
		}
		values[i] = v
		header[name] = values[i : i+1 : i+1]
	}
	if hostAt >= 0 {
		host = values[hostAt]
	}
	return header, host, true
}

// fastHeaderName returns the index in fastHeaderNames of the key (a token key canonicalizes to a name
// exactly when it equals it ignoring ASCII case), -1 when it is none of them
func fastHeaderName(key []byte) int {
	for i, name := range fastHeaderNames {
		if len(name) == len(key) && asciiEqualFold(key, name) {
			return i
		}
	}
	return -1
}

func asciiEqualFold(b []byte, s string) bool {
	for i := 0; i < len(b); i++ {
		c, d := b[i], s[i]
		if c == d {
			continue
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if 'A' <= d && d <= 'Z' {
			d += 'a' - 'A'
		}
		if c != d {
			return false
		}
	}
	return true
}

func trimSpaceAndTab(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

// tokenBytes are the tchar of RFC 7230 (the valid header field name bytes of textproto)
var tokenBytes = func() (token [256]bool) {
	for c := 0; c < 256; c++ {
		token[c] = 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", byte(c)) >= 0
	}
	return token
}()
