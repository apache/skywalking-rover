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
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	"golang.org/x/net/html/charset"
)

var (
	requestMethods = []string{
		"GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "CONNECT", "TRACE", "PATCH",
	}
)

var log = logger.GetLogger("profiling", "task", "network", "layer7", "protocols", "http1", "reader")

type MessageType int

const (
	MessageTypeRequest MessageType = iota
	MessageTypeResponse
	MessageTypeUnknown
)

type Reader struct {
	headBuffer []byte
	bodyBuffer []byte
}

func NewReader() *Reader {
	return &Reader{
		headBuffer: make([]byte, 16),
		bodyBuffer: make([]byte, 4096),
	}
}

func (r *Reader) IdentityMessageType(reader *buffer.Buffer) (MessageType, error) {
	n, err := reader.Peek(r.headBuffer)
	if err != nil {
		return MessageTypeUnknown, err
	} else if n != len(r.headBuffer) {
		return MessageTypeUnknown, fmt.Errorf("need more content for header")
	}

	headerString := string(r.headBuffer)
	isRequest := false
	for _, method := range requestMethods {
		if strings.HasPrefix(headerString, method) {
			isRequest = true
			break
		}
	}
	if isRequest {
		return MessageTypeRequest, nil
	}

	if strings.HasPrefix(headerString, "HTTP") {
		return MessageTypeResponse, nil
	}
	return MessageTypeUnknown, nil
}

type Message interface {
	Headers() http.Header
	HeaderBuffer() *buffer.Buffer
	BodyBuffer() *buffer.Buffer
	Reader() *Reader
}

type MessageOpt struct {
	Message
}

func (m *MessageOpt) ContentTotalSize() int {
	return m.HeaderBuffer().Len() + m.BodyBuffer().Len()
}

func (m *MessageOpt) StartTime() uint64 {
	return m.HeaderBuffer().FirstSocketBuffer().StartTime()
}

func (m *MessageOpt) EndTime() uint64 {
	return m.BodyBuffer().LastSocketBuffer().EndTime()
}

func (m *MessageOpt) Direction() enums.SocketDataDirection {
	return m.HeaderBuffer().FirstSocketBuffer().Direction()
}

// nolint
func (m *MessageOpt) TransformReadableContent(defaultEncoding string, maxSize int) (string, error) {
	contentType := m.Headers().Get("Content-Type")
	if contentType == "" {
		contentType = fmt.Sprintf("text/html; charset=%s", defaultEncoding)
	}
	isPlain := strings.HasPrefix(contentType, "text/") || contentType == "application/json"

	// header to string
	headerBuf, err := io.ReadAll(m.HeaderBuffer())
	if err != nil {
		return "", err
	}
	if maxSize > 0 && len(headerBuf) >= maxSize {
		return string(headerBuf[:maxSize]), nil
	}
	headerString := string(headerBuf)
	if !isPlain {
		return fmt.Sprintf("%s[not plain, current content type: %s]", headerString, contentType), nil
	}

	// body to string
	bodyLength := m.BodyBuffer().Len()
	if bodyLength == 0 {
		return headerString, nil
	}
	bodyReader, err := m.buildBodyReader(defaultEncoding)
	if err != nil {
		return "", err
	}

	bodyData, err := io.ReadAll(bodyReader)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}
	resultSize := len(bodyData)
	if maxSize > 0 && (resultSize+len(headerString)) > maxSize {
		resultSize = maxSize - len(headerString)
	}
	return fmt.Sprintf("%s%s", headerString, string(bodyData[0:resultSize])), nil
}

func (m *MessageOpt) buildBodyReader(contentType string) (io.Reader, error) {
	var needGzip = m.Headers().Get("Content-Encoding") == "gzip"
	var isUtf8 = true
	if _, params, err := mime.ParseMediaType(contentType); err == nil {
		if cs, ok := params["charset"]; ok {
			isUtf8 = strings.EqualFold(cs, "utf-8")
		}
	}

	var data io.Reader = m.BodyBuffer()
	var err error
	if needGzip {
		data, err = gzip.NewReader(m.BodyBuffer())
		if err != nil {
			return nil, err
		}
	}
	if !isUtf8 {
		data, err = newCharsetReader(data, contentType)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (m *MessageOpt) appointedLength() (int, error) {
	contentLengthStr := m.Headers().Get("Content-Length")
	if contentLengthStr == "" {
		return -1, nil
	}
	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("the request has not correct content length header value: %s", contentLengthStr)
	}
	return int(contentLength), nil
}

func (m *MessageOpt) isChunked() bool {
	return m.Headers().Get("Transfer-Encoding") == "chunked"
}

func (m *MessageOpt) readBodyUntilCurrentPackageFinished(buf *buffer.Buffer, reader *bufio.Reader) (*buffer.Buffer, enums.ParseResult, error) {
	startPosition := buf.OffsetPosition(-reader.Buffered())
	for !buf.IsCurrentPacketReadFinished() {
		_, err := buf.Read(m.Reader().bodyBuffer)
		if err != nil {
			return nil, enums.ParseResultSkipPackage, err
		}
	}
	endPosition := buf.Position()
	return buf.Slice(true, startPosition, endPosition), enums.ParseResultSuccess, nil
}

func (m *MessageOpt) checkChunkedBody(buf *buffer.Buffer, bodyReader *bufio.Reader) (*buffer.Buffer, enums.ParseResult, error) {
	buffers := make([]*buffer.Buffer, 0)
	for {
		line, _, err := bodyReader.ReadLine()
		if err != nil {
			return nil, enums.ParseResultSkipPackage, err
		}
		needBytesStr := string(line)
		needBytes, err := strconv.ParseInt(needBytesStr, 16, 64)
		if err != nil {
			return nil, enums.ParseResultSkipPackage, fmt.Errorf("read chunked size error: %s", needBytesStr)
		}
		if needBytes == 0 {
			break
		}
		if b, r, err1 := m.checkBodyWithSize(buf, bodyReader, int(needBytes), false); err1 != nil {
			return nil, enums.ParseResultSkipPackage, err1
		} else if r != enums.ParseResultSuccess {
			return nil, r, nil
		} else {
			if pos := b.DetectNotSendingLastPosition(); pos != nil {
				log.Debugf("found the socket data not sending finished in BPF, so update the body to the latest data, %v", pos)
				successSlice := b.Slice(true, b.Position(), pos)
				buffers = append(buffers, successSlice)
				break
			}
			buffers = append(buffers, b)
		}
		d, _, err := bodyReader.ReadLine()
		if err != nil {
			return nil, enums.ParseResultSkipPackage, err
		}
		if len(d) != 0 {
			return nil, enums.ParseResultSkipPackage, fmt.Errorf("the chunk data parding error, should be empty: %s", d)
		}
	}
	return buffer.CombineSlices(true, buf, buffers...), enums.ParseResultSuccess, nil
}

func (m *MessageOpt) checkBodyWithSize(buf *buffer.Buffer, reader *bufio.Reader, size int,
	detectedNotSending bool) (*buffer.Buffer, enums.ParseResult, error) {
	reduceSize := size
	var readSize, lastReadSize int
	var err error
	startPosition := buf.OffsetPosition(-reader.Buffered())
	for reduceSize > 0 {
		readSize = reduceSize
		if readSize > len(m.Reader().bodyBuffer) {
			readSize = len(m.Reader().bodyBuffer)
		}
		lastReadSize, err = reader.Read(m.Reader().bodyBuffer[0:readSize])
		if err != nil {
			if err == buffer.ErrNotComplete {
				return nil, enums.ParseResultSkipPackage, nil
			}
			if err == io.EOF && reduceSize-lastReadSize <= 0 {
				return nil, enums.ParseResultSuccess, nil
			}
			return nil, enums.ParseResultSkipPackage, err
		}
		reduceSize -= lastReadSize
	}
	endPosition := buf.OffsetPosition(-reader.Buffered())
	slice := buf.Slice(true, startPosition, endPosition)
	if detectedNotSending {
		if pos := slice.DetectNotSendingLastPosition(); pos != nil {
			log.Debugf("found the socket data not sending finished in BPF, so update the body to the latest data, %v", pos)
			endPosition = pos
			slice = buf.Slice(true, startPosition, endPosition)
		}
	}

	return slice, enums.ParseResultSuccess, nil
}

type charsetReadWrapper struct {
	reader io.Reader
}

func newCharsetReader(r io.Reader, contentType string) (*charsetReadWrapper, error) {
	reader, err := charset.NewReader(r, contentType)
	if err != nil {
		return nil, err
	}
	return &charsetReadWrapper{reader: reader}, nil
}

func (c *charsetReadWrapper) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func (c *charsetReadWrapper) Close() error {
	return nil
}
