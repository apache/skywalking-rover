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

package network

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/host"
)

type HTTP1BufferEvent struct {
	pid          uint32
	requestURI   string
	requestTime  uint64
	statusCode   int
	responseTime uint64
}

type HTTP1Analyzer struct {
	channelEvents map[uint64]*HTTP1BufferEvent
}

func NewHTTP1Analyzer() *HTTP1Analyzer {
	return &HTTP1Analyzer{
		channelEvents: make(map[uint64]*HTTP1BufferEvent),
	}
}

func (h *HTTP1Analyzer) HandleBufferEvent(buffer *networkBufferInBPF) BufferEvent {
	if buffer.Direction == BufferDirectionRequest {
		event := &HTTP1BufferEvent{}
		event.pid = buffer.Pid
		event.requestTime = buffer.Timestamp
		uri, err := h.analyzeRequestURI(buffer)
		if err != nil {
			log.Warnf("cannot fount the request uri from content: %s, reason: %v", buffer.Buffer[0:buffer.Size], err)
			return nil
		}
		event.requestURI = uri
		h.channelEvents[buffer.ChannelRef] = event
		return nil
	}

	event := h.channelEvents[buffer.ChannelRef]

	// cannot found the last request event
	if event == nil {
		return nil
	}
	// clean the request buffer
	delete(h.channelEvents, buffer.ChannelRef)

	code, err := h.analyzeResponseStatus(buffer)
	if err != nil {
		log.Warnf("failure to parse the response status code: content: %s, reason: %v", buffer.Buffer[0:buffer.Size], err)
		return nil
	}
	event.statusCode = code
	event.responseTime = buffer.Timestamp
	return event
}

func (h *HTTP1Analyzer) analyzeRequestURI(buffer *networkBufferInBPF) (string, error) {
	bufferData := string(buffer.Buffer[0:buffer.Size])
	firstSpace := strings.Index(bufferData, " ")
	if firstSpace <= 0 {
		return "", fmt.Errorf("the reuquest buffer is not validate")
	}
	if len(bufferData) <= firstSpace+1 {
		return "", fmt.Errorf("current package data data is not enough")
	}
	requestURIData := bufferData[firstSpace+1:]
	for inx, d := range requestURIData {
		// find the first requestURI end index
		if d == '?' || d == ' ' {
			return requestURIData[0:inx], nil
		}
	}
	return "", fmt.Errorf("cannot found the request URI")
}

func (h *HTTP1Analyzer) analyzeResponseStatus(buffer *networkBufferInBPF) (int, error) {
	bufferData := string(buffer.Buffer[0:buffer.Size])
	firstSpace := strings.Index(bufferData, " ")
	if firstSpace <= 0 {
		return 0, fmt.Errorf("the reuquest buffer is not validate")
	}
	if len(bufferData) <= firstSpace+1 {
		return 0, fmt.Errorf("current package data data is not enough")
	}
	secondSpace := strings.Index(bufferData[firstSpace+1:], " ")
	i, err := strconv.ParseInt(bufferData[firstSpace+1:][0:secondSpace], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse response status error")
	}
	return int(i), nil
}

func (h *HTTP1BufferEvent) StartTime() time.Time {
	return host.Time(h.requestTime)
}

func (h *HTTP1BufferEvent) Pid() int32 {
	return int32(h.pid)
}

func (h *HTTP1BufferEvent) RequestURI() string {
	return h.requestURI
}

func (h *HTTP1BufferEvent) IsResponseError() bool {
	return h.statusCode >= 500
}

func (h *HTTP1BufferEvent) Duration() time.Duration {
	return time.Duration(h.responseTime - h.requestTime)
}
