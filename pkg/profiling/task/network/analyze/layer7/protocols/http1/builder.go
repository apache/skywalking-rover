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

package http1

import (
	"bufio"
	"bytes"
	"container/list"
	"net/http"

	base2 "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"

	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
)

type BufferAnalyzer struct {
	http1Analyzer *Analyzer

	unknownEventBuffer base2.SocketDataBuffer
	unknownElement     *list.Element
	unknownSize        int
	request            *base2.SocketDataUploadEvent
	requestElement     *list.Element
	response           *base2.SocketDataUploadEvent
	responseElement    *list.Element

	unknownDataID      uint64
	unknownMaxSequence uint16
	reqDataID          uint64
	reqMaxSequence     uint16
	reqFinished        bool
	respDataID         uint64
	respMaxSequence    uint16
	respFinished       bool
}

func NewHTTP1BufferAnalyzer(http1 *Analyzer) *BufferAnalyzer {
	return &BufferAnalyzer{http1Analyzer: http1}
}

func (h *BufferAnalyzer) Analyze(events *list.List) (request, response base2.SocketDataBuffer) {
	for element := events.Front(); element != nil; element = element.Next() {
		curEvent := element.Value.(*base2.SocketDataUploadEvent)
		// transform the unknown to the request or response
		if continueReading, req, resp := h.handleUnknown(events, element, curEvent); req != nil && resp != nil {
			return req, resp
		} else if continueReading {
			continue
		}

		if continueReading, req, resp := h.handleRequest(events, element, curEvent); req != nil && resp != nil {
			return req, resp
		} else if continueReading {
			continue
		}

		if req, resp := h.handleResponse(events, element, curEvent); req != nil && resp != nil {
			return req, resp
		}
	}
	return nil, nil
}

func (h *BufferAnalyzer) handleUnknown(event *list.List, element *list.Element,
	curEvent *base2.SocketDataUploadEvent) (continueReading bool, req, resp base2.SocketDataBuffer) {
	if curEvent.MsgType != base.SocketMessageTypeUnknown {
		return false, nil, nil
	}
	if h.unknownEventBuffer == nil {
		// maybe the unknown type is response, so clean the context
		if !curEvent.IsStart() {
			h.cleanContext()
			return true, nil, nil
		}
		h.resetStartUnknown(element, curEvent)
		req, resp = h.tryingToAnalyzeTheUnknown(event, curEvent)
		if req != nil && resp != nil {
			return false, req, resp
		}
		return true, nil, nil
	}
	if curEvent.MsgType == base.SocketMessageTypeUnknown {
		if h.unknownDataID == curEvent.DataID && h.unknownMaxSequence+1 == curEvent.Sequence {
			h.unknownEventBuffer = h.unknownEventBuffer.Combine(curEvent)
			h.unknownMaxSequence++
		} else if curEvent.IsStart() {
			h.resetStartUnknown(element, curEvent)
		} else {
			h.cleanContext()
		}

		req, resp = h.tryingToAnalyzeTheUnknown(event, curEvent)
		if req != nil && resp != nil {
			return false, req, resp
		}
		return true, nil, nil
	}
	return false, nil, nil
}

func (h *BufferAnalyzer) handleRequest(events *list.List, element *list.Element,
	curEvent *base2.SocketDataUploadEvent) (continueReading bool, req, resp base2.SocketDataBuffer) {
	if h.request == nil {
		// find the first request package event
		if curEvent.MsgType == base.SocketMessageTypeRequest && curEvent.IsStart() {
			h.resetStartRequest(element, curEvent)
		}
		return true, nil, nil
	}
	if curEvent.MsgType == base.SocketMessageTypeRequest {
		// if the request not finished and latest request sequence match with current event
		// then keep the request tracing
		if !h.reqFinished && h.reqDataID == curEvent.DataID && h.reqMaxSequence+1 == curEvent.Sequence {
			h.reqMaxSequence++
			h.reqFinished = curEvent.IsFinished()
		} else if curEvent.IsStart() {
			// if current event is new one, then update to current request
			h.resetStartRequest(element, curEvent)
		} else {
			// Otherwise, clean the request and response context
			h.cleanContext()
		}

		// if request and response all finished, then return
		if h.reqFinished && h.respFinished {
			req, resp = h.buildHTTP(events)
			return false, req, resp
		}

		return true, nil, nil
	}
	return false, nil, nil
}

func (h *BufferAnalyzer) handleResponse(events *list.List, element *list.Element,
	curEvent *base2.SocketDataUploadEvent) (req, resp base2.SocketDataBuffer) {
	if h.response == nil {
		// if current response is not start, then clean to re-find new one
		if !curEvent.IsStart() {
			h.cleanContext()
			return nil, nil
		}
		h.resetStartResponse(element, curEvent)
		if h.reqFinished && h.respFinished {
			return h.buildHTTP(events)
		}
		return nil, nil
	}

	// if a new response, then clean the re-find new one, wait the previous data
	if curEvent.IsStart() {
		h.cleanContext()
		return nil, nil
	}

	// if response sequence is broken, then clean the context
	if h.respDataID != curEvent.DataID || h.respMaxSequence+1 != curEvent.Sequence {
		h.cleanContext()
		return nil, nil
	}
	h.respDataID = curEvent.DataID
	h.respMaxSequence = curEvent.Sequence

	if h.reqFinished && curEvent.IsFinished() {
		return h.buildHTTP(events)
	}
	return nil, nil
}

func (h *BufferAnalyzer) resetStartUnknown(element *list.Element, curEvent *base2.SocketDataUploadEvent) {
	h.unknownEventBuffer = curEvent
	h.unknownElement = element
	h.unknownDataID = curEvent.DataID
	h.unknownMaxSequence = curEvent.Sequence
}

func (h *BufferAnalyzer) resetStartRequest(element *list.Element, curEvent *base2.SocketDataUploadEvent) {
	h.request = curEvent
	h.reqDataID = curEvent.DataID
	h.reqMaxSequence = curEvent.Sequence
	h.reqFinished = curEvent.IsFinished()
	h.requestElement = element
}

func (h *BufferAnalyzer) resetStartResponse(element *list.Element, curEvent *base2.SocketDataUploadEvent) {
	h.response = curEvent
	h.respDataID = curEvent.DataID
	h.respMaxSequence = curEvent.Sequence
	h.responseElement = element
	h.respFinished = curEvent.IsFinished()
}

func (h *BufferAnalyzer) tryingToAnalyzeTheUnknown(events *list.List, curEvent *base2.SocketDataUploadEvent) (req, resp base2.SocketDataBuffer) {
	if h.unknownEventBuffer == nil {
		return nil, nil
	}
	// length not enough
	if len(h.unknownEventBuffer.BufferData()) < 16 {
		return nil, nil
	}
	_, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(h.unknownEventBuffer.BufferData())))
	if err == nil {
		// update the event as request
		curEvent.FinishStatus = 1
		h.transformUnknown(h.unknownElement, base.SocketMessageTypeRequest)
		// update the current data is request
		h.resetStartRequest(h.unknownElement, h.unknownEventBuffer.FirstEvent())
		h.reqFinished = true
		h.cleanResponseContext()
		h.cleanUnknownContext()
		return nil, nil
	}
	tmpResponse, err := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(h.unknownEventBuffer.BufferData())), &http.Request{})
	if err == nil {
		defer tmpResponse.Body.Close()
		curEvent.FinishStatus = 1
		h.transformUnknown(h.unknownElement, base.SocketMessageTypeResponse)
		// if request already finished, then remove the request
		if h.reqFinished {
			h.resetStartResponse(h.unknownElement, h.unknownEventBuffer.FirstEvent())
			return h.buildHTTP(events)
		}
		// otherwise, clean the context and wait request
		h.cleanContext()
	}
	return nil, nil
}

func (h *BufferAnalyzer) transformUnknown(element *list.Element, msgType base.SocketMessageType) {
	// update message type and total size
	firstEvent := element.Value.(*base2.SocketDataUploadEvent)
	firstEvent.MsgType = msgType
	dataLen := int(firstEvent.DataLen)
	for e := element.Next(); e != nil; e = e.Next() {
		curEvent := e.Value.(*base2.SocketDataUploadEvent)
		if curEvent.FinishStatus == 1 {
			curEvent.MsgType = msgType
			dataLen += int(curEvent.DataLen)
			firstEvent.TotalSize0 = uint64(dataLen)
			return
		}
		curEvent.MsgType = msgType
		dataLen += int(curEvent.DataLen)
	}
}

func (h *BufferAnalyzer) cleanContext() {
	h.cleanUnknownContext()
	h.cleanRequestContext()
	h.cleanResponseContext()
}

func (h *BufferAnalyzer) cleanResponseContext() {
	h.response = nil
	h.respDataID = 0
	h.respMaxSequence = 0
	h.respFinished = false
}

func (h *BufferAnalyzer) cleanRequestContext() {
	h.request = nil
	h.reqDataID = 0
	h.reqMaxSequence = 0
	h.reqFinished = false
}

func (h *BufferAnalyzer) cleanUnknownContext() {
	h.unknownEventBuffer, h.unknownElement = nil, nil
	h.unknownSize, h.unknownDataID, h.unknownMaxSequence = 0, 0, 0
}

func (h *BufferAnalyzer) buildHTTP(events *list.List) (req, resp base2.SocketDataBuffer) {
	return h.http1Analyzer.combineAndRemoveEvent(events, h.requestElement, nil),
		h.http1Analyzer.combineAndRemoveEvent(events, h.responseElement, nil)
}
