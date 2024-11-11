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

import (
	"container/list"
	"io"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/http1/reader"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var http1Log = logger.GetLogger("accesslog", "collector", "protocols", "http1")

func init() {
	registeredProtocols[enums.ConnectionProtocolHTTP] = func(ctx *common.AccessLogContext) Protocol {
		return &HTTP1Protocol{ctx: ctx}
	}
}

type HTTP1Protocol struct {
	ctx *common.AccessLogContext
}

type HTTP1Metrics struct {
	connectionID uint64
	randomID     uint64

	halfRequests *list.List
}

func (p *HTTP1Protocol) GenerateConnection(connectionID, randomID uint64) ProtocolMetrics {
	return &HTTP1Metrics{
		connectionID: connectionID,
		randomID:     randomID,
		halfRequests: list.New(),
	}
}

func (p *HTTP1Protocol) Analyze(metrics ProtocolMetrics, buf *buffer.Buffer, _ *AnalyzeHelper) error {
	http1Metrics := metrics.(*HTTP1Metrics)
	http1Log.Debugf("ready to analyze HTTP/1 protocol data, connection ID: %d, random ID: %d, data len: %d",
		http1Metrics.connectionID, http1Metrics.randomID, buf.DataLength())
	buf.ResetForLoopReading()
	for {
		if !buf.PrepareForReading() {
			return nil
		}

		messageType, err := reader.IdentityMessageType(buf)
		if err != nil {
			http1Log.Debugf("failed to identity message type, %v", err)
			if buf.SkipCurrentElement() {
				break
			}
			continue
		}

		var result enums.ParseResult
		switch messageType {
		case reader.MessageTypeRequest:
			result, _ = p.handleRequest(metrics, buf)
		case reader.MessageTypeResponse:
			result, _ = p.handleResponse(metrics, buf)
		case reader.MessageTypeUnknown:
			result = enums.ParseResultSkipPackage
		}

		finishReading := false
		switch result {
		case enums.ParseResultSuccess:
			finishReading = buf.RemoveReadElements()
		case enums.ParseResultSkipPackage:
			finishReading = buf.SkipCurrentElement()
		}

		if finishReading {
			break
		}
	}
	return nil
}

func (p *HTTP1Protocol) handleRequest(metrics ProtocolMetrics, buf *buffer.Buffer) (enums.ParseResult, error) {
	req, result, err := reader.ReadRequest(buf, true)
	if err != nil {
		return enums.ParseResultSkipPackage, err
	}
	if result != enums.ParseResultSuccess {
		return result, nil
	}
	metrics.(*HTTP1Metrics).appendRequestToList(req)
	return result, nil
}

func (p *HTTP1Protocol) handleResponse(metrics ProtocolMetrics, b *buffer.Buffer) (enums.ParseResult, error) {
	http1Metrics := metrics.(*HTTP1Metrics)
	firstRequest := http1Metrics.halfRequests.Front()
	if firstRequest == nil {
		return enums.ParseResultSkipPackage, nil
	}
	request := http1Metrics.halfRequests.Remove(firstRequest).(*reader.Request)

	// parsing response
	response, result, err := reader.ReadResponse(request, b, true)
	defer func() {
		// if parsing response failed, then put the request back to the list
		if result != enums.ParseResultSuccess {
			http1Metrics.halfRequests.PushFront(request)
		}
	}()
	if err != nil {
		return enums.ParseResultSkipPackage, err
	} else if result != enums.ParseResultSuccess {
		return result, nil
	}

	// getting the request and response, then send to the forwarder
	p.handleHTTPData(http1Metrics, request, response)
	return enums.ParseResultSuccess, nil
}

func (p *HTTP1Protocol) handleHTTPData(metrics *HTTP1Metrics, request *reader.Request, response *reader.Response) {
	detailEvents := make([]events.SocketDetail, 0)
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, request.HeaderBuffer())
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, request.BodyBuffer())
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, response.HeaderBuffer())
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, response.BodyBuffer())

	if len(detailEvents) == 0 {
		http1Log.Warnf("cannot found any detail events for HTTP/1.x protocol, data id: %d-%d",
			request.MinDataID(), response.BodyBuffer().LastSocketBuffer().DataID())
		return
	}
	http1Log.Debugf("found fully HTTP1 request and response, contains %d detail events , connection ID: %d, random ID: %d",
		len(detailEvents), metrics.connectionID, metrics.randomID)
	originalRequest := request.Original()
	originalResponse := response.Original()

	defer func() {
		p.closeStream(originalRequest.Body)
		p.closeStream(originalResponse.Body)
	}()
	forwarder.SendTransferProtocolEvent(p.ctx, detailEvents, &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: forwarder.BuildOffsetTimestamp(detailEvents[0].GetStartTime()),
				EndTime:   forwarder.BuildOffsetTimestamp(detailEvents[len(detailEvents)-1].GetEndTime()),
				Version:   v3.AccessLogHTTPProtocolVersion_HTTP1,
				Request: &v3.AccessLogHTTPProtocolRequest{
					Method:             transformHTTPMethod(originalRequest.Method),
					Path:               originalRequest.URL.Path,
					SizeOfHeadersBytes: uint64(request.HeaderBuffer().DataSize()),
					SizeOfBodyBytes:    uint64(request.BodyBuffer().DataSize()),

					Trace: analyzeTraceInfo(func(key string) string {
						return originalRequest.Header.Get(key)
					}, http1Log),
				},
				Response: &v3.AccessLogHTTPProtocolResponse{
					StatusCode:         int32(originalResponse.StatusCode),
					SizeOfHeadersBytes: uint64(response.HeaderBuffer().DataSize()),
					SizeOfBodyBytes:    uint64(response.BodyBuffer().DataSize()),
				},
			},
		},
	})
}

func (p *HTTP1Protocol) closeStream(ioReader io.Closer) {
	if ioReader != nil {
		_ = ioReader.Close()
	}
}

func transformHTTPMethod(method string) v3.AccessLogHTTPProtocolRequestMethod {
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

func (m *HTTP1Metrics) appendRequestToList(req *reader.Request) {
	if m.halfRequests.Len() == 0 {
		m.halfRequests.PushFront(req)
		return
	}
	if m.halfRequests.Back().Value.(*reader.Request).MinDataID() < req.MinDataID() {
		m.halfRequests.PushBack(req)
		return
	}
	beenAdded := false
	for element := m.halfRequests.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(*reader.Request)
		if existEvent.MinDataID() > req.MinDataID() {
			m.halfRequests.InsertBefore(req, element)
			beenAdded = true
			break
		}
	}
	if !beenAdded {
		m.halfRequests.PushBack(req)
	}
}
