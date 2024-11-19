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

type HTTP1ProtocolAnalyze func(metrics *HTTP1Metrics, request *reader.Request, response *reader.Response)

type HTTP1Protocol struct {
	ctx     *common.AccessLogContext
	analyze HTTP1ProtocolAnalyze
}

func NewHTTP1Analyzer(ctx *common.AccessLogContext, analyze HTTP1ProtocolAnalyze) *HTTP1Protocol {
	protocol := &HTTP1Protocol{ctx: ctx}
	if analyze == nil {
		protocol.analyze = protocol.HandleHTTPData
	} else {
		protocol.analyze = analyze
	}
	return protocol
}

type HTTP1Metrics struct {
	ConnectionID uint64
	RandomID     uint64

	halfRequests *list.List
}

func (p *HTTP1Protocol) GenerateConnection(connectionID, randomID uint64) ProtocolMetrics {
	return &HTTP1Metrics{
		ConnectionID: connectionID,
		RandomID:     randomID,
		halfRequests: list.New(),
	}
}

func (p *HTTP1Protocol) Analyze(connection *PartitionConnection, _ *AnalyzeHelper) error {
	metrics := connection.Metrics(enums.ConnectionProtocolHTTP).(*HTTP1Metrics)
	http1Log.Debugf("ready to analyze HTTP/1 protocol data, connection ID: %d, random ID: %d, data len: %d",
		metrics.ConnectionID, metrics.RandomID, connection.Buffer().DataLength())
	connection.Buffer().ResetForLoopReading()
	for {
		if !connection.Buffer().PrepareForReading() {
			return nil
		}

		messageType, err := reader.IdentityMessageType(connection.Buffer())
		if err != nil {
			http1Log.Debugf("failed to identity message type, %v", err)
			if connection.Buffer().SkipCurrentElement() {
				break
			}
			continue
		}

		var result enums.ParseResult
		switch messageType {
		case reader.MessageTypeRequest:
			result, _ = p.handleRequest(metrics, connection.Buffer())
		case reader.MessageTypeResponse:
			result, _ = p.handleResponse(metrics, connection.Buffer())
		case reader.MessageTypeUnknown:
			result = enums.ParseResultSkipPackage
		}

		finishReading := false
		switch result {
		case enums.ParseResultSuccess:
			finishReading = connection.Buffer().RemoveReadElements()
		case enums.ParseResultSkipPackage:
			finishReading = connection.Buffer().SkipCurrentElement()
		}

		if finishReading {
			break
		}
	}
	return nil
}

func (p *HTTP1Protocol) ForProtocol() enums.ConnectionProtocol {
	return enums.ConnectionProtocolHTTP
}

func (p *HTTP1Protocol) handleRequest(metrics *HTTP1Metrics, buf *buffer.Buffer) (enums.ParseResult, error) {
	req, result, err := reader.ReadRequest(buf, true)
	if err != nil {
		return enums.ParseResultSkipPackage, err
	}
	if result != enums.ParseResultSuccess {
		return result, nil
	}
	metrics.appendRequestToList(req)
	return result, nil
}

func (p *HTTP1Protocol) handleResponse(metrics *HTTP1Metrics, b *buffer.Buffer) (enums.ParseResult, error) {
	firstRequest := metrics.halfRequests.Front()
	if firstRequest == nil {
		return enums.ParseResultSkipPackage, nil
	}
	request := metrics.halfRequests.Remove(firstRequest).(*reader.Request)

	// parsing response
	response, result, err := reader.ReadResponse(request, b, true)
	defer func() {
		// if parsing response failed, then put the request back to the list
		if result != enums.ParseResultSuccess {
			metrics.halfRequests.PushFront(request)
		}
	}()
	if err != nil {
		return enums.ParseResultSkipPackage, err
	} else if result != enums.ParseResultSuccess {
		return result, nil
	}

	// getting the request and response, then send to the forwarder
	p.analyze(metrics, request, response)
	return enums.ParseResultSuccess, nil
}

func (p *HTTP1Protocol) HandleHTTPData(metrics *HTTP1Metrics, request *reader.Request, response *reader.Response) {
	detailEvents := make([]events.SocketDetail, 0)
	detailEvents = AppendSocketDetailsFromBuffer(detailEvents, request.HeaderBuffer())
	detailEvents = AppendSocketDetailsFromBuffer(detailEvents, request.BodyBuffer())
	detailEvents = AppendSocketDetailsFromBuffer(detailEvents, response.HeaderBuffer())
	detailEvents = AppendSocketDetailsFromBuffer(detailEvents, response.BodyBuffer())

	if len(detailEvents) == 0 {
		http1Log.Warnf("cannot found any detail events for HTTP/1.x protocol, connection ID: %d, random ID: %d, data id: %d-%d",
			metrics.ConnectionID, metrics.RandomID,
			request.MinDataID(), response.BodyBuffer().LastSocketBuffer().DataID())
		return
	}
	http1Log.Debugf("found fully HTTP1 request and response, contains %d detail events , connection ID: %d, random ID: %d",
		len(detailEvents), metrics.ConnectionID, metrics.RandomID)
	originalRequest := request.Original()
	originalResponse := response.Original()

	defer func() {
		p.CloseStream(originalRequest.Body)
		p.CloseStream(originalResponse.Body)
	}()
	forwarder.SendTransferProtocolEvent(p.ctx, detailEvents, &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: forwarder.BuildOffsetTimestamp(detailEvents[0].GetStartTime()),
				EndTime:   forwarder.BuildOffsetTimestamp(detailEvents[len(detailEvents)-1].GetEndTime()),
				Version:   v3.AccessLogHTTPProtocolVersion_HTTP1,
				Request: &v3.AccessLogHTTPProtocolRequest{
					Method:             TransformHTTPMethod(originalRequest.Method),
					Path:               originalRequest.URL.Path,
					SizeOfHeadersBytes: uint64(request.HeaderBuffer().DataSize()),
					SizeOfBodyBytes:    uint64(request.BodyBuffer().DataSize()),
					Trace: AnalyzeTraceInfo(func(key string) string {
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

func (p *HTTP1Protocol) CloseStream(ioReader io.Closer) {
	if ioReader != nil {
		_ = ioReader.Close()
	}
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
