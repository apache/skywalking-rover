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
	"fmt"
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
var http1AnalyzeMaxRetryCount = 3

type HTTP1ProtocolAnalyze func(metrics *HTTP1Metrics, request *reader.Request, response *reader.Response) error

type HTTP1Protocol struct {
	ctx     *common.AccessLogContext
	analyze HTTP1ProtocolAnalyze
	reader  *reader.Reader
}

func NewHTTP1Analyzer(ctx *common.AccessLogContext, analyze HTTP1ProtocolAnalyze) *HTTP1Protocol {
	protocol := &HTTP1Protocol{ctx: ctx, reader: reader.NewReader()}
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

	halfRequests      *list.List
	analyzeUnFinished *list.List
}

func (p *HTTP1Protocol) GenerateConnection(connectionID, randomID uint64) ProtocolMetrics {
	return &HTTP1Metrics{
		ConnectionID:      connectionID,
		RandomID:          randomID,
		halfRequests:      list.New(),
		analyzeUnFinished: list.New(),
	}
}

type HTTP1AnalyzeUnFinished struct {
	request    *reader.Request
	response   *reader.Response
	retryCount int
}

func (p *HTTP1Protocol) Analyze(connection *PartitionConnection, _ *AnalyzeHelper) error {
	metrics := connection.Metrics(enums.ConnectionProtocolHTTP).(*HTTP1Metrics)
	buf := connection.Buffer(enums.ConnectionProtocolHTTP)
	http1Log.Debugf("ready to analyze HTTP/1 protocol data, connection ID: %d, random ID: %d, data len: %d",
		metrics.ConnectionID, metrics.RandomID, buf.DataLength())
	p.handleUnFinishedEvents(metrics)
	buf.ResetForLoopReading()
	for {
		if !buf.PrepareForReading() {
			return nil
		}

		messageType, err := p.reader.IdentityMessageType(buf)
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
			result, err = p.handleRequest(metrics, buf)
		case reader.MessageTypeResponse:
			result, err = p.handleResponse(metrics, buf)
		case reader.MessageTypeUnknown:
			result = enums.ParseResultSkipPackage
		}
		if err != nil {
			http1Log.Warnf("failed to handle HTTP/1.x protocol, connection ID: %d, random ID: %d, data id: %d, error: %v",
				metrics.ConnectionID, metrics.RandomID, buf.Position().DataID(), err)
		}

		http1Log.Debugf("readed message, messageType: %v, buf: %p, data id: %d, "+
			"connection ID: %d, random ID: %d, metrics : %p, handle result: %d",
			messageType, buf, buf.Position().DataID(), metrics.ConnectionID, metrics.RandomID, metrics, result)
		finishReading := false
		switch result {
		case enums.ParseResultSuccess:
			finishReading = buf.RemoveReadElements(false)
		case enums.ParseResultSkipPackage:
			finishReading = buf.SkipCurrentElement()
			log.Debugf("skip current element, data id: %d, buf: %p, connection ID: %d, random ID: %d",
				buf.Position().DataID(), buf, metrics.ConnectionID, metrics.RandomID)
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
	req, result, err := p.reader.ReadRequest(buf, true)
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
	request := metrics.findMatchesRequest(b.Position().DataID(), b.Position().PrevDataID())
	if request == nil {
		log.Debugf("cannot found request for response, skip response, connection ID: %d, random ID: %d, "+
			"required prev data id: %d, current data id: %d",
			metrics.ConnectionID, metrics.RandomID, b.Position().PrevDataID(), b.Position().DataID())
		return enums.ParseResultSkipPackage, nil
	}

	// parsing response
	response, result, err := p.reader.ReadResponse(request, b, true)
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
	if analyzeError := p.analyze(metrics, request, response); analyzeError != nil {
		p.appendAnalyzeUnFinished(metrics, request, response)
	}
	return enums.ParseResultSuccess, nil
}

func (p *HTTP1Protocol) appendAnalyzeUnFinished(metrics *HTTP1Metrics, request *reader.Request, response *reader.Response) {
	metrics.analyzeUnFinished.PushBack(&HTTP1AnalyzeUnFinished{
		request:    request,
		response:   response,
		retryCount: 0,
	})
}

func (p *HTTP1Protocol) handleUnFinishedEvents(m *HTTP1Metrics) {
	for element := m.analyzeUnFinished.Front(); element != nil; {
		unFinished := element.Value.(*HTTP1AnalyzeUnFinished)
		err := p.analyze(m, unFinished.request, unFinished.response)
		if err != nil {
			unFinished.retryCount++
			if unFinished.retryCount < http1AnalyzeMaxRetryCount {
				element = element.Next()
				continue
			}
			http1Log.Warnf("failed to analyze HTTP1 request and response, connection ID: %d, random ID: %d, "+
				"retry count: %d, error: %v", m.ConnectionID, m.RandomID, unFinished.retryCount, err)
		}
		next := element.Next()
		m.analyzeUnFinished.Remove(element)
		element = next
	}
}

func (p *HTTP1Protocol) HandleHTTPData(metrics *HTTP1Metrics, request *reader.Request, response *reader.Response) error {
	details := make([]events.SocketDetail, 0)
	var allInclude = true
	var idRange *buffer.DataIDRange
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, request.HeaderBuffer(), idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, request.BodyBuffer(), idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, response.HeaderBuffer(), idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, response.BodyBuffer(), idRange, allInclude)

	if !allInclude {
		return fmt.Errorf("cannot found full detail events for HTTP/1.x protocol, "+
			"data id: %d-%d, current details count: %d",
			request.MinDataID(), response.BodyBuffer().LastSocketBuffer().DataID(), len(details))
	}

	http1Log.Debugf("found fully HTTP1 request and response, contains %d detail events, "+
		"connection ID: %d, random ID: %d, data range: %d-%d(%t)",
		len(details), metrics.ConnectionID, metrics.RandomID, idRange.From, idRange.To, idRange.IsToBufferReadFinished)
	originalRequest := request.Original()
	originalResponse := response.Original()
	// delete details(each request or response is fine because it's will delete the original buffer)
	idRange.DeleteDetails(request.HeaderBuffer())

	defer func() {
		p.CloseStream(originalRequest.Body)
		p.CloseStream(originalResponse.Body)
	}()
	forwarder.SendTransferProtocolEvent(p.ctx, details, &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: forwarder.BuildOffsetTimestamp(details[0].GetStartTime()),
				EndTime:   forwarder.BuildOffsetTimestamp(details[len(details)-1].GetEndTime()),
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
	return nil
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

func (m *HTTP1Metrics) findMatchesRequest(currentDataID, prevDataID uint64) *reader.Request {
	for element := m.halfRequests.Front(); element != nil; element = element.Next() {
		req := element.Value.(*reader.Request)
		// if the tail data id of request is equals to the prev data id of response
		// or tail request data id+1==first response data id, then return the request
		if uint64(req.MaxDataID()) == prevDataID || uint64(req.MaxDataID()+1) == currentDataID {
			m.halfRequests.Remove(element)
			return req
		}
	}
	return nil
}
