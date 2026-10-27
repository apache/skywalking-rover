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
	"strconv"
	"strings"
	"time"

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

type HTTP1ProtocolAnalyzer interface {
	HandleHTTPData(metrics *HTTP1Metrics, connection *PartitionConnection,
		request *reader.Request, response *reader.Response) error
	OnProtocolBreak(metrics *HTTP1Metrics, connection *PartitionConnection)
}

type HTTP1Protocol struct {
	ctx      *common.AccessLogContext
	analyzer HTTP1ProtocolAnalyzer
	reader   *reader.Reader
}

func NewHTTP1Analyzer(ctx *common.AccessLogContext, analyze HTTP1ProtocolAnalyzer) *HTTP1Protocol {
	protocol := &HTTP1Protocol{ctx: ctx, reader: reader.NewReader()}
	if analyze == nil {
		protocol.analyzer = protocol
	} else {
		protocol.analyzer = analyze
	}
	return protocol
}

type HTTP1Metrics struct {
	ConnectionID uint64
	RandomID     uint64

	halfRequests      *list.List
	analyzeUnFinished *list.List
	// pendingBody is the Content-Length body currently being consumed as its data arrives (the events
	// are released immediately instead of being held until the whole message is complete)
	pendingBody *http1PendingBody
}

type http1PendingBody struct {
	request  *reader.Request
	response *reader.Response // nil while a request body is consumed
	consumer *buffer.BodyConsumer
	// started is when the body started being consumed: a body whose announced length never arrives
	// (a wrong Content-Length, a lost event) must not pin the parser of the connection forever
	started time.Time
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
	p.handleUnFinishedEvents(metrics, connection)
	buf.ResetForLoopReading()
	if pending := metrics.pendingBody; pending != nil {
		if time.Since(pending.started) > maxBufferExpireDuration {
			// the announced body never arrived completely (wrong Content-Length, lost events): give it
			// up instead of consuming every following message of the connection as its body
			http1Log.Debugf("give up the pending HTTP/1 body, connection ID: %d, random ID: %d",
				metrics.ConnectionID, metrics.RandomID)
			metrics.pendingBody = nil
		} else if !buf.PrepareForReading() || !p.consumePendingBody(metrics, connection, buf) {
			// the body is consumed as it arrives: without the rest of it there is no next message yet
			return nil
		}
	}
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
			result, err = p.handleResponse(metrics, connection, buf)
		case reader.MessageTypeUnknown:
			result = enums.ParseResultSkipPackage
		}
		if err != nil {
			http1Log.Debugf("failed to handle HTTP/1.x protocol, connection ID: %d, random ID: %d, data id: %d, type: %d, error: %v",
				metrics.ConnectionID, metrics.RandomID, http1DataID(buf), messageType, err)
		}

		http1Log.Debugf("readed message, messageType: %v, buf: %p, data id: %d, "+
			"connection ID: %d, random ID: %d, metrics : %p, handle result: %d",
			messageType, buf, http1DataID(buf), metrics.ConnectionID, metrics.RandomID, metrics, result)
		finishReading := false
		switch result {
		case enums.ParseResultSuccess:
			if !buf.Position().HasElement() {
				// the body consumer released every event up to the end of the buffer
				finishReading = true
			} else {
				finishReading = buf.RemoveReadElements(false)
			}
		case enums.ParseResultSkipPackage:
			finishReading = buf.SkipCurrentElement()
			log.Debugf("skip current element, data id: %d, buf: %p, connection ID: %d, random ID: %d",
				http1DataID(buf), buf, metrics.ConnectionID, metrics.RandomID)
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
	// headers first: a body with a known length is consumed as it arrives (events released right away)
	req, result, err := p.reader.ReadRequest(buf, false)
	if err != nil {
		return enums.ParseResultSkipPackage, err
	}
	if result != enums.ParseResultSuccess {
		return result, nil
	}
	if consumer := http1BodyConsumer(req.Headers(), req.HeaderBuffer()); consumer != nil {
		// the events the headers were read from are not needed anymore: release them before the body is
		// consumed, otherwise they stay at the front of the buffer and the next analyze round (which
		// always restarts at the front) parses them again, in front of the live data
		http1ReleaseReadElements(buf)
		metrics.pendingBody = &http1PendingBody{request: req, consumer: consumer, started: time.Now()}
		p.consumePendingBody(metrics, nil, buf)
		return enums.ParseResultSuccess, nil
	}
	// neither Content-Length nor chunked (no body, or read to the end of the packet): the whole message
	// is read at once, from its start
	buf.PrepareForReading()
	req, result, err = p.reader.ReadRequest(buf, true)
	if err != nil {
		return enums.ParseResultSkipPackage, err
	}
	if result != enums.ParseResultSuccess {
		return result, nil
	}
	metrics.appendRequestToList(req)
	return result, nil
}

// http1ReleaseReadElements removes the events the message headers were read from (everything before
// the reading position) and leaves the position at the first byte of the body
func http1ReleaseReadElements(buf *buffer.Buffer) {
	if !buf.Position().HasElement() {
		return
	}
	if buf.RemoveReadElements(false) {
		return
	}
	// the positions were moved by the removal: continue from the new head (the body start)
	buf.PrepareForReading()
}

// http1DataID returns the data id at the reading position (0 at the end of the buffer), for logs
func http1DataID(buf *buffer.Buffer) uint64 {
	if pos := buf.Position(); pos.HasElement() {
		return pos.DataID()
	}
	return 0
}

// http1BodyConsumer returns the streaming consumer for a body with a known framing (Content-Length or
// chunked transfer encoding), nil when the body has to be read with the message
func http1BodyConsumer(headers map[string][]string, headerBuffer *buffer.Buffer) *buffer.BodyConsumer {
	if length := http1ContentLength(headers); length > 0 {
		return buffer.NewBodyConsumer(length, headerBuffer)
	}
	for _, v := range headers["Transfer-Encoding"] {
		for _, coding := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(coding), "chunked") {
				return buffer.NewChunkedBodyConsumer(headerBuffer)
			}
		}
	}
	return nil
}

// http1ContentLength returns the Content-Length of the message, 0 when absent or invalid
func http1ContentLength(headers map[string][]string) int64 {
	values := headers["Content-Length"]
	if len(values) == 0 {
		return 0
	}
	length, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || length < 0 {
		return 0
	}
	return length
}

// consumePendingBody consumes what the buffer holds of the pending body and finishes the message when
// the body is complete; it returns true when the body is complete
func (p *HTTP1Protocol) consumePendingBody(metrics *HTTP1Metrics, connection *PartitionConnection, buf *buffer.Buffer) bool {
	pending := metrics.pendingBody
	if !pending.consumer.Consume(buf) {
		return false
	}
	metrics.pendingBody = nil
	body := pending.consumer.Body(buf)
	if pending.response == nil {
		pending.request.SetBodyBuffer(body)
		metrics.appendRequestToList(pending.request)
		return true
	}
	pending.response.SetBodyBuffer(body)
	if analyzeError := p.analyzer.HandleHTTPData(metrics, connection, pending.request, pending.response); analyzeError != nil {
		p.appendAnalyzeUnFinished(metrics, pending.request, pending.response)
	}
	return true
}

func (p *HTTP1Protocol) handleResponse(metrics *HTTP1Metrics, connection *PartitionConnection,
	b *buffer.Buffer) (enums.ParseResult, error) {
	request := metrics.findMatchesRequest(b.Position().DataID(), b.Position().PrevDataID())
	if request == nil {
		log.Debugf("cannot found request for response, skip response, connection ID: %d, random ID: %d, "+
			"required prev data id: %d, current data id: %d",
			metrics.ConnectionID, metrics.RandomID, b.Position().PrevDataID(), b.Position().DataID())
		return enums.ParseResultSkipPackage, nil
	}

	// parsing response: headers first, a body with a known length is consumed as it arrives
	response, result, err := p.reader.ReadResponse(request, b, false)
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
	if !response.HasBody() {
		// the response carries no body by definition (HEAD request, 1xx/204/304, 2xx to CONNECT) even
		// when it announces a Content-Length: consuming one would swallow the following messages of
		// the keep-alive connection
		if analyzeError := p.analyzer.HandleHTTPData(metrics, connection, request, response); analyzeError != nil {
			p.appendAnalyzeUnFinished(metrics, request, response)
		}
		return enums.ParseResultSuccess, nil
	}
	if consumer := http1BodyConsumer(response.Headers(), response.HeaderBuffer()); consumer != nil {
		// see handleRequest: the header events must not stay in front of the body
		http1ReleaseReadElements(b)
		metrics.pendingBody = &http1PendingBody{request: request, response: response, consumer: consumer, started: time.Now()}
		p.consumePendingBody(metrics, connection, b)
		return enums.ParseResultSuccess, nil
	}
	// neither Content-Length nor chunked (no body, or read to the end of the packet): the whole message
	// is read at once, from its start
	b.PrepareForReading()
	response, result, err = p.reader.ReadResponse(request, b, true)
	if err != nil {
		return enums.ParseResultSkipPackage, err
	} else if result != enums.ParseResultSuccess {
		return result, nil
	}

	// getting the request and response, then send to the forwarder
	if analyzeError := p.analyzer.HandleHTTPData(metrics, connection, request, response); analyzeError != nil {
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

func (p *HTTP1Protocol) handleUnFinishedEvents(m *HTTP1Metrics, connection *PartitionConnection) {
	for element := m.analyzeUnFinished.Front(); element != nil; {
		unFinished := element.Value.(*HTTP1AnalyzeUnFinished)
		err := p.analyzer.HandleHTTPData(m, connection, unFinished.request, unFinished.response)
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

func (p *HTTP1Protocol) HandleHTTPData(metrics *HTTP1Metrics, _ *PartitionConnection,
	request *reader.Request, response *reader.Response) error {
	details := make([]events.SocketDetail, 0)
	var allInclude = true
	var idRange *buffer.DataIDRange
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, request.HeaderBuffer(), idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, request.BodyBuffer(), idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, response.HeaderBuffer(), idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, response.BodyBuffer(), idRange, allInclude)

	if !allInclude || idRange == nil || len(details) == 0 {
		from, to := DataIDRangeBounds(idRange)
		return fmt.Errorf("cannot found full detail events for HTTP/1.x protocol, "+
			"data id: %d-%d, current details count: %d",
			from, to, len(details))
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
	host := request.Headers().Get("Host")
	if host == "" && originalRequest.URL != nil {
		host = originalRequest.URL.Host
	}
	forwarder.SendTransferProtocolEvent(p.ctx, common.NewProtocolLogEvent(details, &v3.AccessLogProtocolLogs{
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
					Host: host,
				},
				Response: &v3.AccessLogHTTPProtocolResponse{
					StatusCode:         int32(originalResponse.StatusCode),
					SizeOfHeadersBytes: uint64(response.HeaderBuffer().DataSize()),
					SizeOfBodyBytes:    uint64(response.BodyBuffer().DataSize()),
				},
			},
		},
	}))
	return nil
}

func (p *HTTP1Protocol) OnProtocolBreak(*HTTP1Metrics, *PartitionConnection) {
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
