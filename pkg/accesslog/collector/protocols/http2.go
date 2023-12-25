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
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// maxHTTP2StreamingTime is the max time of an HTTP/2 streaming, if the streaming is too long, then this streaming will split
var maxHTTP2StreamingTime = time.Minute * 3

var http2Log = logger.GetLogger("accesslog", "collector", "protocols", "http2")

func init() {
	registeredProtocols[enums.ConnectionProtocolHTTP2] = func(ctx *common.AccessLogContext) Protocol {
		return &HTTP2Protocol{ctx: ctx}
	}
}

type HTTP2Protocol struct {
	ctx *common.AccessLogContext
}

type HTTP2Metrics struct {
	connectionID uint64
	hpackDecoder *hpack.Decoder

	streams map[uint32]*HTTP2Streaming
}

type HTTP2Streaming struct {
	reqHeader        map[string]string
	respHeader       map[string]string
	reqHeaderBuffer  *buffer.Buffer
	reqBodyBuffer    *buffer.Buffer
	isInResponse     bool
	status           int
	respHeaderBuffer *buffer.Buffer
	respBodyBuffer   *buffer.Buffer
}

func (r *HTTP2Protocol) GenerateConnection(connectionID uint64) ProtocolMetrics {
	return &HTTP2Metrics{
		connectionID: connectionID,
		hpackDecoder: hpack.NewDecoder(4096, nil),
		streams:      make(map[uint32]*HTTP2Streaming),
	}
}

func (r *HTTP2Protocol) Analyze(metrics ProtocolMetrics, buf *buffer.Buffer, helper *AnalyzeHelper) error {
	http2Log.Debugf("ready to analyze HTTP/2 protocol data, connection ID: %d", metrics.(*HTTP2Metrics).connectionID)
	http2Metrics := metrics.(*HTTP2Metrics)
	buf.ResetForLoopReading()
	for {
		if !buf.PrepareForReading() {
			return nil
		}

		startPosition := buf.Position()
		header, err := http2.ReadFrameHeader(buf)
		if err != nil {
			http2Log.Debugf("failed to read frame header, %v", err)
			if buf.SkipCurrentElement() {
				break
			}
			continue
		}
		http2Log.Debugf("current reading buffer data id: %d, seq: %d", startPosition.DataID(), startPosition.Seq())

		var protocolBreak bool
		var result enums.ParseResult
		switch header.Type {
		case http2.FrameHeaders:
			result, protocolBreak, _ = r.handleHeader(&header, startPosition, http2Metrics, buf)
		case http2.FrameData:
			result, protocolBreak, _ = r.handleData(&header, startPosition, http2Metrics, buf)
		default:
			tmp := make([]byte, header.Length)
			if err := buf.ReadUntilBufferFull(tmp); err != nil {
				if errors.Is(err, buffer.ErrNotComplete) {
					result = enums.ParseResultSkipPackage
				} else {
					protocolBreak = true
				}
			} else {
				result = enums.ParseResultSuccess
			}
		}

		// if the protocol break, then stop the loop and notify the caller to skip analyze all data(just sending the detail)
		if protocolBreak {
			http2Log.Warnf("the HTTP/2 protocol break, maybe not tracing the connection from beginning, skip all data analyze in this connection, "+
				"connection ID: %d", http2Metrics.connectionID)
			helper.ProtocolBreak = true
			break
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

func (r *HTTP2Protocol) handleHeader(header *http2.FrameHeader, startPos *buffer.Position,
	metrics *HTTP2Metrics, buf *buffer.Buffer) (enums.ParseResult, bool, error) {
	bytes := make([]byte, header.Length)
	if err := buf.ReadUntilBufferFull(bytes); err != nil {
		return enums.ParseResultSkipPackage, false, err
	}
	headerData, err := metrics.hpackDecoder.DecodeFull(bytes)
	if err != nil {
		// reading the header failure, maybe not tracing the connection from beginning
		return enums.ParseResultSkipPackage, true, err
	}
	// saving stream
	streaming := metrics.streams[header.StreamID]
	headers := r.parseHeaders(headerData)
	if streaming == nil {
		streaming = &HTTP2Streaming{
			reqHeader:       headers,
			respHeader:      make(map[string]string),
			reqHeaderBuffer: buf.Slice(true, startPos, buf.Position()),
		}
		metrics.streams[header.StreamID] = streaming
		return enums.ParseResultSuccess, false, nil
	}

	status, contains := headers[":status"]
	if contains {
		streaming.isInResponse = true
		code, err := strconv.ParseInt(status, 10, 64)
		if err != nil {
			log.Warnf("cannot parse status code: %s", status)
			code = 200
		}
		streaming.status = int(code)
	}

	if !streaming.isInResponse {
		r.appendHeaders(streaming.reqHeader, headers)
		streaming.reqHeaderBuffer = buffer.CombineSlices(true, streaming.reqHeaderBuffer, buf.Slice(true, startPos, buf.Position()))
		return enums.ParseResultSuccess, false, nil
	}

	r.appendHeaders(streaming.respHeader, headers)
	streaming.respHeaderBuffer = buffer.CombineSlices(true, streaming.respHeaderBuffer, buf.Slice(true, startPos, buf.Position()))

	// is end of stream and in the response
	if header.Flags.Has(http2.FlagHeadersEndStream) {
		// should be end of the stream and send to the protocol
		r.handleWholeStream(streaming)
		// delete streaming
		delete(metrics.streams, header.StreamID)
	}
	return enums.ParseResultSuccess, false, nil
}

func (r *HTTP2Protocol) validateIsStreamOpenTooLong(metrics *HTTP2Metrics, id uint32, streaming *HTTP2Streaming) {
	// if in the response mode or the request body is not nil, then skip
	if streaming.isInResponse || streaming.reqBodyBuffer == nil {
		return
	}

	// is the body sending too long, then split the stream
	if time.Since(host.Time(streaming.respBodyBuffer.FirstSocketBuffer().StartTime())) > maxHTTP2StreamingTime {
		http2Log.Infof("detect the HTTP/2 stream is too long, split the stream, connection ID: %d, stream ID: %d, headers: %v",
			metrics.connectionID, id, streaming.reqHeader)

		r.handleWholeStream(streaming)

		// clean sent buffers
		if streaming.reqBodyBuffer != nil {
			streaming.reqBodyBuffer.Clean()
		}
	}
}

func (r *HTTP2Protocol) handleWholeStream(stream *HTTP2Streaming) {
	detailEvents := make([]*events.SocketDetailEvent, 0)
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, stream.reqHeaderBuffer)
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, stream.reqBodyBuffer)
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, stream.respHeaderBuffer)
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, stream.respBodyBuffer)

	if len(detailEvents) == 0 {
		http2Log.Warnf("cannot found any detail events for HTTP/2 protocol, data id: %d-%d",
			stream.reqHeaderBuffer.FirstSocketBuffer().DataID(), stream.respBodyBuffer.LastSocketBuffer().DataID())
		return
	}

	forwarder.SendTransferProtocolEvent(r.ctx, detailEvents, &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: forwarder.BuildOffsetTimestamp(r.firstDetail(stream.reqBodyBuffer, detailEvents[0]).StartTime),
				EndTime:   forwarder.BuildOffsetTimestamp(detailEvents[len(detailEvents)-1].EndTime),
				Version:   v3.AccessLogHTTPProtocolVersion_HTTP2,
				Request: &v3.AccessLogHTTPProtocolRequest{
					Method:             r.parseHTTPMethod(stream),
					Path:               stream.reqHeader[":path"],
					SizeOfHeadersBytes: r.bufferSizeOfZero(stream.reqHeaderBuffer),
					SizeOfBodyBytes:    r.bufferSizeOfZero(stream.reqBodyBuffer),

					Trace: analyzeTraceInfo(func(key string) string {
						return stream.reqHeader[key]
					}, http2Log),
				},
				Response: &v3.AccessLogHTTPProtocolResponse{
					StatusCode:         int32(stream.status),
					SizeOfHeadersBytes: r.bufferSizeOfZero(stream.respHeaderBuffer),
					SizeOfBodyBytes:    r.bufferSizeOfZero(stream.respBodyBuffer),
				},
			},
		},
	})
}

func (r *HTTP2Protocol) parseHTTPMethod(streaming *HTTP2Streaming) v3.AccessLogHTTPProtocolRequestMethod {
	method := streaming.reqHeader[":method"]
	if method == "" {
		return v3.AccessLogHTTPProtocolRequestMethod_Get
	}

	return transformHTTPMethod(strings.ToUpper(method))
}

func (r *HTTP2Protocol) firstDetail(buf *buffer.Buffer, def *events.SocketDetailEvent) *events.SocketDetailEvent {
	if buf == nil || buf.Details() == nil || buf.Details().Len() == 0 {
		return def
	}
	return buf.Details().Front().Value.(*events.SocketDetailEvent)
}

func (r *HTTP2Protocol) bufferSizeOfZero(buf *buffer.Buffer) uint64 {
	if buf == nil {
		return 0
	}
	return uint64(buf.DataSize())
}

func (r *HTTP2Protocol) appendHeaders(exist, needAppends map[string]string) {
	for k, v := range needAppends {
		exist[k] = v
	}
}

func (r *HTTP2Protocol) handleData(header *http2.FrameHeader, startPos *buffer.Position,
	metrics *HTTP2Metrics, buf *buffer.Buffer) (enums.ParseResult, bool, error) {
	bytes := make([]byte, header.Length)
	streaming := metrics.streams[header.StreamID]
	if streaming == nil {
		// cannot found the stream, maybe not tracing the connection from beginning
		return enums.ParseResultSkipPackage, true, nil
	}
	if err := buf.ReadUntilBufferFull(bytes); err != nil {
		return enums.ParseResultSkipPackage, false, err
	}
	if !streaming.isInResponse {
		streaming.reqBodyBuffer = buffer.CombineSlices(true, streaming.reqBodyBuffer, buf.Slice(true, startPos, buf.Position()))
	} else {
		streaming.respBodyBuffer = buffer.CombineSlices(true, streaming.respBodyBuffer, buf.Slice(true, startPos, buf.Position()))
	}

	r.validateIsStreamOpenTooLong(metrics, header.StreamID, streaming)
	return enums.ParseResultSuccess, false, nil
}

func (r *HTTP2Protocol) parseHeaders(headers []hpack.HeaderField) map[string]string {
	result := make(map[string]string)
	for _, header := range headers {
		result[header.Name] = header.Value
	}
	return result
}
