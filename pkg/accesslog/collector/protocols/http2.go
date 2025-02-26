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
	"fmt"
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

type HTTP2StreamAnalyze func(stream *HTTP2Streaming) error

type HTTP2Protocol struct {
	ctx     *common.AccessLogContext
	analyze HTTP2StreamAnalyze
}

func NewHTTP2Analyzer(ctx *common.AccessLogContext, analyze HTTP2StreamAnalyze) *HTTP2Protocol {
	protocol := &HTTP2Protocol{ctx: ctx}
	if analyze == nil {
		protocol.analyze = protocol.handleWholeStream
	} else {
		protocol.analyze = analyze
	}
	return protocol
}

type HTTP2Metrics struct {
	connectionID uint64
	randomID     uint64
	hpackDecoder *hpack.Decoder

	streams map[uint32]*HTTP2Streaming
}

type HTTP2Streaming struct {
	ReqHeader        map[string]string
	RespHeader       map[string]string
	ReqHeaderBuffer  *buffer.Buffer
	ReqBodyBuffer    *buffer.Buffer
	IsInResponse     bool
	Status           int
	RespHeaderBuffer *buffer.Buffer
	RespBodyBuffer   *buffer.Buffer
	Connection       *PartitionConnection
}

func (r *HTTP2Protocol) GenerateConnection(connectionID, randomID uint64) ProtocolMetrics {
	return &HTTP2Metrics{
		connectionID: connectionID,
		randomID:     randomID,
		hpackDecoder: hpack.NewDecoder(4096, nil),
		streams:      make(map[uint32]*HTTP2Streaming),
	}
}

func (r *HTTP2Protocol) Analyze(connection *PartitionConnection, helper *AnalyzeHelper) error {
	http2Metrics := connection.Metrics(enums.ConnectionProtocolHTTP2).(*HTTP2Metrics)
	buf := connection.Buffer(enums.ConnectionProtocolHTTP2)
	http2Log.Debugf("ready to analyze HTTP/2 protocol data, connection ID: %d, random ID: %d",
		http2Metrics.connectionID, http2Metrics.randomID)
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
			result, protocolBreak, _ = r.handleHeader(connection, &header, startPosition, http2Metrics, buf)
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
			finishReading = buf.RemoveReadElements(false)
		case enums.ParseResultSkipPackage:
			finishReading = buf.SkipCurrentElement()
		}

		if finishReading {
			break
		}
	}

	return nil
}

func (r *HTTP2Protocol) ForProtocol() enums.ConnectionProtocol {
	return enums.ConnectionProtocolHTTP2
}

func (r *HTTP2Protocol) handleHeader(connection *PartitionConnection, header *http2.FrameHeader, startPos *buffer.Position,
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
			ReqHeader:       headers,
			RespHeader:      make(map[string]string),
			ReqHeaderBuffer: buf.Slice(true, startPos, buf.Position()),
			Connection:      connection,
		}
		metrics.streams[header.StreamID] = streaming
		return enums.ParseResultSuccess, false, nil
	}

	status, contains := headers[":status"]
	if contains {
		streaming.IsInResponse = true
		code, err := strconv.ParseInt(status, 10, 64)
		if err != nil {
			log.Warnf("cannot parse status code: %s", status)
			code = 200
		}
		streaming.Status = int(code)
	}

	if !streaming.IsInResponse {
		r.AppendHeaders(streaming.ReqHeader, headers)
		streaming.ReqHeaderBuffer = buffer.CombineSlices(true, buf, streaming.ReqHeaderBuffer, buf.Slice(true, startPos, buf.Position()))
		return enums.ParseResultSuccess, false, nil
	}

	r.AppendHeaders(streaming.RespHeader, headers)
	streaming.RespHeaderBuffer = buffer.CombineSlices(true, buf, streaming.RespHeaderBuffer, buf.Slice(true, startPos, buf.Position()))

	// is end of stream and in the response
	if header.Flags.Has(http2.FlagHeadersEndStream) {
		// should be end of the stream and send to the protocol
		_ = r.analyze(streaming)
		// delete streaming
		delete(metrics.streams, header.StreamID)
	}
	return enums.ParseResultSuccess, false, nil
}

func (r *HTTP2Protocol) validateIsStreamOpenTooLong(metrics *HTTP2Metrics, id uint32, streaming *HTTP2Streaming) {
	// if in the response mode or the request body is not nil, then skip
	if streaming.IsInResponse || streaming.ReqBodyBuffer == nil {
		return
	}

	// is the body sending too long, then split the stream
	socketBuffer := streaming.ReqBodyBuffer.FirstSocketBuffer()
	if socketBuffer == nil {
		return
	}
	if time.Since(host.Time(socketBuffer.StartTime())) > maxHTTP2StreamingTime {
		http2Log.Infof("detect the HTTP/2 stream is too long, split the stream, connection ID: %d, stream ID: %d, headers: %v",
			metrics.connectionID, id, streaming.ReqHeader)

		_ = r.analyze(streaming)

		// clean sent buffers
		if streaming.ReqBodyBuffer != nil {
			streaming.ReqBodyBuffer.Clean()
		}
	}
}

func (r *HTTP2Protocol) handleWholeStream(stream *HTTP2Streaming) error {
	details := make([]events.SocketDetail, 0)
	var allInclude = true
	var idRange *buffer.DataIDRange
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.ReqHeaderBuffer, idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.ReqBodyBuffer, idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.RespHeaderBuffer, idRange, allInclude)
	details, idRange, allInclude = AppendSocketDetailsFromBuffer(details, stream.RespBodyBuffer, idRange, allInclude)

	if !allInclude {
		return fmt.Errorf("cannot found any detail events for HTTP/2 protocol, data id: %d-%d, current details count: %d",
			stream.ReqHeaderBuffer.FirstSocketBuffer().DataID(), stream.RespBodyBuffer.LastSocketBuffer().DataID(),
			len(details))
	}
	idRange.DeleteDetails(stream.ReqHeaderBuffer)

	streamHost := stream.ReqHeader[":authority"]
	if streamHost == "" {
		streamHost = stream.ReqHeader[":host"]
	}
	forwarder.SendTransferProtocolEvent(r.ctx, details, &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: forwarder.BuildOffsetTimestamp(r.FirstDetail(stream.ReqBodyBuffer, details[0]).GetStartTime()),
				EndTime:   forwarder.BuildOffsetTimestamp(details[len(details)-1].GetEndTime()),
				Version:   v3.AccessLogHTTPProtocolVersion_HTTP2,
				Request: &v3.AccessLogHTTPProtocolRequest{
					Method:             r.ParseHTTPMethod(stream),
					Path:               stream.ReqHeader[":path"],
					SizeOfHeadersBytes: r.BufferSizeOfZero(stream.ReqHeaderBuffer),
					SizeOfBodyBytes:    r.BufferSizeOfZero(stream.ReqBodyBuffer),
					Host:               streamHost,
					Trace: AnalyzeTraceInfo(func(key string) string {
						return stream.ReqHeader[key]
					}, http2Log),
				},
				Response: &v3.AccessLogHTTPProtocolResponse{
					StatusCode:         int32(stream.Status),
					SizeOfHeadersBytes: r.BufferSizeOfZero(stream.RespHeaderBuffer),
					SizeOfBodyBytes:    r.BufferSizeOfZero(stream.RespBodyBuffer),
				},
			},
		},
	})
	return nil
}

func (r *HTTP2Protocol) ParseHTTPMethod(streaming *HTTP2Streaming) v3.AccessLogHTTPProtocolRequestMethod {
	method := streaming.ReqHeader[":method"]
	if method == "" {
		return v3.AccessLogHTTPProtocolRequestMethod_Get
	}

	return TransformHTTPMethod(strings.ToUpper(method))
}

func (r *HTTP2Protocol) FirstDetail(buf *buffer.Buffer, def events.SocketDetail) events.SocketDetail {
	if buf == nil {
		return def
	}
	details := buf.BuildDetails()
	if details == nil || details.Len() == 0 {
		return def
	}
	return details.Front().Value.(events.SocketDetail)
}

func (r *HTTP2Protocol) BufferSizeOfZero(buf *buffer.Buffer) uint64 {
	if buf == nil {
		return 0
	}
	return uint64(buf.DataSize())
}

func (r *HTTP2Protocol) AppendHeaders(exist, needAppends map[string]string) {
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
	if !streaming.IsInResponse {
		streaming.ReqBodyBuffer = buffer.CombineSlices(true, buf, streaming.ReqBodyBuffer, buf.Slice(true, startPos, buf.Position()))
	} else {
		streaming.RespBodyBuffer = buffer.CombineSlices(true, buf, streaming.RespBodyBuffer, buf.Slice(true, startPos, buf.Position()))
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
