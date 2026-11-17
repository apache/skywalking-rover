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

#pragma once

#include "api.h"

#define CONNECTION_PROTOCOL_UNKNOWN 0
#define CONNECTION_PROTOCOL_HTTP1 1
#define CONNECTION_PROTOCOL_HTTP2 2
// the ids from 3 on belong to the protocols an override of protocol_analyzer_ext.h adds

// HTTP/2 frames (RFC 7540 4.1 and 6): the header length, the frame types and the flags the BPF side reads
#define HTTP2_FRAME_HEADER_LEN 9
#define HTTP2_FRAME_TYPE_DATA 0x0
#define HTTP2_FRAME_TYPE_HEADERS 0x1
#define HTTP2_FRAME_TYPE_PRIORITY 0x2
#define HTTP2_FRAME_TYPE_SETTINGS 0x4
#define HTTP2_FRAME_TYPE_PING 0x6
#define HTTP2_FRAME_TYPE_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_TYPE_CONTINUATION 0x9
// the highest frame type RFC 7540 defines
#define HTTP2_FRAME_TYPE_MAX HTTP2_FRAME_TYPE_CONTINUATION
#define HTTP2_FLAG_ACK 0x1
#define HTTP2_FLAG_PADDED 0x8

#define CONNECTION_MESSAGE_TYPE_UNKNOWN 0
#define CONNECTION_MESSAGE_TYPE_REQUEST 1
#define CONNECTION_MESSAGE_TYPE_RESPONSE 2
// the protocol is recognized but the message does not tell whether the sender is the client or the server
#define CONNECTION_MESSAGE_TYPE_ANY 3

// HTTP 1.x
// request frame format: https://www.rfc-editor.org/rfc/rfc2068.html#section-5
// response frame format: https://www.rfc-editor.org/rfc/rfc2068.html#section-6
static __inline __u32 infer_http1_message(const char* buf, size_t count) {
    if (count < 16) {
        return CONNECTION_MESSAGE_TYPE_UNKNOWN;
    }
    // response
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        return CONNECTION_MESSAGE_TYPE_RESPONSE;
    }
    // request
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O'
        && buf[5] == 'N' && buf[6] == 'S')
    {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N' && buf[4] == 'E'
        && buf[5] == 'C' && buf[6] == 'T')
    {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'T' && buf[1] == 'R' && buf[2] == 'A' && buf[3] == 'C' && buf[4] == 'E') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    return CONNECTION_MESSAGE_TYPE_UNKNOWN;
}

// http2_frame_length decodes the 24 bit length of an HTTP/2 frame header (RFC 7540 4.1)
static __always_inline __u32 http2_frame_length(const __u8 *header) {
    return ((__u32)header[0] << 16) | ((__u32)header[1] << 8) | header[2];
}

static bool is_http2_magic(const char *buf_src, size_t count)
{
	static const char magic[] = "PRI * HTTP/2";
	char buffer[sizeof(magic)] = { 0 };
	if (count < sizeof(magic) - 1) {
		return false;
	}
	bpf_probe_read(buffer, sizeof(buffer) - 1, buf_src);
	for (int idx = 0; idx < sizeof(magic) - 1; ++idx) {
		if (magic[idx] == buffer[idx])
			continue;
		return false;
	}
	return true;
}

// is_http2_settings_frame: a message starting with a SETTINGS frame on stream 0 (RFC 7540 6.5),
// which is the first frame both endpoints send after the (client) preface
static __inline bool is_http2_settings_frame(const char *buf, size_t count)
{
	static const __u8 kFrameBasicSize = HTTP2_FRAME_HEADER_LEN;
	__u8 frame[HTTP2_FRAME_HEADER_LEN] = { 0 };
	if (count < kFrameBasicSize) {
		return false;
	}
	bpf_probe_read(frame, sizeof(frame), buf);
	__u32 length = http2_frame_length(frame);
	// type SETTINGS(0x4), flags only ACK(0x1) allowed, stream id 0, and a length that is a multiple of
	// the 6 byte setting entry. The length is bounded by the default SETTINGS_MAX_FRAME_SIZE rather
	// than by a guess at how many settings a peer sends: a client that sends more of them would
	// otherwise not be recognized as HTTP/2 when the capture starts at its SETTINGS frame, which is
	// the silent "no protocol" case this inference exists to avoid.
	if (frame[3] != HTTP2_FRAME_TYPE_SETTINGS || (frame[4] & ~HTTP2_FLAG_ACK & 0xff) || (frame[5] & 0x7f) || frame[6] || frame[7] || frame[8]) {
		return false;
	}
	if (length % 6 != 0 || length > 16384) {
		return false;
	}
	return true;
}

// HTTP 2.x
// frame format: https://www.rfc-editor.org/rfc/rfc7540.html#section-4.1
static __inline __u32 infer_http2_message(const char* buf, size_t count) {
    static const __u8 kFrameBasicSize = HTTP2_FRAME_HEADER_LEN; // including Length, Type, Flags, Reserved, Stream Identity
    static const __u8 kFrameTypeHeader = HTTP2_FRAME_TYPE_HEADERS; // https://www.rfc-editor.org/rfc/rfc7540.html#section-6.2
    static const __u8 kFrameLoopCount = 5;

    static const __u8 kStaticTableMaxSize = 61;// https://www.rfc-editor.org/rfc/rfc7541#appendix-A
    static const __u8 kStaticTableAuth = 1;
    static const __u8 kStaticTableGet = 2;
    static const __u8 kStaticTablePost = 3;
    static const __u8 kStaticTablePath1 = 4;
    static const __u8 kStaticTablePath2 = 5;

    // the buffer size must bigger than basic frame size
    if (count < kFrameBasicSize) {
		return CONNECTION_MESSAGE_TYPE_UNKNOWN;
    }

    // frame info
    __u8 frame[21] = { 0 };
    __u32 frameOffset = 0;
    // header info
    __u8 staticInx, headerBlockFragmentOffset;

    // the client connection preface (RFC 7540 3.5) is only ever sent by the client, so the message
    // is an HTTP/2 request and the connection is recognized from its very first byte
    if (is_http2_magic(buf, count)) {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    // a message starting with the SETTINGS frame (server preface, or client SETTINGS when the preface
    // was written separately): HTTP/2 for sure, but it does not tell the role
    if (is_http2_settings_frame(buf, count)) {
        return CONNECTION_MESSAGE_TYPE_ANY;
    }

    // each all frame
#pragma unroll
    for (__u8 i = 0; i < kFrameLoopCount; i++) {
        if (frameOffset >= count) {
            break;
        }

        // read frame
        bpf_probe_read(frame, sizeof(frame), buf + frameOffset);
        frameOffset += (bpf_ntohl(*(__u32 *) frame) >> 8) + kFrameBasicSize;

        // frametype only accept 0x00 - 0x09
        if (frame[3] > HTTP2_FRAME_TYPE_MAX) {
            return CONNECTION_MESSAGE_TYPE_UNKNOWN;
        }
        // is header frame
        if (frame[3] != kFrameTypeHeader) {
            continue;
        }

        // validate the header(unset): not HTTP2 protocol
        // this frame must is a send request
        if ((frame[4] & 0xd2) || frame[5] & 0x01) {
            return CONNECTION_MESSAGE_TYPE_UNKNOWN;
        }

        // stream ID cannot be 0
        __u32 streamID = ((frame[5] & 0x7F) << 24) | (frame[6] << 16) | (frame[7] << 8) | frame[8];
        if (streamID == 0) {
            return CONNECTION_MESSAGE_TYPE_UNKNOWN;
        }

        // locate the header block fragment offset
        headerBlockFragmentOffset = kFrameBasicSize;
        if (frame[4] & HTTP2_FLAG_PADDED) {
            headerBlockFragmentOffset += 1;
        }
        if (frame[4] & 0x20) {  // PRIORITY flag is set
            headerBlockFragmentOffset += 5;
        }

#pragma unroll
        for (__u8 j = 0; j <= kStaticTablePath2; j++) {
            if (headerBlockFragmentOffset > count) {
                return CONNECTION_MESSAGE_TYPE_UNKNOWN;
            }
            staticInx = frame[headerBlockFragmentOffset] & 0x7f;
            if (staticInx <= kStaticTableMaxSize && staticInx > 0) {
                if (staticInx == kStaticTableAuth ||
                    staticInx == kStaticTableGet ||
                    staticInx == kStaticTablePost ||
                    staticInx == kStaticTablePath1 ||
                    staticInx == kStaticTablePath2) {
                    return CONNECTION_MESSAGE_TYPE_REQUEST;
                } else {
                    return CONNECTION_MESSAGE_TYPE_RESPONSE;
                }
            }
            headerBlockFragmentOffset++;
        }
    }

	return CONNECTION_MESSAGE_TYPE_UNKNOWN;
}

// the protocols a build recognizes beyond HTTP/1.x and HTTP/2, see protocol_analyzer_ext.h
#include <protocol_analyzer_ext.h>

static __noinline __u32 analyze_protocol(char *buf, __u32 count, __u8 *protocol_ref) {
    __u32 protocol = CONNECTION_PROTOCOL_UNKNOWN, type = CONNECTION_MESSAGE_TYPE_UNKNOWN;

    // support http 1.x and 2.x
    if ((type = infer_http1_message(buf, count)) != CONNECTION_PROTOCOL_UNKNOWN) {
        protocol = CONNECTION_PROTOCOL_HTTP1;
    } else if ((type = infer_http2_message(buf, count)) != CONNECTION_PROTOCOL_UNKNOWN) {
        protocol = CONNECTION_PROTOCOL_HTTP2;
    } else {
        type = infer_extra_protocol(buf, count, &protocol);
    }

    if (protocol != CONNECTION_PROTOCOL_UNKNOWN) {
        *protocol_ref = protocol;
    }

    return type;
}