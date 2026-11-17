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

package sender

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"

	v32 "skywalking.apache.org/repo/goapi/collect/common/v3"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// Wire encoding of the access log messages: each log is encoded once, when it can no longer change, and waits
// in the backlog as bytes; a stream message is the concatenation of its header and log fields. The encoder writes
// exactly what proto.MarshalOptions{Deterministic: true} writes for the messages of encodedFields; with other
// generated messages (another goapi version) every field goes through proto.Marshal instead. The kernel and
// protocol logs skip unknown fields, see kernelLog.

var deterministic = proto.MarshalOptions{Deterministic: true}

// encodedFields is every message the encoder writes, with its fields as "<number> <kind>[ repeated][ oneof]"
//
//nolint:goconst // a table of field layouts, messages with equal layouts are unrelated
var encodedFields = map[protoreflect.Name]string{
	"EBPFAccessLogMessage":            "1 message, 2 message, 3 message repeated, 4 message",
	"EBPFAccessLogNodeInfo":           "1 string, 2 message repeated, 3 message, 4 string, 5 message",
	"EBPFAccessLogNodeNetInterface":   "1 int32, 2 int32, 3 string",
	"Instant":                         "1 int64, 2 int32",
	"EBPFAccessLogPolicy":             "1 string repeated",
	"AccessLogConnection":             "1 message, 2 message, 3 enum, 4 enum, 5 enum, 6 message",
	"ConnectionAddress":               "1 message oneof, 2 message oneof",
	"KubernetesProcessAddress":        "1 string, 2 string, 3 string, 4 string, 5 int32",
	"IPAddress":                       "1 string, 2 int32",
	"ConnectionAttachment":            "1 message oneof",
	"ZTunnelAttachmentEnvironment":    "1 string, 2 enum, 3 enum, 4 message repeated",
	"KeyStringValuePair":              "1 string, 2 string",
	"AccessLogKernelLog":              "1 message oneof, 2 message oneof, 3 message oneof, 4 message oneof, 5 message oneof",
	"AccessLogKernelConnectOperation": "1 message, 2 message, 3 bool",
	"EBPFTimestamp":                   "1 message oneof",
	"EBPFOffsetTimestamp":             "1 uint64",
	"AccessLogKernelAcceptOperation":  "1 message, 2 message",
	"AccessLogKernelCloseOperation":   "1 message, 2 message, 3 bool",
	"AccessLogKernelReadOperation":    "1 message, 2 message, 3 enum, 4 message, 5 message, 6 message",
	"AccessLogKernelReadL2Metrics":    "1 uint32, 2 uint32, 3 uint64, 4 uint64, 5 uint64",
	"AccessLogKernelReadL3Metrics":    "1 uint64, 2 uint64, 3 uint64, 4 uint64, 5 uint64",
	"AccessLogKernelReadL4Metrics":    "1 uint64",
	"AccessLogKernelWriteOperation":   "1 message, 2 message, 3 enum, 4 message, 5 message, 6 message",
	"AccessLogKernelWriteL4Metrics":   "1 uint64, 2 int64, 3 int64, 4 message repeated, 5 int64",
	"AccessLogLossPackageMetrics":     "1 string, 2 int32",
	"AccessLogKernelWriteL3Metrics":   "1 uint64, 2 uint64, 3 uint64, 5 uint64, 6 uint64, 7 uint64, 8 uint64",
	"AccessLogKernelWriteL2Metrics":   "1 uint64, 2 uint32, 3 uint64, 4 uint64, 5 uint64",
	"AccessLogProtocolLogs":           "1 message oneof",
	"AccessLogHTTPProtocol":           "1 message, 2 message, 3 enum, 4 message, 5 message",
	"AccessLogHTTPProtocolRequest":    "1 enum, 2 string, 3 uint64, 4 uint64, 5 message, 6 string",
	"AccessLogTraceInfo":              "1 enum, 2 string, 3 string, 4 string",
	"AccessLogHTTPProtocolResponse":   "1 int32, 3 uint64, 4 uint64",
}

// wireEncodingCovered tells whether the generated messages are the ones the encoder is written for
var wireEncodingCovered = uncoveredMessages() == nil

// uncoveredMessages lists the messages of EBPFAccessLogMessage whose fields differ from encodedFields
func uncoveredMessages() []string {
	var result []string
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		fields := md.Fields()
		described := make([]string, 0, fields.Len())
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			d := fmt.Sprintf("%d %s", f.Number(), f.Kind())
			if f.Cardinality() == protoreflect.Repeated {
				d += " repeated"
			}
			if f.ContainingOneof() != nil {
				d += " oneof"
			}
			described = append(described, d)
			if f.Message() != nil {
				walk(f.Message())
			}
		}
		if got := strings.Join(described, ", "); encodedFields[md.Name()] != got {
			result = append(result, fmt.Sprintf("%s: %s", md.FullName(), got))
		}
	}
	walk((&v3.EBPFAccessLogMessage{}).ProtoReflect().Descriptor())
	return result
}

// field numbers of EBPFAccessLogMessage
const (
	messageNodeField        protowire.Number = 1
	messageConnectionField  protowire.Number = 2
	messageKernelLogsField  protowire.Number = 3
	messageProtocolLogField protowire.Number = 4
)

// EncodeAccessLogMessage encodes the message the way the sender does, which is what
// proto.MarshalOptions{Deterministic: true}.Marshal gives
func EncodeAccessLogMessage(m *v3.EBPFAccessLogMessage) ([]byte, error) {
	e := &wireEncoder{}
	e.encodeHeader(m.Node, m.Connection)
	e.encodeProtocolLog(m.KernelLogs, m.ProtocolLog)
	e.unknown(m)
	return e.buf, e.err
}

// wireEncoder appends the fields of the messages to buf, err is the first failure
type wireEncoder struct {
	buf []byte
	err error
}

func (e *wireEncoder) fail(err error) {
	if e.err == nil {
		e.err = err
	}
}

// begin starts a message field: its length is written by end, on the byte reserved here, which is
// enough for a message shorter than 128 bytes and is widened otherwise
func (e *wireEncoder) begin(num protowire.Number) int {
	e.buf = protowire.AppendTag(e.buf, num, protowire.BytesType)
	e.buf = append(e.buf, 0)
	return len(e.buf)
}

// lengthPadding widens a length: a varint is at most 10 bytes, one of them reserved by begin
var lengthPadding [9]byte

func (e *wireEncoder) end(start int) {
	n := len(e.buf) - start
	if n < 0x80 {
		e.buf[start-1] = byte(n)
		return
	}
	e.buf = slices.Insert(e.buf, start, lengthPadding[:protowire.SizeVarint(uint64(n))-1]...)
	protowire.AppendVarint(e.buf[:start-1], uint64(n))
}

// fallback writes the message field with proto.Marshal, when the encoder is not written for the generated messages
func (e *wireEncoder) fallback(num protowire.Number, m proto.Message) {
	start := e.begin(num)
	var err error
	e.buf, err = deterministic.MarshalAppend(e.buf, m)
	if err != nil {
		e.fail(err)
	}
	e.end(start)
}

// unknown writes the unknown fields of the message, which proto.Marshal writes after the known ones
func (e *wireEncoder) unknown(m protoreflect.ProtoMessage) {
	if u := m.ProtoReflect().GetUnknown(); len(u) > 0 {
		e.buf = append(e.buf, u...)
	}
}

func (e *wireEncoder) uint64Field(num protowire.Number, v uint64) {
	if v != 0 {
		e.buf = protowire.AppendVarint(protowire.AppendTag(e.buf, num, protowire.VarintType), v)
	}
}

// int32Field writes an int32 or an enum: a negative value is sign extended to 10 bytes, as protobuf does
func (e *wireEncoder) int32Field(num protowire.Number, v int32) {
	e.uint64Field(num, uint64(int64(v)))
}

func (e *wireEncoder) int64Field(num protowire.Number, v int64) {
	e.uint64Field(num, uint64(v))
}

func (e *wireEncoder) boolField(num protowire.Number, v bool) {
	if v {
		e.buf = append(protowire.AppendTag(e.buf, num, protowire.VarintType), 1)
	}
}

// stringValue writes a string, even empty, which must be UTF-8 like proto.Marshal requires of a proto3 string
func (e *wireEncoder) stringValue(num protowire.Number, v, name string) {
	if !utf8.ValidString(v) {
		e.fail(fmt.Errorf("string field %s contains invalid UTF-8", name))
	}
	e.buf = protowire.AppendString(protowire.AppendTag(e.buf, num, protowire.BytesType), v)
}

// stringField writes a string field, skipped when empty
func (e *wireEncoder) stringField(num protowire.Number, v, name string) {
	if v != "" {
		e.stringValue(num, v, name)
	}
}

func (e *wireEncoder) node(num protowire.Number, m *v3.EBPFAccessLogNodeInfo) {
	if !wireEncodingCovered {
		e.fallback(num, m)
		return
	}
	start := e.begin(num)
	e.stringField(1, m.Name, "EBPFAccessLogNodeInfo.name")
	for _, n := range m.NetInterfaces {
		s := e.begin(2)
		if n != nil {
			e.int32Field(1, n.Index)
			e.int32Field(2, n.Mtu)
			e.stringField(3, n.Name, "EBPFAccessLogNodeNetInterface.name")
			e.unknown(n)
		}
		e.end(s)
	}
	if m.BootTime != nil {
		e.instant(3, m.BootTime)
	}
	e.stringField(4, m.ClusterName, "EBPFAccessLogNodeInfo.clusterName")
	if m.Policy != nil {
		s := e.begin(5)
		for _, ns := range m.Policy.ExcludeNamespaces {
			e.stringValue(1, ns, "EBPFAccessLogPolicy.excludeNamespaces")
		}
		e.unknown(m.Policy)
		e.end(s)
	}
	e.unknown(m)
	e.end(start)
}

func (e *wireEncoder) instant(num protowire.Number, m *v32.Instant) {
	start := e.begin(num)
	e.int64Field(1, m.Seconds)
	e.int32Field(2, m.Nanos)
	e.unknown(m)
	e.end(start)
}

func (e *wireEncoder) connection(num protowire.Number, m *v3.AccessLogConnection) {
	if !wireEncodingCovered {
		e.fallback(num, m)
		return
	}
	start := e.begin(num)
	if m.Local != nil {
		e.address(1, m.Local)
	}
	if m.Remote != nil {
		e.address(2, m.Remote)
	}
	e.int32Field(3, int32(m.Role))
	e.int32Field(4, int32(m.TlsMode))
	e.int32Field(5, int32(m.Protocol))
	if m.Attachment != nil {
		e.attachment(6, m.Attachment)
	}
	e.unknown(m)
	e.end(start)
}

func (e *wireEncoder) address(num protowire.Number, m *v3.ConnectionAddress) {
	start := e.begin(num)
	switch a := m.Address.(type) {
	case *v3.ConnectionAddress_Kubernetes:
		s := e.begin(1)
		if k := a.Kubernetes; k != nil {
			e.stringField(1, k.ServiceName, "KubernetesProcessAddress.serviceName")
			e.stringField(2, k.PodName, "KubernetesProcessAddress.podName")
			e.stringField(3, k.ContainerName, "KubernetesProcessAddress.containerName")
			e.stringField(4, k.ProcessName, "KubernetesProcessAddress.processName")
			e.int32Field(5, k.Port)
			e.unknown(k)
		}
		e.end(s)
	case *v3.ConnectionAddress_Ip:
		s := e.begin(2)
		if ip := a.Ip; ip != nil {
			e.stringField(1, ip.Host, "IPAddress.host")
			e.int32Field(2, ip.Port)
			e.unknown(ip)
		}
		e.end(s)
	}
	e.unknown(m)
	e.end(start)
}

func (e *wireEncoder) attachment(num protowire.Number, m *v3.ConnectionAttachment) {
	start := e.begin(num)
	if a, ok := m.Environment.(*v3.ConnectionAttachment_ZTunnel); ok {
		s := e.begin(1)
		if z := a.ZTunnel; z != nil {
			e.stringField(1, z.RealDestinationIp, "ZTunnelAttachmentEnvironment.real_destination_ip")
			e.int32Field(2, int32(z.By))
			e.int32Field(3, int32(z.SecurityPolicy))
			for _, kv := range z.Addition {
				p := e.begin(4)
				if kv != nil {
					e.stringField(1, kv.Key, "KeyStringValuePair.key")
					e.stringField(2, kv.Value, "KeyStringValuePair.value")
					e.unknown(kv)
				}
				e.end(p)
			}
			e.unknown(z)
		}
		e.end(s)
	}
	e.unknown(m)
	e.end(start)
}

func (e *wireEncoder) timestamp(num protowire.Number, m *v3.EBPFTimestamp) {
	start := e.begin(num)
	if t, ok := m.Timestamp.(*v3.EBPFTimestamp_Offset); ok {
		s := e.begin(1)
		if o := t.Offset; o != nil {
			e.uint64Field(1, o.Offset)
		}
		e.end(s)
	}
	e.end(start)
}

// kernelLog and protocolLogs, and the messages they hold, write no unknown fields: only proto.Unmarshal,
// proto.Merge or SetUnknown give a message unknown fields, and the agent applies none of them to the logs it
// builds (TestNoUnknownFieldsInTheLogs), so the per-log GetUnknown calls are saved. The header keeps them.
// A kernel log is always an element of the kernel logs field of the message.
func (e *wireEncoder) kernelLog(m *v3.AccessLogKernelLog) {
	if !wireEncodingCovered {
		e.fallback(messageKernelLogsField, m)
		return
	}
	start := e.begin(messageKernelLogsField)
	// an element of a repeated field is written even when nil
	if m != nil {
		switch op := m.Operation.(type) {
		case *v3.AccessLogKernelLog_Connect:
			s := e.begin(1)
			if c := op.Connect; c != nil {
				e.startAndEndTime(c.StartTime, c.EndTime)
				e.boolField(3, c.Success)
			}
			e.end(s)
		case *v3.AccessLogKernelLog_Accept:
			s := e.begin(2)
			if a := op.Accept; a != nil {
				e.startAndEndTime(a.StartTime, a.EndTime)
			}
			e.end(s)
		case *v3.AccessLogKernelLog_Close:
			s := e.begin(3)
			if c := op.Close; c != nil {
				e.startAndEndTime(c.StartTime, c.EndTime)
				e.boolField(3, c.Success)
			}
			e.end(s)
		case *v3.AccessLogKernelLog_Read:
			e.readOperation(4, op.Read)
		case *v3.AccessLogKernelLog_Write:
			e.writeOperation(5, op.Write)
		}
	}
	e.end(start)
}

// transferLog writes the kernel log of the TransferLog, the bytes kernelLog writes for the messages its
// KernelLogBuilder builds: an operation with both times set, the syscall and the metrics messages in order,
// as an element of the kernel logs field of the message
func (e *wireEncoder) transferLog(t *forwarder.TransferLog) {
	start := e.begin(messageKernelLogsField)
	operation := protowire.Number(4)
	if t.Write {
		operation = 5
	}
	s := e.begin(operation)
	e.offsetTimestamp(1, t.StartTime)
	e.offsetTimestamp(2, t.EndTime)
	e.int32Field(3, t.Syscall)
	for i := range t.Metrics {
		if !t.HasMetrics[i] {
			continue
		}
		m := e.begin(protowire.Number(4 + i))
		for f := 1; f < len(t.Metrics[i]); f++ {
			e.uint64Field(protowire.Number(f), t.Metrics[i][f])
		}
		e.end(m)
	}
	e.end(s)
	e.end(start)
}

// offsetTimestamp is timestamp for the EBPFTimestamp that forwarder.OffsetTimestamp builds
func (e *wireEncoder) offsetTimestamp(num protowire.Number, offset uint64) {
	start := e.begin(num)
	s := e.begin(1)
	e.uint64Field(1, offset)
	e.end(s)
	e.end(start)
}

// startAndEndTime writes the fields 1 and 2 every operation has
func (e *wireEncoder) startAndEndTime(startTime, endTime *v3.EBPFTimestamp) {
	if startTime != nil {
		e.timestamp(1, startTime)
	}
	if endTime != nil {
		e.timestamp(2, endTime)
	}
}

func (e *wireEncoder) readOperation(num protowire.Number, m *v3.AccessLogKernelReadOperation) {
	start := e.begin(num)
	// a oneof wrapper holding nil is an empty message
	if m != nil {
		e.startAndEndTime(m.StartTime, m.EndTime)
		e.int32Field(3, int32(m.Syscall))
		if l2 := m.L2Metrics; l2 != nil {
			s := e.begin(4)
			e.uint64Field(1, uint64(l2.Ifindex))
			e.uint64Field(2, uint64(l2.TotalPackageCount))
			e.uint64Field(3, l2.TotalPackageSize)
			e.uint64Field(4, l2.TotalPackageToQueueDuration)
			e.uint64Field(5, l2.TotalRcvPackageFromQueueDuration)
			e.end(s)
		}
		if l3 := m.L3Metrics; l3 != nil {
			s := e.begin(5)
			e.uint64Field(1, l3.TotalDuration)
			e.uint64Field(2, l3.TotalRecvDuration)
			e.uint64Field(3, l3.TotalLocalDuration)
			e.uint64Field(4, l3.TotalNetFilterCount)
			e.uint64Field(5, l3.TotalNetFilterDuration)
			e.end(s)
		}
		if l4 := m.L4Metrics; l4 != nil {
			s := e.begin(6)
			e.uint64Field(1, l4.TotalDuration)
			e.end(s)
		}
	}
	e.end(start)
}

func (e *wireEncoder) writeOperation(num protowire.Number, m *v3.AccessLogKernelWriteOperation) {
	start := e.begin(num)
	// a oneof wrapper holding nil is an empty message
	if m != nil {
		e.startAndEndTime(m.StartTime, m.EndTime)
		e.int32Field(3, int32(m.Syscall))
		if l4 := m.L4Metrics; l4 != nil {
			s := e.begin(4)
			e.uint64Field(1, l4.TotalDuration)
			e.int64Field(2, l4.TotalTransmitPackageCount)
			e.int64Field(3, l4.TotalRetransmitPackageCount)
			for _, loss := range l4.LossPackageMetrics {
				p := e.begin(4)
				if loss != nil {
					e.stringField(1, loss.Location, "AccessLogLossPackageMetrics.location")
					e.int32Field(2, loss.Count)
				}
				e.end(p)
			}
			e.int64Field(5, l4.TotalPackageSize)
			e.end(s)
		}
		if l3 := m.L3Metrics; l3 != nil {
			s := e.begin(5)
			e.uint64Field(1, l3.TotalDuration)
			e.uint64Field(2, l3.TotalLocalDuration)
			e.uint64Field(3, l3.TotalOutputDuration)
			e.uint64Field(5, l3.TotalResolveMACCount)
			e.uint64Field(6, l3.TotalResolveMACDuration)
			e.uint64Field(7, l3.TotalNetFilterCount)
			e.uint64Field(8, l3.TotalNetFilterDuration)
			e.end(s)
		}
		if l2 := m.L2Metrics; l2 != nil {
			s := e.begin(6)
			e.uint64Field(1, l2.TotalDuration)
			e.uint64Field(2, uint64(l2.Ifindex))
			e.uint64Field(3, l2.TotalEnterQueueBufferCount)
			e.uint64Field(4, l2.TotalReadySendDuration)
			e.uint64Field(5, l2.TotalNetDeviceSendDuration)
			e.end(s)
		}
	}
	e.end(start)
}

func (e *wireEncoder) protocolLogs(num protowire.Number, m *v3.AccessLogProtocolLogs) {
	if !wireEncodingCovered {
		e.fallback(num, m)
		return
	}
	start := e.begin(num)
	if p, ok := m.Protocol.(*v3.AccessLogProtocolLogs_Http); ok {
		e.httpProtocol(1, p.Http)
	}
	e.end(start)
}

func (e *wireEncoder) httpProtocol(num protowire.Number, m *v3.AccessLogHTTPProtocol) {
	start := e.begin(num)
	// a oneof wrapper holding nil is an empty message
	if m != nil {
		e.startAndEndTime(m.StartTime, m.EndTime)
		e.int32Field(3, int32(m.Version))
		if r := m.Request; r != nil {
			s := e.begin(4)
			e.int32Field(1, int32(r.Method))
			e.stringField(2, r.Path, "AccessLogHTTPProtocolRequest.path")
			e.uint64Field(3, r.SizeOfHeadersBytes)
			e.uint64Field(4, r.SizeOfBodyBytes)
			if t := r.Trace; t != nil {
				ts := e.begin(5)
				e.int32Field(1, int32(t.Provider))
				e.stringField(2, t.TraceId, "AccessLogTraceInfo.traceId")
				e.stringField(3, t.TraceSegmentId, "AccessLogTraceInfo.traceSegmentId")
				e.stringField(4, t.SpanId, "AccessLogTraceInfo.spanId")
				e.end(ts)
			}
			e.stringField(6, r.Host, "AccessLogHTTPProtocolRequest.host")
			e.end(s)
		}
		if r := m.Response; r != nil {
			s := e.begin(5)
			e.int32Field(1, r.StatusCode)
			e.uint64Field(3, r.SizeOfHeadersBytes)
			e.uint64Field(4, r.SizeOfBodyBytes)
			e.end(s)
		}
	}
	e.end(start)
}

// encodeProtocolLog is the kernelLogs and protocolLog (when set) fields of the message of a protocol log
func (e *wireEncoder) encodeProtocolLog(kernels []*v3.AccessLogKernelLog, protocol *v3.AccessLogProtocolLogs) {
	for _, k := range kernels {
		e.kernelLog(k)
	}
	if protocol != nil {
		e.protocolLogs(messageProtocolLogField, protocol)
	}
}

// encodeTransferProtocolLog is encodeProtocolLog for a protocol log whose kernel logs are the kernel transfer
// events details, written straight from the events when it can be (see forwarder.TransferLog), and how many
// kernel logs it wrote: an event without a log is skipped, like the builder's nil log is. With merge, the consecutive
// logs of one operation are folded into one as the kernel logs of the connection are (forwarder.TryMergeTransferLog,
// TryMergeKernelLog): the details of a message are not merged before (common.SetMergeKernelLogs) when they carry the
// L2 to L4 details of their calls, which only the logs show (access_log.kernel_metrics.l2_l3).
func (e *wireEncoder) encodeTransferProtocolLog(details []events.SocketDetail, protocol *v3.AccessLogProtocolLogs, merge bool) int {
	count := 0
	// with merge: the latest log, kept while the next one may be folded into it, as a TransferLog or as a message
	var pending forwarder.TransferLog
	hasPending := false
	var pendingMessage *v3.AccessLogKernelLog
	flush := func() {
		if hasPending {
			e.transferLog(&pending)
			count++
			hasPending = false
		}
		if pendingMessage != nil {
			e.kernelLog(pendingMessage)
			count++
			pendingMessage = nil
		}
	}
	for _, d := range details {
		if wireEncodingCovered {
			if t, filled, ok := forwarder.BuildTransferLog(d); filled {
				if !ok {
					continue
				}
				if !merge {
					e.transferLog(&t)
					count++
					continue
				}
				if hasPending && forwarder.TryMergeTransferLog(&pending, &t) {
					continue
				}
				flush()
				pending, hasPending = t, true
				continue
			}
		}
		k := forwarder.BuildKernelLogFromEvent(common.LogTypeKernelTransfer, d)
		if k == nil {
			continue
		}
		if !merge {
			e.kernelLog(k)
			count++
			continue
		}
		if pendingMessage != nil && forwarder.TryMergeKernelLog(pendingMessage, k) {
			continue
		}
		flush()
		pendingMessage = k
	}
	flush()
	if protocol != nil {
		e.protocolLogs(messageProtocolLogField, protocol)
	}
	return count
}

// EncodeTransferProtocolLog is the kernelLogs and protocolLog fields AppendTransferProtocolLog adds, and the count
// of kernel logs: the bytes of the message of the logs BuildKernelLogFromEvent builds for the details
func EncodeTransferProtocolLog(details []events.SocketDetail, protocol *v3.AccessLogProtocolLogs) (message []byte, kernelLogs int, err error) {
	e := &wireEncoder{}
	count := e.encodeTransferProtocolLog(details, protocol, false)
	return e.buf, count, e.err
}

// encodeHeader is the node (when set) and the connection (when set) fields that start a message
func (e *wireEncoder) encodeHeader(node *v3.EBPFAccessLogNodeInfo, connection *v3.AccessLogConnection) {
	if node != nil {
		e.node(messageNodeField, node)
	}
	if connection != nil {
		e.connection(messageConnectionField, connection)
	}
}

// the encoded logs of a batch are copied into chunks growing from minArenaChunk to maxArenaChunk, so a small
// batch does not pin a mostly empty chunk while it waits to be sent
const (
	minArenaChunk = 4 << 10
	maxArenaChunk = 64 << 10
)

// logArena keeps the encoded logs of a batch in large chunks: one allocation, free of pointers, for many
// logs instead of one per log. A log is a slice of a chunk with no room to append, so it cannot be overwritten.
type logArena struct {
	chunk []byte
	// size is the size of the latest chunk
	size int
}

func (a *logArena) copy(b []byte) []byte {
	if cap(a.chunk)-len(a.chunk) < len(b) {
		a.size = min(max(2*a.size, minArenaChunk), maxArenaChunk)
		a.chunk = make([]byte, 0, max(a.size, len(b)))
	}
	start := len(a.chunk)
	a.chunk = append(a.chunk, b...)
	return a.chunk[start:len(a.chunk):len(a.chunk)]
}
