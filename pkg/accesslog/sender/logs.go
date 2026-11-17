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
	"sync/atomic"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

// BatchLogs is the logs of one flush, by connection. A log is encoded (see encode.go) as soon as it can no
// longer change, while it is still in the cache: a protocol log when it is appended, a kernel log when the
// next one of its connection is not merged into it, or when the batch is added to the sender.
// The batch is built by one goroutine.
type BatchLogs struct {
	logs map[*common.ConnectionInfo]*ConnectionLogs
	// mergeKernelLogs folds a kernel log into the previous one of the same connection when they
	// describe the same operation, for the records that do not belong to a protocol log
	mergeKernelLogs bool
	// mergeProtocolKernelLogs folds the consecutive kernel logs of one operation of a protocol log into one as they
	// are encoded, see EnableProtocolKernelLogMerge
	mergeProtocolKernelLogs bool

	// scratch is the buffer a log is encoded in before it is copied into the arena
	scratch []byte
	arena   logArena
}

// EnableKernelLogMerge makes the batch fold the kernel logs it is given, see forwarder.MergeKernelLogs
func (l *BatchLogs) EnableKernelLogMerge() {
	l.mergeKernelLogs = true
}

// EnableProtocolKernelLogMerge makes the batch fold the consecutive kernel logs of one operation of a protocol log as
// it encodes them: with access_log.flush.merge_kernel_logs and the L2 to L4 details of the calls
// (access_log.kernel_metrics.l2_l3), whose logs are merged by their interface and with every metric summed, which the
// details of a message, merged before (events.MergeDetails), do not carry
func (l *BatchLogs) EnableProtocolKernelLogMerge() {
	l.mergeProtocolKernelLogs = true
}

func newBatchLogs() *BatchLogs {
	return &BatchLogs{
		logs: make(map[*common.ConnectionInfo]*ConnectionLogs),
	}
}

func (l *BatchLogs) ConnectionCount() int {
	return len(l.logs)
}

func (l *BatchLogs) connectionLogs(connection *common.ConnectionInfo) *ConnectionLogs {
	logs, ok := l.logs[connection]
	if !ok {
		logs = &ConnectionLogs{}
		l.logs[connection] = logs
	}
	return logs
}

func (l *BatchLogs) AppendKernelLog(connection *common.ConnectionInfo, log *v3.AccessLogKernelLog) {
	logs := l.connectionLogs(connection)
	if !l.mergeKernelLogs {
		l.appendEncodedKernelLog(logs, log)
		return
	}
	if logs.hasLastTransfer {
		if !isTransferOperation(log) {
			// it cannot be merged into the latest log, nor can anything be merged into it but another
			// read or write: TryMergeKernelLog of the two would give false
			l.appendEncodedTransferLog(logs, &logs.lastTransfer)
			logs.hasLastTransfer = false
			logs.lastKernel = log
			return
		}
		// a read or write message after a TransferLog: the latest log becomes its message, which the
		// message is merged into as it would have been
		logs.lastKernel = transferLogMessage(&logs.lastTransfer)
		logs.hasLastTransfer = false
	}
	// the latest kernel log stays a message while the next one may be merged into it
	if logs.lastKernel != nil {
		if forwarder.TryMergeKernelLog(logs.lastKernel, log) {
			return
		}
		l.appendEncodedKernelLog(logs, logs.lastKernel)
	}
	logs.lastKernel = log
}

// AppendKernelEvent appends the kernel log of the type the event is built into and reports whether there is
// one, what AppendKernelLog(connection, forwarder.BuildKernelLogFromEvent(tp, event)) does when that log is
// not nil. A kernel transfer log is not built: it is encoded, and merged, from its forwarder.TransferLog,
// which spares the messages of every socket call that belongs to no protocol log.
func (l *BatchLogs) AppendKernelEvent(connection *common.ConnectionInfo, tp common.LogType, event events.Event) bool {
	if tp == common.LogTypeKernelTransfer && wireEncodingCovered {
		if t, filled, ok := forwarder.BuildTransferLog(event); filled {
			if ok {
				l.appendTransferLog(connection, &t)
			}
			return ok
		}
	}
	k := forwarder.BuildKernelLogFromEvent(tp, event)
	if k == nil {
		return false
	}
	l.AppendKernelLog(connection, k)
	return true
}

// appendTransferLog is AppendKernelLog for the message of the TransferLog
func (l *BatchLogs) appendTransferLog(connection *common.ConnectionInfo, t *forwarder.TransferLog) {
	logs := l.connectionLogs(connection)
	if !l.mergeKernelLogs {
		l.appendEncodedTransferLog(logs, t)
		return
	}
	if logs.hasLastTransfer {
		if forwarder.TryMergeTransferLog(&logs.lastTransfer, t) {
			return
		}
		l.appendEncodedTransferLog(logs, &logs.lastTransfer)
		logs.lastTransfer = *t
		return
	}
	if logs.lastKernel != nil {
		if isTransferOperation(logs.lastKernel) {
			// the latest log is a read or write message: the log is merged into it as a message
			l.AppendKernelLog(connection, transferLogMessage(t))
			return
		}
		// TryMergeKernelLog never merges into a log that is no read or write
		l.appendEncodedKernelLog(logs, logs.lastKernel)
		logs.lastKernel = nil
	}
	logs.lastTransfer, logs.hasLastTransfer = *t, true
}

// isTransferOperation tells whether the log is a read or a write, the only logs TryMergeKernelLog merges
func isTransferOperation(log *v3.AccessLogKernelLog) bool {
	if log == nil {
		return false
	}
	switch log.Operation.(type) {
	case *v3.AccessLogKernelLog_Read, *v3.AccessLogKernelLog_Write:
		return true
	}
	return false
}

// transferLogMessage is the message of the TransferLog, the message transferLog writes the bytes of, for the
// merge of a TransferLog with a read or write message (which only a builder without filler gives)
func transferLogMessage(t *forwarder.TransferLog) *v3.AccessLogKernelLog {
	start, end := forwarder.BuildOffsetTimestamps(t.StartTime, t.EndTime)
	m := t.Metrics
	if t.Write {
		w := &v3.AccessLogKernelWriteOperation{StartTime: start, EndTime: end, Syscall: v3.AccessLogKernelWriteSyscall(t.Syscall)}
		if t.HasMetrics[0] {
			w.L4Metrics = &v3.AccessLogKernelWriteL4Metrics{TotalDuration: m[0][1], TotalTransmitPackageCount: int64(m[0][2]),
				TotalRetransmitPackageCount: int64(m[0][3]), TotalPackageSize: int64(m[0][5])}
		}
		if t.HasMetrics[1] {
			w.L3Metrics = &v3.AccessLogKernelWriteL3Metrics{TotalDuration: m[1][1], TotalLocalDuration: m[1][2],
				TotalOutputDuration: m[1][3], TotalResolveMACCount: m[1][5], TotalResolveMACDuration: m[1][6],
				TotalNetFilterCount: m[1][7], TotalNetFilterDuration: m[1][8]}
		}
		if t.HasMetrics[2] {
			w.L2Metrics = &v3.AccessLogKernelWriteL2Metrics{TotalDuration: m[2][1], Ifindex: uint32(m[2][2]),
				TotalEnterQueueBufferCount: m[2][3], TotalReadySendDuration: m[2][4], TotalNetDeviceSendDuration: m[2][5]}
		}
		return &v3.AccessLogKernelLog{Operation: &v3.AccessLogKernelLog_Write{Write: w}}
	}
	r := &v3.AccessLogKernelReadOperation{StartTime: start, EndTime: end, Syscall: v3.AccessLogKernelReadSyscall(t.Syscall)}
	if t.HasMetrics[0] {
		r.L2Metrics = &v3.AccessLogKernelReadL2Metrics{Ifindex: uint32(m[0][1]), TotalPackageCount: uint32(m[0][2]),
			TotalPackageSize: m[0][3], TotalPackageToQueueDuration: m[0][4], TotalRcvPackageFromQueueDuration: m[0][5]}
	}
	if t.HasMetrics[1] {
		r.L3Metrics = &v3.AccessLogKernelReadL3Metrics{TotalDuration: m[1][1], TotalRecvDuration: m[1][2],
			TotalLocalDuration: m[1][3], TotalNetFilterCount: m[1][4], TotalNetFilterDuration: m[1][5]}
	}
	if t.HasMetrics[2] {
		r.L4Metrics = &v3.AccessLogKernelReadL4Metrics{TotalDuration: m[2][1]}
	}
	return &v3.AccessLogKernelLog{Operation: &v3.AccessLogKernelLog_Read{Read: r}}
}

func (l *BatchLogs) appendEncodedTransferLog(logs *ConnectionLogs, t *forwarder.TransferLog) {
	e := wireEncoder{buf: l.scratch[:0]}
	e.transferLog(t)
	l.keep(&e, &logs.kernels)
}

func (l *BatchLogs) appendEncodedKernelLog(logs *ConnectionLogs, log *v3.AccessLogKernelLog) {
	// the encoder is a local variable: its buffer is written without the write barrier of the heap
	e := wireEncoder{buf: l.scratch[:0]}
	e.kernelLog(log)
	l.keep(&e, &logs.kernels)
}

// AppendProtocolLog adds the log of one message, which is not changed once it is built; false when it cannot be
// encoded (not added)
func (l *BatchLogs) AppendProtocolLog(connection *common.ConnectionInfo, kernels []*v3.AccessLogKernelLog,
	protocols *v3.AccessLogProtocolLogs) bool {
	logs := l.connectionLogs(connection)
	e := wireEncoder{buf: l.scratch[:0]}
	e.encodeProtocolLog(kernels, protocols)
	return l.keep(&e, &logs.protocols)
}

// AppendTransferProtocolLog is AppendProtocolLog for the kernel logs BuildKernelLogFromEvent builds of the kernel
// transfer events details, encoded without building them, and returns how many there are: nothing is added
// when there is none, or when the log cannot be encoded (0)
func (l *BatchLogs) AppendTransferProtocolLog(connection *common.ConnectionInfo, details []events.SocketDetail,
	protocols *v3.AccessLogProtocolLogs) int {
	if len(details) == 0 {
		// a protocol log goes out only with its kernel logs: don't encode one that is dropped anyway
		return 0
	}
	e := wireEncoder{buf: l.scratch[:0]}
	count := e.encodeTransferProtocolLog(details, protocols, l.mergeProtocolKernelLogs)
	if count == 0 {
		l.scratch = e.buf
		return 0
	}
	if !l.keep(&e, &l.connectionLogs(connection).protocols) {
		return 0
	}
	return count
}

// keep appends the log the encoder wrote to logs, copied into the arena, or drops it when it cannot be encoded
// (false)
func (l *BatchLogs) keep(e *wireEncoder, logs *[][]byte) bool {
	l.scratch = e.buf
	if e.err != nil {
		encodeFailed(e.err)
		return false
	}
	*logs = append(*logs, l.arena.copy(e.buf))
	return true
}

// seal encodes the kernel logs that were kept for a merge, nothing is added to the batch anymore
func (l *BatchLogs) seal() {
	for _, logs := range l.logs {
		if logs.lastKernel != nil {
			l.appendEncodedKernelLog(logs, logs.lastKernel)
			logs.lastKernel = nil
		}
		if logs.hasLastTransfer {
			l.appendEncodedTransferLog(logs, &logs.lastTransfer)
			logs.hasLastTransfer = false
		}
	}
	// the logs keep the chunks they are in
	l.scratch, l.arena = nil, logArena{}
}

// LogCount is the count of logs of the batch: every protocol log and every kernel log
func (l *BatchLogs) LogCount() int {
	count := 0
	for _, logs := range l.logs {
		count += logs.logCount()
	}
	return count
}

// splitBatchLogs splits the sealed batch into batches of at most maxLogs logs (at least 1), each sent over a
// stream of its own. The logs of a connection keep their order and may be split over several batches:
// every batch names the connection again on its first message of the connection (see
// GRPCSender.sendLogs). A batch that fits is returned as it is.
func (l *BatchLogs) splitBatchLogs(maxLogs int) []*BatchLogs {
	total := l.LogCount()
	if total == 0 {
		return nil
	}
	if total <= maxLogs {
		return []*BatchLogs{l}
	}
	result := make([]*BatchLogs, 0, (total+maxLogs-1)/maxLogs)
	var current *BatchLogs
	room := 0
	next := func() {
		current = newBatchLogs()
		current.mergeKernelLogs = l.mergeKernelLogs
		current.mergeProtocolKernelLogs = l.mergeProtocolKernelLogs
		result = append(result, current)
		room = maxLogs
	}
	for connection, logs := range l.logs {
		count := logs.logCount()
		if count == 0 {
			continue
		}
		if room == 0 {
			next()
		}
		if count <= room {
			// the connection fits whole
			current.logs[connection] = logs
			room -= count
			continue
		}
		kernels, protocols := logs.kernels, logs.protocols
		for len(kernels) > 0 || len(protocols) > 0 {
			if room == 0 {
				next()
			}
			part := current.logs[connection]
			if part == nil {
				part = &ConnectionLogs{}
				current.logs[connection] = part
			}
			var taken int
			if len(kernels) > 0 {
				part.kernels, kernels, taken = takeN(part.kernels, kernels, room)
			} else {
				part.protocols, protocols, taken = takeN(part.protocols, protocols, room)
			}
			room -= taken
		}
	}
	return result
}

// takeN moves up to n items from the front of from to the back of to
func takeN[T any](to, from []T, n int) (newTo, rest []T, taken int) {
	taken = min(n, len(from))
	return append(to, from[:taken]...), from[taken:], taken
}

// ConnectionLogs is the encoded logs of a connection, the fields of the messages that carry them
type ConnectionLogs struct {
	// kernels are the kernel logs that do not belong to a protocol log, each an element of
	// EBPFAccessLogMessage.kernelLogs: they are sent together in one message
	kernels [][]byte
	// protocols are the protocol logs, each the kernelLogs and protocolLog fields of its own message
	protocols [][]byte
	// lastKernel is the latest kernel log, not encoded yet while the next one may be merged into it
	lastKernel *v3.AccessLogKernelLog
	// lastTransfer is lastKernel for a kernel transfer log appended as its TransferLog (AppendKernelEvent),
	// set when hasLastTransfer is: at most one of the two is set
	lastTransfer    forwarder.TransferLog
	hasLastTransfer bool
}

func (c *ConnectionLogs) logCount() int {
	count := len(c.kernels) + len(c.protocols)
	if c.lastKernel != nil || c.hasLastTransfer {
		count++
	}
	return count
}

var (
	encodeErrors       atomic.Int64
	lastEncodeErrorLog atomic.Int64
)

// encodeFailed drops a log that cannot be encoded, a string that is not UTF-8 (proto.Marshal fails the same
// way, and failed the whole stream when the logs were marshaled at sending)
func encodeFailed(err error) {
	total := encodeErrors.Add(1)
	if !shouldWarn(&lastEncodeErrorLog) {
		return
	}
	log.Warnf("dropped an access log that cannot be encoded, %d dropped in total: %v", total, err)
}
