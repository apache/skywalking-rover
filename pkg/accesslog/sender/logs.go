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
	"github.com/apache/skywalking-rover/pkg/accesslog/common"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var maxLogsPerSend = 10_000

type BatchLogs struct {
	logs map[*common.ConnectionInfo]*ConnectionLogs
}

func newBatchLogs() *BatchLogs {
	return &BatchLogs{
		logs: make(map[*common.ConnectionInfo]*ConnectionLogs),
	}
}

func (l *BatchLogs) ConnectionCount() int {
	return len(l.logs)
}

func (l *BatchLogs) AppendKernelLog(connection *common.ConnectionInfo, log *v3.AccessLogKernelLog) {
	logs, ok := l.logs[connection]
	if !ok {
		logs = newConnectionLogs()
		l.logs[connection] = logs
	}

	logs.kernels = append(logs.kernels, log)
}

func (l *BatchLogs) AppendProtocolLog(connection *common.ConnectionInfo, kernels []*v3.AccessLogKernelLog, protocols *v3.AccessLogProtocolLogs) {
	logs, ok := l.logs[connection]
	if !ok {
		logs = newConnectionLogs()
		l.logs[connection] = logs
	}

	logs.protocols = append(logs.protocols, &ConnectionProtocolLog{
		kernels:  kernels,
		protocol: protocols,
	})
}

func (l *BatchLogs) splitBatchLogs() []*BatchLogs {
	logsCount := len(l.logs)
	if logsCount == 0 {
		return nil
	}
	splitCount := logsCount / maxLogsPerSend
	if logsCount%maxLogsPerSend != 0 {
		splitCount++
	}
	result := make([]*BatchLogs, 0, splitCount)

	// split the connections by maxLogsPerSend
	currentCount := 0
	var currentBatch *BatchLogs
	for connection, logs := range l.logs {
		if currentCount%maxLogsPerSend == 0 {
			currentBatch = newBatchLogs()
			result = append(result, currentBatch)
			currentCount = 0
		}
		currentBatch.logs[connection] = logs
		currentCount++
	}

	return result
}

type ConnectionLogs struct {
	kernels   []*v3.AccessLogKernelLog
	protocols []*ConnectionProtocolLog
}

type ConnectionProtocolLog struct {
	kernels  []*v3.AccessLogKernelLog
	protocol *v3.AccessLogProtocolLogs
}

func newConnectionLogs() *ConnectionLogs {
	return &ConnectionLogs{
		kernels:   make([]*v3.AccessLogKernelLog, 0),
		protocols: make([]*ConnectionProtocolLog, 0),
	}
}
