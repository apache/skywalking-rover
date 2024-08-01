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

package forwarder

import (
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

func init() {
	registerKernelLogBuilder(common.LogTypeClose, closeLogBuilder)
}

func SendCloseEvent(context *common.AccessLogContext, event *common.CloseEventWithNotify) {
	context.Queue.AppendKernelLog(common.LogTypeClose, event)
}

func closeLogBuilder(event events.Event) *v3.AccessLogKernelLog {
	closeEvent := event.(*common.CloseEventWithNotify)
	if closeEvent.StartTime == 0 {
		return nil
	}
	closeOp := &v3.AccessLogKernelCloseOperation{}
	closeOp.StartTime = BuildOffsetTimestamp(closeEvent.StartTime)
	closeOp.EndTime = BuildOffsetTimestamp(closeEvent.EndTime)
	closeOp.Success = closeEvent.Success == 1
	return &v3.AccessLogKernelLog{
		Operation: &v3.AccessLogKernelLog_Close{
			Close: closeOp,
		},
	}
}
