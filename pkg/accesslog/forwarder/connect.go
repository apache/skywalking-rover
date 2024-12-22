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
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"github.com/apache/skywalking-rover/pkg/tools/ip"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

func init() {
	RegisterKernelLogBuilder(common.LogTypeConnect, connectLogBuilder)
}

func SendConnectEvent(context *common.AccessLogContext, event *events.SocketConnectEvent, socketPair *ip.SocketPair) {
	context.Queue.AppendKernelLog(common.LogTypeConnect, &common.ConnectEventWithSocket{
		SocketConnectEvent: event,
		SocketPair:         socketPair,
	})
}

func connectLogBuilder(event events.Event) *v3.AccessLogKernelLog {
	connectEvent := event.(*common.ConnectEventWithSocket)
	switch connectEvent.FuncName {
	case enums.SocketFunctionNameConnect:
		return &v3.AccessLogKernelLog{
			Operation: &v3.AccessLogKernelLog_Connect{
				Connect: &v3.AccessLogKernelConnectOperation{
					StartTime: BuildOffsetTimestamp(connectEvent.StartTime),
					EndTime:   BuildOffsetTimestamp(connectEvent.EndTime),
					Success:   connectEvent.ConnectSuccess == 1,
				},
			},
		}
	case enums.SocketFunctionNameAccept:
		return &v3.AccessLogKernelLog{
			Operation: &v3.AccessLogKernelLog_Accept{
				Accept: &v3.AccessLogKernelAcceptOperation{
					StartTime: BuildOffsetTimestamp(connectEvent.StartTime),
					EndTime:   BuildOffsetTimestamp(connectEvent.EndTime),
				},
			},
		}
	}
	return nil
}
