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

package collector

import (
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
)

var closeLog = logger.GetLogger("access_log", "collector", "close")

var closeCollectorInstance = NewCloseCollector()

type CloseCollector struct {
}

func NewCloseCollector() *CloseCollector {
	return &CloseCollector{}
}

func (c *CloseCollector) Start(_ *module.Manager, context *common.AccessLogContext) error {
	context.BPF.AddTracePoint("syscalls", "sys_enter_close", context.BPF.TracepointEnterClose)
	context.BPF.AddTracePoint("syscalls", "sys_exit_close", context.BPF.TracepointExitClose)

	context.BPF.ReadEventAsync(context.BPF.SocketCloseEventQueue, func(data interface{}) {
		event := data.(*events.SocketCloseEvent)
		closeLog.Debugf("receive close event, connection ID: %d, randomID: %d, pid: %d, fd: %d",
			event.ConnectionID, event.RandomID, event.PID, event.SocketFD)
		wapperedEvent := context.ConnectionMgr.OnConnectionClose(event)
		forwarder.SendCloseEvent(context, wapperedEvent)
	}, func() interface{} {
		return &events.SocketCloseEvent{}
	})
	return nil
}

func (c *CloseCollector) Stop() {
}
