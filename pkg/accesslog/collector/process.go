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
	"github.com/apache/skywalking-rover/pkg/module"
)

var processCollectInstance = NewProcessCollector()

// ProcessCollector Management all processes which needs to be monitored
type ProcessCollector struct {
}

func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{}
}

func (p *ProcessCollector) Start(_ *module.Manager, context *common.AccessLogContext) error {
	// monitor process been execute
	context.BPF.AddTracePoint("sched", "sched_process_fork", context.BPF.TracepointSchedProcessFork)

	context.BPF.ReadEventAsync(context.BPF.ProcessExecuteQueue, func(data interface{}) {
		context.ConnectionMgr.OnNewProcessExecuting(int32(data.(*ProcessExecuteEvent).PID))
	}, func() interface{} {
		return &ProcessExecuteEvent{}
	})

	return nil
}

func (p *ProcessCollector) Stop() {
}

type ProcessExecuteEvent struct {
	PID uint32
}
