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

package common //nolint:revive // package name is acceptable in this context

import (
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"

	"reflect"
)

var log = logger.GetLogger("profiling", "continuous", "checker", "common")

type ProcessInfo interface {
}

type numbers interface {
	int | int32 | int64 | float64
}

// BaseChecker contains the process with them self info
// Key: process pid
// Value: the process information, usually contains the time windows and policy items
type BaseChecker[Info ProcessInfo] struct {
	InfoGenerator func(p api.ProcessInterface, older Info, items []*base.PolicyItem) Info
	PidWithInfos  map[int32]Info
}

func NewBaseChecker[Info ProcessInfo](generator func(p api.ProcessInterface, older Info, items []*base.PolicyItem) Info) *BaseChecker[Info] {
	return &BaseChecker[Info]{
		InfoGenerator: generator,
		PidWithInfos:  make(map[int32]Info),
	}
}

func (c *BaseChecker[Info]) SyncPolicies(policies []*base.SyncPolicyWithProcesses,
	getEnabledItem func(items map[base.CheckType]*base.PolicyItem) *base.PolicyItem,
	notify func(key int32, isDelete bool)) {
	pidWithPolicyItems := make(map[api.ProcessInterface][]*base.PolicyItem)
	for _, processWithPolicies := range policies {
		item := getEnabledItem(processWithPolicies.Policy.Items)
		if item == nil {
			continue
		}

		// create or get the existing windows
		// and add the policy into the update
		for _, p := range processWithPolicies.Processes {
			pidWithPolicyItems[p] = append(pidWithPolicyItems[p], item)
		}
	}

	// generate the new process info
	result := make(map[int32]Info)
	for p, items := range pidWithPolicyItems {
		pid := p.Pid()
		if existing := c.PidWithInfos[pid]; reflect.ValueOf(existing).IsZero() && notify != nil {
			notify(pid, false)
		}
		result[pid] = c.InfoGenerator(p, c.PidWithInfos[pid], items)
	}

	// if the pid is not exist in the new policies, then notify to delete
	for key := range c.PidWithInfos {
		if newResult := result[key]; reflect.ValueOf(newResult).IsZero() && notify != nil {
			notify(key, true)
		}
	}

	c.PidWithInfos = result
}
