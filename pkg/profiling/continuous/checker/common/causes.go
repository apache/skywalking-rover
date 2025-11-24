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
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type SingleValueCause struct {
	process            api.ProcessInterface
	policy             *base.PolicyItem
	monitorType        v3.ContinuousProfilingTriggeredMonitorType
	threshold, current float64
}

func NewSingleValueCause(p api.ProcessInterface, policyItem *base.PolicyItem, monitorType v3.ContinuousProfilingTriggeredMonitorType,
	threshold, current float64) *SingleValueCause {
	return &SingleValueCause{
		process:     p,
		policy:      policyItem,
		monitorType: monitorType,
		threshold:   threshold,
		current:     current,
	}
}

func (p *SingleValueCause) Process() api.ProcessInterface {
	return p.process
}

func (p *SingleValueCause) FromPolicy() *base.PolicyItem {
	return p.policy
}

func (p *SingleValueCause) GenerateTransferCause() *v3.ContinuousProfilingCause {
	return &v3.ContinuousProfilingCause{
		Type: p.monitorType,
		Cause: &v3.ContinuousProfilingCause_SingleValue{
			SingleValue: &v3.ContinuousProfilingSingleValueCause{
				Threshold: p.threshold,
				Current:   p.current,
			},
		},
	}
}

type URICause struct {
	IsRegex bool
	URI     string

	process            api.ProcessInterface
	policy             *base.PolicyItem
	causeType          v3.ContinuousProfilingTriggeredMonitorType
	threshold, current float64
}

func NewURICause(p api.ProcessInterface, isRegex bool, uri string, policyItem *base.PolicyItem,
	monitorType v3.ContinuousProfilingTriggeredMonitorType, threshold, current float64) *URICause {
	return &URICause{
		process:   p,
		policy:    policyItem,
		causeType: monitorType,
		IsRegex:   isRegex,
		URI:       uri,
		threshold: threshold,
		current:   current,
	}
}

func (p *URICause) Process() api.ProcessInterface {
	return p.process
}

func (p *URICause) FromPolicy() *base.PolicyItem {
	return p.policy
}

func (p *URICause) GenerateTransferCause() *v3.ContinuousProfilingCause {
	uriCause := &v3.ContinuousProfilingURICause{
		Threshold: p.threshold,
		Current:   p.current,
	}
	if p.IsRegex {
		uriCause.Uri = &v3.ContinuousProfilingURICause_Regex{
			Regex: p.URI,
		}
	} else {
		uriCause.Uri = &v3.ContinuousProfilingURICause_Path{
			Path: p.URI,
		}
	}
	return &v3.ContinuousProfilingCause{
		Type: p.causeType,
		Cause: &v3.ContinuousProfilingCause_Uri{
			Uri: uriCause,
		},
	}
}
