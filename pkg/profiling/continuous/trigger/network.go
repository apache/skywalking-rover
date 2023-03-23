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

package trigger

import (
	"fmt"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/checker/common"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type NetworkTrigger struct {
	*BaseTrigger
}

func NewNetworkTrigger() base.Trigger {
	return &NetworkTrigger{}
}

func (n *NetworkTrigger) Init(moduleMgr *module.Manager, conf *base.ContinuousConfig) error {
	n.BaseTrigger = NewMultipleProcessBasedTrigger(conf, func(p api.ProcessInterface) string {
		// same instance
		entity := p.Entity()
		return fmt.Sprintf("%s_%s", entity.ServiceName, entity.InstanceName)
	}, func(ps []api.ProcessInterface) api.ProcessInterface {
		var mainApplication api.ProcessInterface
		for _, p := range ps {
			// for service mesh, find the application
			if processHasLabel(p, "mesh-application") {
				mainApplication = p
			}
			// otherwise, find the process belong a kubernetes service
			if mainApplication == nil && processHasLabel(p, "k8s-service") {
				mainApplication = p
			}
		}
		if mainApplication != nil {
			return mainApplication
		}
		return ps[0]
	}, func(task *profiling.ProfilingTask, processes []api.ProcessInterface, thresholds []base.ThresholdCause) {
		task.TargetType = profiling.TargetTypeNetworkTopology
		task.ExtensionConfig = &profiling.ExtensionConfig{
			NetworkSamplings: transformCausesToNetworkSamplingRules(thresholds),
		}
	}, func(report *v3.ContinuousProfilingReport, processes []api.ProcessInterface, thresholds []base.ThresholdCause) {
		rules := transformCausesToNetworkSamplingRules(thresholds)
		uriRegexes := make([]string, 0)
		if len(rules) > 0 {
			for _, r := range rules {
				uriRegexes = append(uriRegexes, *r.URIRegex)
			}
		}
		report.TargetTask = &v3.ContinuousProfilingReport_Network{
			Network: &v3.ContinuousNetworkProfilingTask{
				SamplingURIRegexes: uriRegexes,
			},
		}
	})
	return n.BaseTrigger.Init(conf)
}

func processHasLabel(p api.ProcessInterface, label string) bool {
	for _, l := range p.Entity().Labels {
		if l == label {
			return true
		}
	}
	return false
}

func transformCausesToNetworkSamplingRules(thresholds []base.ThresholdCause) []*profiling.NetworkSamplingRule {
	result := make([]*profiling.NetworkSamplingRule, 0)
	var minDuration int32 = 0
	for _, threshold := range thresholds {
		uriCause, ok := threshold.(*common.URICause)
		if !ok {
			continue
		}
		// collecting all request and response
		rule := &profiling.NetworkSamplingRule{
			URIRegex:    &uriCause.URI,
			MinDuration: &minDuration,
			When4XX:     true,
			When5XX:     true,
			Settings: &profiling.NetworkDataCollectingSettings{
				RequireCompleteRequest:  true,
				MaxRequestSize:          -1,
				RequireCompleteResponse: true,
				MaxResponseSize:         -1,
			},
		}

		if uriCause.URI == "" {
			return []*profiling.NetworkSamplingRule{rule}
		}
		result = append(result, rule)
	}
	return result
}
