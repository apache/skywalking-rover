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

package common

import (
	"fmt"
	"strings"
	"time"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type SystemBasedChecker[V numbers] struct {
	CheckType         base.CheckType
	CauseType         v3.ContinuousProfilingCauseType
	ThresholdGenerate func(val string) (V, error)
	DataGenerate      func() (V, error)
	GlobalWindows     *base.TimeWindows[V, V]

	Policies []*SystemBasedPolicy[V]
}

func NewSystemBasedChecker[V numbers](checkType base.CheckType, thresholdGenerator func(val string) (V, error),
	dataGenerator func() (V, error), causeType v3.ContinuousProfilingCauseType) *SystemBasedChecker[V] {
	checker := &SystemBasedChecker[V]{
		CheckType:         checkType,
		CauseType:         causeType,
		ThresholdGenerate: thresholdGenerator,
		DataGenerate:      dataGenerator,
		GlobalWindows: base.NewTimeWindows[V, V](nil, func() base.WindowData[V, V] {
			return base.NewLatestWindowData[V]()
		}),
	}
	return checker
}

func (s *SystemBasedChecker[V]) SyncPolicies(policies []*base.SyncPolicyWithProcesses) {
	result := make([]*SystemBasedPolicy[V], 0)
	items := make([]*base.PolicyItem, 0)
	for _, policyWithProcesses := range policies {
		item := policyWithProcesses.Policy.Items[s.CheckType]
		if item == nil {
			continue
		}
		threshold, err := s.ThresholdGenerate(item.Threshold)
		if err != nil {
			log.Warnf("failure to parse the %s threshold: %v, error: %v", s.CheckType, item.Threshold, err)
			continue
		}
		items = append(items, item)
		processes := make([]api.ProcessInterface, 0)
		for _, p := range policyWithProcesses.Processes {
			processes = append(processes, p)
		}
		result = append(result, &SystemBasedPolicy[V]{
			Threshold: threshold,
			Policy:    item,
			Processes: processes,
		})
	}

	s.Policies = result
	s.GlobalWindows.ScalePeriod(items)
}

func (s *SystemBasedChecker[V]) Fetch() error {
	if len(s.Policies) == 0 {
		return nil
	}

	val, err := s.DataGenerate()
	if err != nil {
		return fmt.Errorf("get the system %s error: %v", s.CheckType, err)
	}
	s.GlobalWindows.Add(time.Now(), val)
	return nil
}

func (s *SystemBasedChecker[V]) Check(ctx base.CheckContext, metricsAppender *base.MetricsAppender) []base.ThresholdCause {
	if len(s.Policies) == 0 {
		return nil
	}

	causes := make([]base.ThresholdCause, 0)
	data, hasData := s.GlobalWindows.FlushLastWriteData()

	for _, policy := range s.Policies {
		if hasData {
			for _, p := range policy.Processes {
				metricsAppender.AppendProcessSingleValue(strings.ToLower(string(s.CheckType)), p, nil, float64(data))
			}
		}
		lastMatch, isMatch := s.GlobalWindows.MatchRule(policy.Policy, func(val V) bool {
			return val >= policy.Threshold
		})
		if !isMatch {
			continue
		}

		for _, p := range policy.Processes {
			if !ctx.ShouldCheck(p, policy.Policy) {
				continue
			}

			causes = append(causes, NewSingleValueCause(p, policy.Policy, s.CauseType, float64(policy.Threshold), float64(lastMatch)))
		}
	}

	return causes
}

func (s *SystemBasedChecker[V]) Close() error {
	return nil
}

type SystemBasedPolicy[V numbers] struct {
	Threshold V
	Policy    *base.PolicyItem
	Processes []api.ProcessInterface
}
