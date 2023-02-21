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

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type ProcessBasedChecker[V numbers] struct {
	*BaseChecker[*ProcessBasedInfo[V]]

	CheckType         base.CheckType
	CauseType         v3.ContinuousProfilingCauseType
	ThresholdGenerate func(val string) (V, error)
	DataGenerate      func(process api.ProcessInterface) (V, error)
}

func NewProcessBasedChecker[V numbers](checkType base.CheckType, thresholdGenerator func(val string) (V, error),
	dataGenerator func(p api.ProcessInterface) (V, error), causeType v3.ContinuousProfilingCauseType) *ProcessBasedChecker[V] {
	checker := &ProcessBasedChecker[V]{
		CheckType:         checkType,
		CauseType:         causeType,
		ThresholdGenerate: thresholdGenerator,
		DataGenerate:      dataGenerator,
	}
	checker.BaseChecker = NewBaseChecker[*ProcessBasedInfo[V]](
		func(p api.ProcessInterface, older *ProcessBasedInfo[V], items []*base.PolicyItem) *ProcessBasedInfo[V] {
			var win *base.TimeWindows[V, V]
			if older != nil {
				win = older.Windows
				older.Windows.ScalePeriod(items)
			} else {
				win = base.NewTimeWindows[V, V](items, func() base.WindowData[V, V] {
					return base.NewLatestWindowData[V]()
				})
			}
			policies := make([]*ProcessBasedPolicy[V], 0)
			for _, i := range items {
				threshold, _ := thresholdGenerator(i.Threshold)
				policies = append(policies, &ProcessBasedPolicy[V]{
					Threshold: threshold,
					Policy:    i,
				})
			}
			return &ProcessBasedInfo[V]{
				Process:  p,
				Windows:  win,
				Policies: policies,
			}
		})
	return checker
}

func (r *ProcessBasedChecker[V]) SyncPolicies(policies []*base.SyncPolicyWithProcesses) {
	r.BaseChecker.SyncPolicies(policies, func(items map[base.CheckType]*base.PolicyItem) *base.PolicyItem {
		item := items[r.CheckType]
		if item == nil {
			return nil
		}
		_, err := r.ThresholdGenerate(item.Threshold)
		if err != nil {
			log.Warnf("failure to parse the %s threshold: %v, error: %v", r.CheckType, item.Threshold, err)
			return nil
		}
		return item
	}, nil)
}

func (r *ProcessBasedChecker[V]) Fetch() error {
	if len(r.PidWithInfos) == 0 {
		return nil
	}

	var result error
	now := time.Now()
	for _, info := range r.PidWithInfos {
		val, err := r.DataGenerate(info.Process)
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("get the process %s failure, pid: %d, error: %v",
				r.CheckType, info.Process.Pid(), err))
			continue
		}

		info.Windows.Add(now, val)
	}
	return result
}

func (r *ProcessBasedChecker[V]) Check(ctx base.CheckContext, metricsAppender *base.MetricsAppender) []base.ThresholdCause {
	if len(r.PidWithInfos) == 0 {
		return nil
	}

	causes := make([]base.ThresholdCause, 0)
	for _, info := range r.PidWithInfos {
		for _, threshold := range info.Policies {
			if data, hasData := info.Windows.FlushLastWriteData(); hasData {
				metricsAppender.AppendProcessSingleValue(strings.ToLower(string(r.CheckType)), info.Process, nil, float64(data))
			}
			if !ctx.ShouldCheck(info.Process, threshold.Policy) {
				continue
			}
			// check is reach the threshold
			if lastMatch, enable := info.Windows.MatchRule(threshold.Policy, func(val V) bool {
				return val >= threshold.Threshold
			}); enable {
				causes = append(causes,
					NewSingleValueCause(info.Process, threshold.Policy, r.CauseType, float64(threshold.Threshold), float64(lastMatch)))
			}
		}
	}
	return causes
}

func (r *ProcessBasedChecker[V]) Close() error {
	return nil
}

type ProcessBasedInfo[V numbers] struct {
	Process  api.ProcessInterface
	Windows  *base.TimeWindows[V, V]
	Policies []*ProcessBasedPolicy[V]
}

type ProcessBasedPolicy[V numbers] struct {
	Threshold V
	Policy    *base.PolicyItem
}
