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

package checker

import (
	"strconv"

	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/checker/bpf/network"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/checker/common"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type NetworkHTTPAvgResponseTimeChecker struct {
	*common.HTTPBasedChecker[*processNetworkAvgResponseTimeStatics]
}

func NewNetworkAvgResponseTimeChecker() *NetworkHTTPAvgResponseTimeChecker {
	return &NetworkHTTPAvgResponseTimeChecker{}
}

func (n *NetworkHTTPAvgResponseTimeChecker) Init(config *base.ContinuousConfig) error {
	n.HTTPBasedChecker = common.NewHTTPBasedChecker[*processNetworkAvgResponseTimeStatics](
		base.CheckTypeHTTPAvgResponseTime, func(val string) (float64, error) {
			return strconv.ParseFloat(val, 64)
		}, func() base.WindowData[network.BufferEvent, float64] {
			return &processNetworkAvgResponseTimeStatics{}
		}, v3.ContinuousProfilingCauseType_HTTPAvgResponseTime)
	return nil
}

type processNetworkAvgResponseTimeStatics struct {
	totalCount    int
	totalDuration int
}

func (s *processNetworkAvgResponseTimeStatics) Reset() {
	s.totalCount, s.totalDuration = 0, 0
}

func (s *processNetworkAvgResponseTimeStatics) Accept(data network.BufferEvent) {
	s.totalCount++
	s.totalDuration += int(data.Duration().Milliseconds())
}

func (s *processNetworkAvgResponseTimeStatics) Get() float64 {
	return float64(s.totalDuration) / float64(s.totalCount)
}
