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

type NetworkHTTPErrorRateChecker struct {
	*common.HTTPBasedChecker
}

func NewNetworkResponseErrorChecker() *NetworkHTTPErrorRateChecker {
	return &NetworkHTTPErrorRateChecker{}
}

func (n *NetworkHTTPErrorRateChecker) Init(*base.ContinuousConfig) error {
	n.HTTPBasedChecker = common.NewHTTPBasedChecker(
		base.CheckTypeHTTPErrorRate, func(val string) (float64, error) {
			v, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return 0, err
			}
			return v, nil
		}, func() base.WindowData[network.BufferEvent, float64] {
			return &processNetworkResponseErrorStatics{}
		}, v3.ContinuousProfilingTriggeredMonitorType_HTTPErrorRate)
	return nil
}

type processNetworkResponseErrorStatics struct {
	totalCount int
	errorCount int
}

func (s *processNetworkResponseErrorStatics) Reset() {
	s.totalCount, s.errorCount = 0, 0
}

func (s *processNetworkResponseErrorStatics) Accept(data network.BufferEvent) {
	s.totalCount++
	if data.IsResponseError() {
		s.errorCount++
	}
}

func (s *processNetworkResponseErrorStatics) Get() float64 {
	if s.totalCount == 0 {
		return 0
	}
	return float64(s.errorCount) / float64(s.totalCount) * 100
}
