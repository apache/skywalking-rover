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

	"github.com/shirou/gopsutil/load"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"

	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/checker/common"
)

type SystemLoadChecker struct {
	*common.SystemBasedChecker[float64]
}

func NewSystemLoadChecker() *SystemLoadChecker {
	return &SystemLoadChecker{}
}

func (s *SystemLoadChecker) Init(*base.ContinuousConfig) error {
	s.SystemBasedChecker = common.NewSystemBasedChecker[float64](
		base.CheckTypeSystemLoad, func(val string) (float64, error) {
			return strconv.ParseFloat(val, 64)
		}, func() (float64, error) {
			avg, err := load.Avg()
			if err != nil {
				return 0, err
			}
			return avg.Load1, nil
		}, v3.ContinuousProfilingTriggeredMonitorType_SystemLoad)
	return nil
}
