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

package base

import (
	"fmt"

	v3 "skywalking.apache.org/repo/goapi/collect/common/v3"
)

type TargetType string

const (
	TargetTypeOnCPU           TargetType = "ON_CPU"
	TargetTypeOffCPU          TargetType = "OFF_CPU"
	TargetTypeNetworkTopology TargetType = "NETWORK"
)

func ParseTargetType(err error, val string) (TargetType, error) {
	if err != nil {
		return "", err
	}
	if TargetType(val) == TargetTypeOnCPU {
		return TargetTypeOnCPU, nil
	} else if TargetType(val) == TargetTypeOffCPU {
		return TargetTypeOffCPU, nil
	} else if TargetType(val) == TargetTypeNetworkTopology {
		return TargetTypeNetworkTopology, nil
	}
	return "", fmt.Errorf("could not found target type: %s", val)
}

func (t TargetType) InitTask(task *ProfilingTask, command *v3.Command) error {
	return nil
}
