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
	"time"

	v3 "skywalking.apache.org/repo/goapi/collect/common/v3"
)

type TriggerType string

const (
	TriggerTypeFixedTime TriggerType = "FIXED_TIME"
)

func ParseTriggerType(err error, val string) (TriggerType, error) {
	if err != nil {
		return "", err
	}
	if TriggerType(val) == TriggerTypeFixedTime {
		return TriggerTypeFixedTime, nil
	}
	return "", fmt.Errorf("could not found trigger type: %s", val)
}

func (t TriggerType) InitTask(task *ProfilingTask, command *v3.Command) error {
	if t == TriggerTypeFixedTime {
		val, err := getCommandIntValue(nil, command, "FixedTriggerDuration")
		if err != nil {
			return err
		}
		task.MaxRunningDuration = time.Duration(val) * time.Second
	}
	return nil
}
