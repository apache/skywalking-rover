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

package task

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/oncpu"
)

var profilingRunners = make(map[base.TargetType]func(config *base.TaskConfig) (base.ProfileTaskRunner, error))

func init() {
	profilingRunners[base.TargetTypeOnCPU] = oncpu.NewRunner
}

func NewProfilingRunner(taskType base.TargetType, taskConfig *base.TaskConfig) (base.ProfileTaskRunner, error) {
	if profilingRunners[taskType] == nil {
		return nil, fmt.Errorf("could not found %s runner", taskType)
	}
	return profilingRunners[taskType](taskConfig)
}

func CheckProfilingTaskConfig(taskConfig *base.TaskConfig) error {
	if taskConfig == nil {
		return fmt.Errorf("please provide the profiling task config")
	}

	var err error
	for _, runner := range profilingRunners {
		if _, e := runner(taskConfig); e != nil {
			err = multierror.Append(err, e)
		}
	}
	return err
}
