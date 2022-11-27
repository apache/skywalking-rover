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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	v3 "skywalking.apache.org/repo/goapi/collect/common/v3"
)

type ProfilingTask struct {
	// TaskID of profiling task
	TaskID string
	// ProcessIDList of need to monitoring process
	ProcessIDList []string
	// UpdateTime of profiling task
	UpdateTime int64
	// StartTime of profiling task, when need to start to profiling
	StartTime int64
	// TriggerType of task
	TriggerType TriggerType
	// TargetType of task
	TargetType TargetType
	// MaxRunningDuration of task
	MaxRunningDuration time.Duration
	ExtensionConfig    *ExtensionConfig
}

func ProfilingTaskFromCommand(command *v3.Command) (*ProfilingTask, error) {
	if command.GetCommand() != "EBPFProfilingTaskQuery" {
		return nil, fmt.Errorf("not support command: %s", command.GetCommand())
	}

	var err error
	taskID, err := getCommandStringValue(err, command, "TaskId")
	processIDList, err := getCommandStringValue(err, command, "ProcessId")
	taskUpdateTime, err := getCommandIntValue(err, command, "TaskUpdateTime")
	triggerTypeStr, err := getCommandStringValue(err, command, "TriggerType")
	triggerType, err := ParseTriggerType(err, triggerTypeStr)
	targetTypeStr, err := getCommandStringValue(err, command, "TargetType")
	targetType, err := ParseTargetType(err, targetTypeStr)
	taskStartTime, err := getCommandIntValue(err, command, "TaskStartTime")
	extensionConfig, err := getCommandExtensionConfig(err, command, "ExtensionConfigJSON")
	if err != nil {
		return nil, err
	}

	processes := strings.Split(processIDList, ",")

	task := &ProfilingTask{
		TaskID:          taskID,
		ProcessIDList:   processes,
		UpdateTime:      taskUpdateTime,
		StartTime:       taskStartTime,
		TargetType:      targetType,
		TriggerType:     triggerType,
		ExtensionConfig: extensionConfig,
	}

	if err := task.TriggerType.InitTask(task, command); err != nil {
		return nil, err
	}
	if err := task.TargetType.InitTask(task, command); err != nil {
		return nil, err
	}

	return task, nil
}

type ExtensionConfig struct {
	NetworkSamplings []*NetworkSamplingRule `json:"NetworkSamplings"`
}

type NetworkSamplingRule struct {
	URIRegex    *string                        `json:"URIRegex"`
	MinDuration *int32                         `json:"MinDuration"`
	When4XX     bool                           `json:"When4xx"`
	When5XX     bool                           `json:"When5xx"`
	Settings    *NetworkDataCollectingSettings `json:"Settings"`
}

type NetworkDataCollectingSettings struct {
	RequireCompleteRequest  bool  `json:"RequireCompleteRequest"`
	MaxRequestSize          int32 `json:"MaxRequestSize"`
	RequireCompleteResponse bool  `json:"RequireCompleteResponse"`
	MaxResponseSize         int32 `json:"MaxResponseSize"`
}

func getCommandStringValue(err error, command *v3.Command, key string) (string, error) {
	if err != nil {
		return "", err
	}
	for _, arg := range command.GetArgs() {
		if arg.GetKey() == key {
			return arg.GetValue(), nil
		}
	}
	return "", fmt.Errorf("could not found key: %v", key)
}

func getCommandIntValue(err error, command *v3.Command, key string) (int64, error) {
	val, err := getCommandStringValue(err, command, key)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(val, 10, 64)
}

func getCommandExtensionConfig(err error, command *v3.Command, key string) (*ExtensionConfig, error) {
	val, err := getCommandStringValue(err, command, key)
	if err != nil {
		return nil, err
	}
	config := &ExtensionConfig{}
	if e := json.Unmarshal([]byte(val), config); e != nil {
		return nil, e
	}
	return config, nil
}
