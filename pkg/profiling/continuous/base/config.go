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

type ContinuousConfig struct {
	MeterPrefix string `mapstructure:"meter_prefix"` // continuous related meters prefix name

	FetchInterval string        `mapstructure:"fetch_interval"` // The interval of fetch metrics from the system
	CheckInterval string        `mapstructure:"check_interval"` // The interval of check metrics is reach the thresholds
	Trigger       TriggerConfig `mapstructure:"trigger"`
}

type TriggerConfig struct {
	ExecuteDuration string `mapstructure:"execute_duration"` // the duration of the profiling task
	SilenceDuration string `mapstructure:"silence_duration"` // the duration between the execution of the same profiling task.
}
