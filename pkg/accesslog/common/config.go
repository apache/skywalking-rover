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

import "github.com/apache/skywalking-rover/pkg/module"

type Config struct {
	module.Config

	Active            bool                  `mapstructure:"active"`
	ExcludeNamespaces string                `mapstructure:"exclude_namespaces"`
	Flush             FlushConfig           `mapstructure:"flush"`
	ProtocolAnalyze   ProtocolAnalyzeConfig `mapstructure:"protocol_analyze"`
}

type FlushConfig struct {
	MaxCountOneStream int    `mapstructure:"max_count"`
	Period            string `mapstructure:"period"`
}

type ProtocolAnalyzeConfig struct {
	PerCPUBufferSize string `mapstructure:"per_cpu_buffer"`
	Parallels        int    `mapstructure:"parallels"`
	QueueSize        int    `mapstructure:"queue_size"`
}

func (c *Config) IsActive() bool {
	return c.Active
}
