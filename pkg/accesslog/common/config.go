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

package common //nolint:revive // package name is acceptable in this context

import "github.com/apache/skywalking-rover/pkg/module"

type Config struct {
	module.Config

	Active            bool                    `mapstructure:"active"`
	ExcludeNamespaces string                  `mapstructure:"exclude_namespaces"`
	ExcludeClusters   string                  `mapstructure:"exclude_cluster"`
	Flush             FlushConfig             `mapstructure:"flush"`
	ConnectionAnalyze ConnectionAnalyzeConfig `mapstructure:"connection_analyze"`
	ProtocolAnalyze   ProtocolAnalyzeConfig   `mapstructure:"protocol_analyze"`
}

type FlushConfig struct {
	MaxCountOneStream int    `mapstructure:"max_count"`
	Period            string `mapstructure:"period"`
}

type ConnectionAnalyzeConfig struct {
	PerCPUBufferSize string `mapstructure:"per_cpu_buffer"`
	ParseParallels   int    `mapstructure:"parse_parallels"`
	AnalyzeParallels int    `mapstructure:"analyze_parallels"`
	QueueSize        int    `mapstructure:"queue_size"`
}

type ProtocolAnalyzeConfig struct {
	PerCPUBufferSize string `mapstructure:"per_cpu_buffer"`
	ParseParallels   int    `mapstructure:"parse_parallels"`
	AnalyzeParallels int    `mapstructure:"analyze_parallels"`
	QueueSize        int    `mapstructure:"queue_size"`
	// TriggerEvents: analyze the buffered socket data of a partition as soon as this many data events are
	// pending, instead of only on the flush period tick. Bounds the memory held by the unparsed events
	// (each one keeps a 20 KB buffer until it is parsed). 0 disables the trigger.
	TriggerEvents int `mapstructure:"trigger_events"`
	// MaxMemoryPercent: when the memory usage of the process reaches this share of its memory limit (the
	// cgroup limit, or GOMEMLIMIT), new socket data events are dropped (counted in the log) until the
	// usage is below it again, instead of growing until the process is killed. 0 disables it.
	MaxMemoryPercent int `mapstructure:"max_memory_percent"`
	// MaxMemory: an absolute threshold that overrides the percentage when set (e.g. 1GB).
	MaxMemory string `mapstructure:"max_memory"`
}

func (c *Config) IsActive() bool {
	return c.Active
}
